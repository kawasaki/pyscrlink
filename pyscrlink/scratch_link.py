#!/usr/bin/env python
import select
import struct

"""Scratch link on bluepy"""

import asyncio
import pathlib
import ssl
import websockets
import socket
import json
import base64
import logging
import sys
import signal
import traceback
import argparse

from bleak import BleakScanner
from bleak import BleakClient
from bleak.exc import BleakError
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData
from pyscrlink import bluepy_helper_cap
from websockets.exceptions import ConnectionClosedOK

import threading
import traceback
import time
import queue

# for websockets certificate
from pyscrlink import gencert

logLevel = logging.INFO

# for logging
logger = logging.getLogger(__name__)
formatter = logging.Formatter(fmt='%(asctime)s %(message)s')
handler = logging.StreamHandler()
handler.setLevel(logLevel)
handler.setFormatter(formatter)
logger.setLevel(logLevel)
logger.addHandler(handler)
logger.propagate = False

HOSTNAME="device-manager.scratch.mit.edu"
scan_seconds=5.0

class Session():
    """Base class for BTSession and BLESession"""
    def __init__(self, websocket, loop):
        self.websocket = websocket
        self.loop = loop
        self.lock = threading.RLock()
        self.notification_queue = queue.Queue()

    async def recv_request(self):
        """
        Handle a request from Scratch through websocket.
        Return True when the session should end.
        """
        logger.debug("start recv_request")
        try:
            req = await asyncio.wait_for(self.websocket.recv(), 0.0001)
        except asyncio.TimeoutError:
            return False
        logger.debug(f"request: {req}")
        jsonreq = json.loads(req)
        if jsonreq['jsonrpc'] != '2.0':
            logger.error("error: jsonrpc version is not 2.0")
            return True
        jsonres = await self.handle_request(jsonreq['method'], jsonreq['params'])
        if 'id' in jsonreq:
            jsonres['id'] = jsonreq['id']
        response = json.dumps(jsonres)
        logger.debug(f"response: {response}")
        await self.websocket.send(response)
        if self.end_request():
            return True
        return False

    async def handle_request(self, method, params):
        """Default request handler"""
        logger.debug(f"default handle_request: {method}, {params}")

    def end_request(self):
        """
        Default callback at request end. This callback is required to
        allow other websocket usage out of the request handler.
        Return true when the session should end.
        """
        logger.debug("default end_request")
        return False

    def notify(self, key, params):
        self.notification_queue.put((key, params))

    async def _send_notifications(self):
        """
        Notify BT/BLE device events to scratch.
        """
        logger.debug("start to notify")
        # flush notification queue
        while not self.notification_queue.empty():
            method, params = self.notification_queue.get()
            await self._send_notification(method, params)

    async def _send_notification(self, method, params):
        jsonn = { 'jsonrpc': "2.0", 'method': method }
        jsonn['params'] = params
        notification = json.dumps(jsonn)
        logger.debug(f"notification: {notification}")
        await self.websocket.send(notification)

    async def handle(self):
        logger.debug("start session handler")
        await self.recv_request()
        await asyncio.sleep(0.1)
        while True:
            try:
                if await self.recv_request():
                    break
                await self._send_notifications()
                logger.debug("in handle loop")
            except ConnectionClosedOK as e:
                logger.warning(f"scratch closed session: {e}")
                self.close()
                break
            except websockets.ConnectionClosedError as e:
                logger.info("scratch closed session")
                logger.error(e)
                self.close()
                break

    def close(self):
        """
        Default handler called at session end.
        """
        return

class BTSession(Session):
    """Manage a session for Bluetooth device"""

class BLESession(Session):
    """
    Manage a session for Bluetooth Low Energy device such as micro:bit
    """

    INITIAL = 1
    DISCOVERY = 2
    CONNECTED = 3
    DONE = 4

    SERVICE_CLASS_UUID_ADTYPES = {
        0x7: "adtype complete 128b",
        0x3: "adtype complete 16b",
        0x6: "adtype incomplete 128b",
        0x5: "adtype complete 32b",
        0x4: "adtype incomplete 32b",
        0x2: "adtype incomplete 16b",
    }

    MAX_SCANNER_IF = 3

    found_devices = {}
    nr_connected = 0
    scan_lock = threading.RLock()
    scan_started = False

    class BLEThread(threading.Thread):
        """
        Separated thread to control notifications to Scratch.
        It handles device discovery notification in DISCOVERY status
        and notifications from BLE devices in CONNECTED status.
        """
        def __init__(self, session):
            threading.Thread.__init__(self)
            self.session = session

        def run(self):
            while True:
                if self.session.status == self.session.DISCOVERY:
                    logger.debug("send out found devices")
                    devices = BLESession.found_devices
                    for dev, advert in devices.values():
                        params = { 'rssi': advert.rssi }
                        params['peripheralId'] = dev.address
                        params['name'] = dev.name
                        self.session.notify('didDiscoverPeripheral', params)
                    time.sleep(1)
                elif self.session.status == self.session.CONNECTED:
                    logger.debug("in connected status:")
                    delegate = self.session.delegate
                    if delegate and len(delegate.handles) > 0:
                        if not delegate.restart_notification_event.is_set():
                            delegate.restart_notification_event.wait()
                        try:
                            logger.debug("getting lock for waitForNotification")
                            with self.session.lock:
                                logger.debug("before waitForNotification")
                                time.sleep(0.001)
                                logger.debug("after waitForNotification")
                            logger.debug("released lock for waitForNotification")
                        except Exception as e:
                            logger.error(e)
                            self.session.close()
                            break
                    else:
                        time.sleep(0.2)
                    # To avoid repeated lock by this single thread,
                    # yield CPU to other lock waiting threads.
                    time.sleep(0.4)
                else:
                    # Nothing to do:
                    time.sleep(0.5)

    class BLEDelegate():
        """
        A bleak handler to receive notifictions from BLE devices.
        """
        def __init__(self, client, session):
            self.client = client
            self.session = session
            self.handles = {}
            self.restart_notification_event = threading.Event()
            self.restart_notification_event.set()

        def add_handle(self, serviceId, charId, handle):
            logger.info(f"add handle for notification: {handle}")
            params = { 'serviceId': serviceId,
                       'characteristicId': charId,
                       'encoding': 'base64' }
            self.handles[handle] = params

        async def handleNotification(self, handle, data):
            logger.debug(f"BLE notification: {handle}")
            params = {}
            params['characteristicId'] = handle.uuid
            params['serviceId'] = handle.service_uuid
            params['message'] = base64.standard_b64encode(data).decode('ascii')
            self.session.notify('characteristicDidChange', params)
            await asyncio.sleep(0.5)

    def __init__(self, websocket, loop):
        super().__init__(websocket, loop)
        self.status = self.INITIAL
        self.device = None
        self.deviceName = None
        self.client = None
        self.delegate = None
        self.characteristics_cache = []

    async def close(self):
        if self.status == self.CONNECTED:
            BLESession.nr_connected -= 1
            logger.info(f"BLE session disconnected")
            logger.debug(f"BLE session connected={BLESession.nr_connected}")
            if BLESession.nr_connected == 0:
                logger.info("all BLE sessions disconnected")
                BLESession.scan_started = False
        self.status = self.DONE
        if self.client:
            logger.info("disconnect from the BLE peripheral: "
                        f"{self.deviceName}")
            with self.lock:
                await self.client.disconnect()
            self.client = None

    def __del__(self):
        self.close()

    def _get_dev_uuids(self, dev):
        for adtype in self.SERVICE_CLASS_UUID_ADTYPES:
            service_class_uuids = dev.getValue(adtype)
            if service_class_uuids:
                for u in service_class_uuids:
                    a = self.SERVICE_CLASS_UUID_ADTYPES[adtype]
                    logger.debug(f"service class uuid for {a}/{adtype}: {u}")
                return service_class_uuids
        return None

    def matches(self, dev, advert, filters):
        """
        Check if the found BLE device matches the filters Scratch specifies.
        """
        logger.debug(f"in matches {dev.name} {filters}")
        for f in filters:
            if 'services' in f:
                for s in f['services']:
                    logger.debug(f"service to check: {s}")
                    given_uuid = s
                    logger.debug(f"given UUID: {given_uuid} hash={UUID(given_uuid).__hash__()}")
                    dev_uuids = self._get_dev_uuids(dev)
                    if not dev_uuids:
                        continue
                    for u in dev_uuids:
                        logger.debug(f"dev UUID: {u} hash={u.__hash__()}")
                        logger.debug(given_uuid == u)
                        if given_uuid == u:
                            logger.debug("match...")
                            return True
            if 'namePrefix' in f:
                logger.debug(f"given namePrefix: {f['namePrefix']}")
                deviceName = dev.name
                if deviceName:
                    logger.debug(f"SHORT_LOCAL_NAME: {deviceName}")
                    if deviceName.startswith(f['namePrefix']):
                        logger.debug(f"match...")
                        return True
                deviceName = advert.local_name
                if deviceName:
                    logger.debug(f"COMPLETE_LOCAL_NAME: {deviceName}")
                    if deviceName.startswith(f['namePrefix']):
                        logger.debug(f"match...")
                        return True
            if 'name' in f or 'manufactureData' in f:
                logger.error("name/manufactureData filters not implemented")
                # TODO: implement other filters defined:
                # ref: https://github.com/LLK/scratch-link/blob/develop/Documentation/BluetoothLE.md
        return False

    async def _scan_devices(self, params):
        global scan_seconds
        if BLESession.nr_connected > 0:
            return len(BLESession.found_devices) > 0
        found = False
        with BLESession.scan_lock:
            if not BLESession.scan_started:
                BLESession.scan_started = True
                BLESession.found_devices.clear()
                for j in range(scan_retry):
                    try:
                        logger.info(f"BLE scanning for: {scan_seconds} seconds (attempt {j})")
                        devices: Dict[str, Tuple[BLEDevice, AdvertisementData]] = await BleakScanner.discover(scan_seconds, return_adv=True)
                        for dev, advert in devices.values():
                            logger.debug(f"device: {dev}")
                            logger.debug(advert)
                            if self.matches(dev, advert, params['filters']):
                                logger.debug(f"match: {dev.name}")
                                BLESession.found_devices[dev.address] = [dev, advert]
                                found = True
                                logger.info(f"BLE device found: #{dev}")
                        if found:
                            break
                    except Exception as e:
                        logger.error(f"BLE iface #{dev}: {e}")
                        print(traceback.format_exc())
            else:
                found = len(BLESession.found_devices) > 0
        return found

    def _get_service(self, service_id):
        with self.lock:
            for svc in self.client.services:
                if svc == service_id:
                    service = svc

    async def _get_characteristic(self, chara_id):
        if not self.client:
            return None
        with self.lock:
            char = await self.client.read_gatt_char(chara_id)
            return char

    async def _cache_characteristics(self):
        if not self.client:
            return
        with self.lock:
            self.characteristics_cache = {}
            for service in self.client.services:
                logger.info("[Service] %s", service)
                for char in service.characteristics:
                    if "read" in char.properties:
                        try:
                            value = await self.client.read_gatt_char(char.uuid)
                            extra = f", Value: {value}"
                        except Exception as e:
                            extra = f", Error: {e}"
                    else:
                        extra = ""
                    if "write-without-response" in char.properties:
                        extra += f", Max write w/o rsp size: {char.max_write_without_response_size}"

                    logger.info(
                        "  [Characteristic] %s (%s)%s",
                        char,
                        ",".join(char.properties),
                        extra,
                    )
                    for descriptor in char.descriptors:
                        try:
                            value = await self.client.read_gatt_descriptor(descriptor.handle)
                            logger.info("    [Descriptor] %s, Value: %r", descriptor, value)
                        except Exception as e:
                            logger.error("    [Descriptor] %s, Error: %s", descriptor, e)
                    self.characteristics_cache[char] = char.properties

        if not self.characteristics_cache:
            logger.info("Characteristics are not cached")

    def _get_characteristic_cached(self, chara_id):
        if not self.client:
            return None
        if not self.characteristics_cache:
            self._cache_characteristics()
        if self.characteristics_cache:
            for characteristic in self.characteristics_cache:
                if characteristic.uuid == chara_id:
                    return characteristic

    async def handle_request(self, method, params):
        """Handle requests from Scratch"""
        if self.delegate:
            # Do not allow notification during request handling to avoid
            # websocket server errors
            self.delegate.restart_notification_event.clear()

        logger.debug(f"handle {method} request to BLE device")
        if len(params) > 0:
            logger.debug(params)

        res = { "jsonrpc": "2.0" }
        err_msg = None

        if self.status == self.INITIAL and method == 'discover':
            if not bluepy_helper_cap.is_set():
                logger.error("Capability is not set to bluepy helper.")
                logger.error("Run bluepy_helper_cap(.py).")
                logger.error("e.g. $ bluepy_helper_cap")
                logger.error("e.g. $ sudo bluepy_helper_cap.py")
                sys.exit(1)
            found = await self._scan_devices(params)
            if not found:
                if BLESession.nr_connected > 0:
                    err_msg = "Can not scan BLE devices. Disconnect other sessions."
                elif len(BLESession.found_devices) == 0:
                    err_msg = "Can not scan BLE devices. Check BLE controller."
                logger.error(err_msg);
                res["error"] = { "message": err_msg }
                self.status = self.DONE

            if len(BLESession.found_devices) == 0 and not err_msg:
                err_msg = (f"No BLE device found: {params['filters']}. "
                           "Check BLE device.")
                res["error"] = { "message": err_msg }
                logger.error(err_msg)
                self.status = self.DONE
            else:
                res["result"] = None
                self.status = self.DISCOVERY
                self.ble_thread = self.BLEThread(self)
                self.ble_thread.start()

        elif self.status == self.DISCOVERY and method == 'connect':
            logger.info("connecting to the BLE device")
            self.device, advert = BLESession.found_devices[params['peripheralId']]
            self.deviceName = self.device.name

            self.client = BleakClient(self.device.address)
            try:
                connected = await self.client.connect()
                if connected:
                    self.status = self.CONNECTED
                    BLESession.nr_connected += 1
                    logger.info(f"connected to the BLE peripheral: {self.deviceName}")
                    self.delegate = self.BLEDelegate(self.client, self)
                    await self._cache_characteristics()
                    logger.debug(f"connect done.")

            except BleakError as e:
                err_msg = f"BLE connect failed: {self.deviceName}"
                res["error"] = { "message": err_msg }
                self.status = self.DONE
                logger.error(e)
            except Exception as e:
                print(e)
                print(traceback.format_exc())

        elif self.status == self.CONNECTED and method == 'read':
            logger.debug("handle read request")
            service_id = params['serviceId']
            chara_id = params['characteristicId']
            c = self._get_characteristic_cached(chara_id)
            if not c or c.uuid != chara_id:
                logger.error(f"Failed to get characteristic {chara_id}")
                self.status = self.DONE
            else:
                with self.lock:
                    b = c.read()
                message = base64.standard_b64encode(b).decode('ascii')
                res['result'] = { 'message': message, 'encode': 'base64' }
                logger.debug(f"got msg: {message}")
            if params.get('startNotifications') == True:
                logger.debug(f"starting notifications for svc {service_id}")
                self.startNotifications(service_id, chara_id)

        elif self.status == self.CONNECTED and method == 'startNotifications':
            logger.debug("handle startNotifications request")
            service_id = params['serviceId']
            chara_id = params['characteristicId']
            await self.startNotifications(service_id, chara_id)

        elif self.status == self.CONNECTED and method == 'stopNotifications':
            logger.debug("handle stopNotifications request")
            service_id = params['serviceId']
            chara_id = params['characteristicId']
            await self.stopNotifications(service_id, chara_id)

        elif self.status == self.CONNECTED and method == 'write':
            logger.debug("handle write request")
            service_id = params['serviceId']
            chara_id = params['characteristicId']
            c = self._get_characteristic_cached(chara_id)
            if not c or c.uuid != chara_id:
                logger.error(f"Failed to get characteristic {chara_id}")
                self.status = self.DONE
            else:
                if params['encoding'] != 'base64':
                    logger.error("encoding other than base 64 is not "
                                 "yet supported: ", params['encoding'])
                msg_bstr = params['message'].encode('ascii')
                data = base64.standard_b64decode(msg_bstr)
                logger.debug("getting lock for c.write()")
                with self.lock:
                    await self.client.write_gatt_char(chara_id, data, response=True)
                logger.debug("released lock for c.write()")
                res['result'] = len(data)

        logger.debug(res)
        return res

    async def setNotifications(self, service_id, chara_id, value):
        service = self._get_service(service_id)
        c = self._get_characteristic_cached(chara_id)
        if c is not None:
            # prepare notification handler
            self.delegate.add_handle(service_id, chara_id, c.handle)
            # request notification to the BLE device
            with self.lock:
                await self.client.write_gatt_char(c.handle, value, response=True)
                # start keep-alive thread. TODO: for intelino only?
                logger.info(f"starting notifications for {chara_id}")
                await self.client.start_notify(chara_id, self.delegate.handleNotification)


    async def startNotifications(self, service_id, chara_id):
        value = bytearray([0x10]) # b"\x01\x00"
        logger.debug(f"start notification for {chara_id}: {value}")
        await self.setNotifications(service_id, chara_id, value)

    async def stopNotifications(self, service_id, chara_id):
        logger.debug(f"stop notification for {chara_id}")
        value = bytearray([0x00]) # b"\x00\x00"
        await self.setNotifications(service_id, chara_id, value)

    def end_request(self):
        logger.debug("end_request of BLESession")
        if self.delegate:
            self.delegate.restart_notification_event.set()
        return self.status == self.DONE

async def ws_handler(websocket, path):
    sessionTypes = { '/scratch/ble': BLESession, '/scratch/bt': BTSession }
    try:
        logger.info(f"Start session for web socket path: {path}")
        loop = asyncio.get_event_loop()
        session = sessionTypes[path](websocket, loop)
        await session.handle()
    except Exception as e:
        logger.error(f"Failure in session for web socket path: {path}")
        logger.error(f"{type(e).__name__}: {e}")
        print(traceback.format_exc())
        await session.close()

def stack_trace():
    print("in stack_trace")
    code = []
    for threadId, stack in sys._current_frames().items():
        code.append("\n# ThreadID: %s" % threadId)
        for filename, lineno, name, line in traceback.extract_stack(stack):
            code.append('File: "%s", line %d, in %s' % (filename,
                                                    lineno, name))
            if line:
                code.append("  %s" % (line.strip()))

    for line in code:
         print(line)

def main():
    global scan_seconds
    global scan_retry
    parser = argparse.ArgumentParser(description='start Scratch-link')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='print debug messages')
    parser.add_argument('-s', '--scan_seconds', type=float, default=scan_seconds,
                        help='specifiy duration to scan BLE devices in seconds')
    parser.add_argument('-r', '--scan_retry', type=int, default=1,
                        help='specifiy retry times to scan BLE devices')
    args = parser.parse_args()
    if args.debug:
        print("Print debug messages")
        logLevel = logging.DEBUG
        handler.setLevel(logLevel)
        logger.setLevel(logLevel)
    scan_seconds = args.scan_seconds
    scan_retry = args.scan_retry
    logger.debug(f"set scan_seconds: {scan_seconds}")
    logger.debug(f"set scan_retry: {scan_retry}")

    # Prepare certificate of the WSS server
    gencert.prep_cert()

    # kick start WSS server
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    localhost_cer = gencert.cert_file_path
    localhost_key = gencert.key_file_path
    ssl_context.load_cert_chain(localhost_cer, localhost_key)

    start_server = websockets.serve(
         ws_handler, HOSTNAME, 20110, ssl=ssl_context
    )

    while True:
        try:
            asyncio.get_event_loop().run_until_complete(start_server)
            logger.info("Started scratch-link")
            asyncio.get_event_loop().run_forever()
        except KeyboardInterrupt as e:
            stack_trace()
            break
        except socket.gaierror as e:
            logger.error(f"{type(e).__name__}: {e}")
            logger.info(f"Check internet connection to {HOSTNAME}. If not "
                        f"available, add '127.0.0.1 {HOSTNAME}' to /etc/hosts.")
            break
        except Exception as e:
            logger.error(f"{type(e).__name__}: {e}")
            logger.info("Restarting scratch-link...")

if __name__ == "__main__":
    main()
