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

# for BLESession (e.g. BBC micro:bit)
from bluepy.btle import Scanner, UUID, Peripheral, DefaultDelegate
from bluepy.btle import BTLEDisconnectError, BTLEManagementError
from pyscrlink import bluepy_helper_cap

import threading
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
scan_seconds=10.0

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
        jsonres = self.handle_request(jsonreq['method'], jsonreq['params'])
        if 'id' in jsonreq:
            jsonres['id'] = jsonreq['id']
        response = json.dumps(jsonres)
        logger.debug(f"response: {response}")
        await self.websocket.send(response)
        if self.end_request():
            return True
        return False

    def handle_request(self, method, params):
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
            except websockets.ConnectionClosedError as e:
                logger.info("scratch closed session")
                logger.debug(e)
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

    found_devices = []
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
                logger.debug("loop in BLE thread")
                if self.session.status == self.session.DISCOVERY:
                    logger.debug("send out found devices")
                    devices = BLESession.found_devices
                    for d in devices:
                        params = { 'rssi': d.rssi }
                        params['peripheralId'] = devices.index(d)
                        params['name'] = d.getValueText(0x9) or d.getValueText(0x8)
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
                                self.session.perip.waitForNotifications(0.0001)
                                logger.debug("after waitForNotification")
                            logger.debug("released lock for waitForNotification")
                        except Exception as e:
                            logger.error(e)
                            self.session.close()
                            break
                    else:
                        time.sleep(0.0)
                    # To avoid repeated lock by this single thread,
                    # yield CPU to other lock waiting threads.
                    time.sleep(0)
                else:
                    # Nothing to do:
                    time.sleep(0)

    class BLEDelegate(DefaultDelegate):
        """
        A bluepy handler to receive notifictions from BLE devices.
        """
        def __init__(self, session):
            DefaultDelegate.__init__(self)
            self.session = session
            self.handles = {}
            self.restart_notification_event = threading.Event()
            self.restart_notification_event.set()

        def add_handle(self, serviceId, charId, handle):
            logger.debug(f"add handle for notification: {handle}")
            params = { 'serviceId': UUID(serviceId).getCommonName(),
                       'characteristicId': charId,
                       'encoding': 'base64' }
            self.handles[handle] = params

        def handleNotification(self, handle, data):
            logger.debug(f"BLE notification: {handle} {data}")
            params = self.handles[handle].copy()
            params['message'] = base64.standard_b64encode(data).decode('ascii')
            self.session.notify('characteristicDidChange', params)

    def __init__(self, websocket, loop):
        super().__init__(websocket, loop)
        self.status = self.INITIAL
        self.device = None
        self.deviceName = None
        self.perip = None
        self.delegate = None
        self.characteristics_cache = []

    def close(self):
        if self.status == self.CONNECTED:
            BLESession.nr_connected -= 1
            logger.info(f"BLE session disconnected")
            logger.debug(f"BLE session connected={BLESession.nr_connected}")
            if BLESession.nr_connected == 0:
                logger.info("all BLE sessions disconnected")
                BLESession.scan_started = False
        self.status = self.DONE
        if self.perip:
            logger.info("disconnect from the BLE peripheral: "
                        f"{self.deviceName}")
            with self.lock:
                self.perip.disconnect()
            self.perip = None

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

    def matches(self, dev, filters):
        """
        Check if the found BLE device matches the filters Scratch specifies.
        """
        logger.debug(f"in matches {dev.addr} {filters}")
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
                # 0x08: Shortened Local Name
                deviceName = dev.getValueText(0x08)
                if not deviceName:
                    continue
                logger.debug(f"Name of \"{deviceName}\" begins with: \"{f['namePrefix']}\"?")
                if(deviceName.startswith(f['namePrefix'])):
                    logger.debug("Yes")
                    return True
                logger.debug("No")
            if 'name' in f or 'manufactureData' in f:
                logger.error("name/manufactureData filters not implemented")
                # TODO: implement other filters defined:
                # ref: https://github.com/LLK/scratch-link/blob/develop/Documentation/BluetoothLE.md
        return False

    def _scan_devices(self, params):
        global scan_seconds
        if BLESession.nr_connected > 0:
            return len(BLESession.found_devices) > 0
        found = False
        with BLESession.scan_lock:
            if not BLESession.scan_started:
                BLESession.scan_started = True
                BLESession.found_devices.clear()
                for i in range(self.MAX_SCANNER_IF):
                    scanner = Scanner(iface=i)
                    for j in range(scan_retry):
                        try:
                            logger.debug(f"start BLE scan: {scan_seconds} seconds")
                            devices = scanner.scan(scan_seconds)
                            for dev in devices:
                                if self.matches(dev, params['filters']):
                                    BLESession.found_devices.append(dev)
                                    found = True
                                    logger.debug(f"BLE device found with iface #{i}");
                            if found:
                                break
                        except BTLEDisconnectError as de:
                            logger.debug(f"BLE iface #{i}: {de}");
                        except BTLEManagementError as me:
                            logger.debug(f"BLE iface #{i}: {me}");
                    if found:
                        break
            else:
                found = len(BLESession.found_devices) > 0
        return found

    def _get_service(self, service_id):
        with self.lock:
            service = self.perip.getServiceByUUID(UUID(service_id))

    def _get_characteristic(self, chara_id):
        if not self.perip:
            return None
        with self.lock:
            charas = self.perip.getCharacteristics(uuid=chara_id)
            return charas[0]

    def _cache_characteristics(self):
        if not self.perip:
            return
        with self.lock:
            self.characteristics_cache = self.perip.getCharacteristics()
        if not self.characteristics_cache:
            logger.debug("Characteristics are not cached")

    def _get_characteristic_cached(self, chara_id):
        if not self.perip:
            return None
        if not self.characteristics_cache:
            self._cache_characteristics()
        if self.characteristics_cache:
            for characteristic in self.characteristics_cache:
                if characteristic.uuid == chara_id:
                    return characteristic
        return _get_characteristic(chara_id)

    def handle_request(self, method, params):
        """Handle requests from Scratch"""
        if self.delegate:
            # Do not allow notification during request handling to avoid
            # websocket server errors
            self.delegate.restart_notification_event.clear()

        logger.debug("handle request to BLE device")
        logger.debug(method)
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
            found = self._scan_devices(params)
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
            logger.debug("connecting to the BLE device")
            self.device = BLESession.found_devices[params['peripheralId']]
            self.deviceName = self.device.getValueText(0x9) or self.device.getValueText(0x8)
            try:
                self.perip = Peripheral(self.device)
                logger.info(f"connected to the BLE peripheral: {self.deviceName}")
                BLESession.found_devices.remove(self.device)
            except BTLEDisconnectError as e:
                logger.error(f"failed to connect to the BLE device \"{self.deviceName}\": {e}")
                self.status = self.DONE

            if self.perip:
                res["result"] = None
                self.status = self.CONNECTED
                BLESession.nr_connected += 1
                logger.debug(f"BLE session connected={BLESession.nr_connected}")
                self.delegate = self.BLEDelegate(self)
                self.perip.withDelegate(self.delegate)
                self._cache_characteristics()
            else:
                err_msg = f"BLE connect failed: {self.deviceName}"
                res["error"] = { "message": err_msg }
                self.status = self.DONE

        elif self.status == self.CONNECTED and method == 'read':
            logger.debug("handle read request")
            service_id = params['serviceId']
            chara_id = params['characteristicId']
            c = self._get_characteristic(chara_id)
            if not c or c.uuid != UUID(chara_id):
                logger.error(f"Failed to get characteristic {chara_id}")
                self.status = self.DONE
            else:
                with self.lock:
                    b = c.read()
                message = base64.standard_b64encode(b).decode('ascii')
                res['result'] = { 'message': message, 'encode': 'base64' }
            if params.get('startNotifications') == True:
                self.startNotifications(service_id, chara_id)

        elif self.status == self.CONNECTED and method == 'startNotifications':
            logger.debug("handle startNotifications request")
            service_id = params['serviceId']
            chara_id = params['characteristicId']
            self.startNotifications(service_id, chara_id)

        elif self.status == self.CONNECTED and method == 'stopNotifications':
            logger.debug("handle stopNotifications request")
            service_id = params['serviceId']
            chara_id = params['characteristicId']
            self.stopNotifications(service_id, chara_id)

        elif self.status == self.CONNECTED and method == 'write':
            logger.debug("handle write request")
            service_id = params['serviceId']
            chara_id = params['characteristicId']
            c = self._get_characteristic_cached(chara_id)
            if not c or c.uuid != UUID(chara_id):
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
                    c.write(data)
                logger.debug("released lock for c.write()")
                res['result'] = len(data)

        logger.debug(res)
        return res

    def setNotifications(self, service_id, chara_id, value):
        service = self._get_service(service_id)
        c = self._get_characteristic(chara_id)
        handle = c.getHandle()
        # prepare notification handler
        self.delegate.add_handle(service_id, chara_id, handle)
        # request notification to the BLE device
        with self.lock:
            self.perip.writeCharacteristic(handle + 1, value, True)

    def startNotifications(self, service_id, chara_id):
        logger.debug(f"start notification for {chara_id}")
        self.setNotifications(service_id, chara_id, b"\x01\x00")

    def stopNotifications(self, service_id, chara_id):
        logger.debug(f"stop notification for {chara_id}")
        self.setNotifications(service_id, chara_id, b"\x00\x00")

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
        session.close()

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
    parser.add_argument('-s', '--scan_seconds', type=float, default=10.0,
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
