#!/usr/bin/env python
import select
import struct

"""Scratch link on bluepy"""

import asyncio
import pathlib
import ssl
import websockets
import json
import base64
import logging
import sys
import signal
import traceback

# for Bluetooth (e.g. Lego EV3)
import bluetooth

# for BLESession (e.g. BBC micro:bit)
from bluepy.btle import Scanner, UUID, Peripheral, DefaultDelegate
from bluepy.btle import BTLEDisconnectError, BTLEManagementError

import threading
import time
import queue

# for websockets certificate
import gencert

logLevel = logging.INFO

# handle command line options
if __name__ == "__main__":
    opts = [opt for opt in sys.argv[1:] if opt.startswith("-")]
    if "-h" in opts:
        print((f"Usage: {sys.argv[0]} [OPTS]\n"
               "OPTS:\t-h Show this help.\n"
               "\t-d Print debug messages."
        ))
        sys.exit(1)
    elif "-d" in opts:
        print("Print debug messages")
        logLevel = logging.DEBUG

# for logging
logger = logging.getLogger(__name__)
formatter = logging.Formatter(fmt='%(asctime)s %(message)s')
handler = logging.StreamHandler()
handler.setLevel(logLevel)
handler.setFormatter(formatter)
logger.setLevel(logLevel)
logger.addHandler(handler)
logger.propagate = False

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

    INITIAL = 1
    DISCOVERY = 2
    DISCOVERY_COMPLETE = 3
    CONNECTED = 4
    DONE = 5

    # Split this into discovery thread and communication thread
    # discovery thread should auto-terminate

    class BTThread(threading.Thread):
        """
        Separated thread to control notifications to Scratch.
        It handles device discovery notification in DISCOVERY status
        and notifications from bluetooth devices in CONNECTED status.
        """

        class BTDiscoverer(bluetooth.DeviceDiscoverer):

            def __init__(self, major_class, minor_class):
                super().__init__()
                self.major_class = major_class
                self.minor_class = minor_class
                self.found_devices = {}
                self.done = False

            def pre_inquiry(self):
                self.done = False

            def device_discovered(self, address, device_class, rssi, name):
                logger.debug(f"Found device {name} addr={address} class={device_class} rssi={rssi}")
                major_class = (device_class & 0x1F00) >> 8
                minor_class = (device_class & 0xFF) >> 2
                if major_class == self.major_class and minor_class == self.minor_class:
                    self.found_devices[address] = (name, device_class, rssi)

            def inquiry_complete(self):
                self.done = True

        def __init__(self, session, major_device_class, minor_device_class):
            threading.Thread.__init__(self)
            self.session = session
            self.major_device_class = major_device_class
            self.minor_device_class = minor_device_class
            self.cancel_discovery = False
            self.ping_time = None

        def discover(self):
            discoverer = self.BTDiscoverer(self.major_device_class, self.minor_device_class)
            discoverer.find_devices(lookup_names=True)
            while self.session.status == self.session.DISCOVERY and not discoverer.done and not self.cancel_discovery:
                readable = select.select([discoverer], [], [], 0.5)[0]
                if discoverer in readable:
                    discoverer.process_event()
                    for addr, (device_name, device_class, rssi) in discoverer.found_devices.items():
                        logger.debug(f"notifying discovered {addr}: {device_name}")
                        params = {"rssi": rssi, 'peripheralId': addr, 'name': device_name.decode("utf-8")}
                        self.session.notify('didDiscoverPeripheral', params)
                    discoverer.found_devices.clear()

            if not discoverer.done:
                discoverer.cancel_inquiry()

        def run(self):
            while self.session.status != self.session.DONE:

                logger.debug("loop in BT thread")
                current_time = int(round(time.time()))

                if self.session.status == self.session.DISCOVERY and not self.cancel_discovery:
                    logger.debug("in discovery status:")
                    try:
                        self.discover()
                        self.ping_time = current_time + 5
                    finally:
                        self.session.status = self.session.DISCOVERY_COMPLETE

                elif self.session.status == self.session.CONNECTED:
                    logger.debug("in connected status:")
                    sock = self.session.sock
                    try:
                        ready = select.select([sock], [], [], 1)
                        if ready[0]:
                            header = sock.recv(2)
                            [msg_len] = struct.unpack("<H", header)
                            msg_data = sock.recv(msg_len)
                            data = header + msg_data
                            params = {'message': base64.standard_b64encode(data).decode('utf-8'), "encoding": "base64"}
                            self.session.notify('didReceiveMessage', params)
                            self.ping_time = current_time + 5

                    except Exception as e:
                            logger.error(e)
                            self.session.close()
                            break

                    # To avoid repeated lock by this single thread,
                    # yield CPU to other lock waiting threads.
                    time.sleep(0)
                else:
                    # Nothing to do:
                    time.sleep(1)

                # Terminate if we have lost websocket connection to Scratch (e.g. browser closed)
                if self.ping_time is None or self.ping_time <= current_time:
                    try:
                        self.session.notify('ping', {})
                        self.ping_time = current_time + 5
                    except Exception as e:
                        logger.error(e)
                        self.session.close()
                        break

    def __init__(self, websocket, loop):
        super().__init__(websocket, loop)
        self.status = self.INITIAL
        self.sock = None
        self.bt_thread = None

    def close(self):
        self.status = self.DONE
        if self.sock:
            logger.info(f"disconnect to BT socket: {self.sock}")
            self.sock.close()
            self.sock = None

    def __del__(self):
        self.close()

    def handle_request(self, method, params):
        """Handle requests from Scratch"""
        logger.debug("handle request to BT device")
        logger.debug(method)
        if len(params) > 0:
            logger.debug(params)

        res = { "jsonrpc": "2.0" }

        if self.status == self.INITIAL and method == 'discover':
            logger.debug("Starting async discovery")
            self.status = self.DISCOVERY
            self.bt_thread = self.BTThread(self, params["majorDeviceClass"], params["minorDeviceClass"])
            self.bt_thread.start()
            res["result"] = None

        elif self.status in [self.DISCOVERY, self.DISCOVERY_COMPLETE] and method == 'connect':

            # Cancel discovery
            while self.status == self.DISCOVERY:
                logger.debug("Cancelling discovery")
                self.bt_thread.cancel_discovery = True
                time.sleep(1)

            addr = params['peripheralId']
            logger.debug(f"connecting to the BT device {addr}")
            try:
                self.sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
                self.sock.connect((addr, 1))
                logger.info(f"connected to BT device: {addr}")
            except bluetooth.BluetoothError as e:
                logger.error(f"failed to connect to BT device: {e}", exc_info=e)
                self.status = self.DONE
                self.sock = None

            if self.sock:
                res["result"] = None
                self.status = self.CONNECTED
            else:
                err_msg = f"BT connect failed: {addr}"
                res["error"] = { "message": err_msg }
                self.status = self.DONE

        elif self.status == self.CONNECTED and method == 'send':
            logger.debug("handle send request")
            if params['encoding'] != 'base64':
                logger.error("encoding other than base 64 is not "
                                 "yet supported: ", params['encoding'])
            msg_bstr = params['message'].encode('ascii')
            data = base64.standard_b64decode(msg_bstr)
            self.sock.send(data)
            res['result'] = len(data)

        logger.debug(res)
        return res

    def end_request(self):
        logger.debug(f"end_request of BTSession {self}")
        return self.status == self.DONE


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
                    devices = self.session.found_devices
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
        self.found_devices = []
        self.device = None
        self.deviceName = None
        self.perip = None
        self.delegate = None

    def close(self):
        self.status = self.DONE
        if self.perip:
            logger.info("disconnect from the BLE peripheral: "
                        f"{self.deviceName}")
            with self.lock:
                self.perip.disconnect()
            self.perip = None

    def __del__(self):
        self.close()

    def _get_dev_uuid(self, dev):
        for adtype in self.SERVICE_CLASS_UUID_ADTYPES:
            service_class_uuid = dev.getValueText(adtype)
            if service_class_uuid:
                logger.debug(self.SERVICE_CLASS_UUID_ADTYPES[adtype])
                return UUID(service_class_uuid)
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
                    logger.debug(f"given: {given_uuid}")
                    dev_uuid = self._get_dev_uuid(dev)
                    if not dev_uuid:
                        continue
                    logger.debug(f"dev: {dev_uuid}")
                    logger.debug(given_uuid == dev_uuid)
                    if given_uuid == dev_uuid:
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

    def _get_service(self, service_id):
        with self.lock:
            service = self.perip.getServiceByUUID(UUID(service_id))

    def _get_characteristic(self, chara_id):
        if not self.perip:
            return None
        with self.lock:
            charas = self.perip.getCharacteristics(uuid=chara_id)
            return charas[0]

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
            found_ifaces = 0
            for i in range(self.MAX_SCANNER_IF):
                scanner = Scanner(iface=i)
                try:
                    devices = scanner.scan(10.0)
                    for dev in devices:
                        if self.matches(dev, params['filters']):
                            self.found_devices.append(dev)
                    found_ifaces += 1
                    logger.debug(f"BLE device found with iface #{i}");
                except BTLEManagementError as e:
                    logger.debug(f"BLE iface #{i}: {e}");

            if found_ifaces == 0:
                err_msg = "Can not scan BLE devices. Check BLE controller."
                logger.error(err_msg);
                res["error"] = { "message": err_msg }
                self.status = self.DONE

            if len(self.found_devices) == 0 and not err_msg:
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
            self.device = self.found_devices[params['peripheralId']]
            self.deviceName = self.device.getValueText(0x9) or self.device.getValueText(0x8)
            try:
                self.perip = Peripheral(self.device)
                logger.info(f"connected to the BLE peripheral: {self.deviceName}")
            except BTLEDisconnectError as e:
                logger.error(f"failed to connect to the BLE device \"{self.deviceName}\": {e}")
                self.status = self.DONE

            if self.perip:
                res["result"] = None
                self.status = self.CONNECTED
                self.delegate = self.BLEDelegate(self)
                self.perip.withDelegate(self.delegate)
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
            c = self._get_characteristic(chara_id)
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

# Prepare certificate of the WSS server
gencert.prep_cert()

# kick start WSS server
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
localhost_cer = gencert.cert_file_path
localhost_key = gencert.key_file_path
ssl_context.load_cert_chain(localhost_cer, localhost_key)
sessionTypes = { '/scratch/ble': BLESession, '/scratch/bt': BTSession }

async def ws_handler(websocket, path):
    try:
        logger.info(f"Start session for web socket path: {path}")
        loop = asyncio.get_event_loop()
        session = sessionTypes[path](websocket, loop)
        await session.handle()
    except Exception as e:
        logger.error(f"Failure in session for web socket path: {path}")
        logger.error(e)

start_server = websockets.serve(
    ws_handler, "device-manager.scratch.mit.edu", 20110, ssl=ssl_context
)

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

while True:
    try:
        asyncio.get_event_loop().run_until_complete(start_server)
        logger.info("Started scratch-link")
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt as e:
        stack_trace()
        break
    except Exception as e:
        logger.info("Restarting scratch-link...")

