from sdbus import DbusInterfaceCommonAsync, SdBus, sd_bus_open_system
from sdbus.dbus_proxy_async_interfaces import DbusIntrospectableAsync
import xml.etree.ElementTree as ET
from sdbus_async.bluez.adapter_api import AdapterInterfaceAsync
from sdbus_async.bluez.device_api import DeviceInterfaceAsync
from sdbus_async.bluez.gatt_api import (
    GattCharacteristicInterfaceAsync,
    GattServiceInterfaceAsync,
)
import asyncio
import base64
from asyncio import sleep
from os import dup, fdopen, close

import pyscrlink.scratch_link
from pyscrlink.scratch_link import BTUUID

import logging
logger = logging.getLogger('pyscrlink.scratch_link')

class BLEDBusSession(pyscrlink.scratch_link.Session):
    """
    Manage a session for Bluetooth Low Energy device such as micro:bit using
    DBus as backend.
    """

    INITIAL = 1
    DISCOVERY = 2
    CONNECTED = 3
    DONE = 4

    MAX_SCANNER_IF = 3

    connected_devices = {}

    class Device():
        def __init__(self, interface, path, node_name, name, address):
            self.interface = interface
            self.path = path
            self.node_name = node_name
            self.name = name
            self.address = address

    class Notification():
        def __init__(self, loop, acquired_fd, fd, fp, params):
            self.loop = loop
            self.acquired_fd = acquired_fd
            self.fd = fd
            self.fp = fp
            self.params = params

        def close(self):
            self.loop.remove_reader(self.fd)
            self.fp.close()

    def _connect_to_adapters(self):
        self.iface = None
        self.adapter = None
        self.adapter_introspect = None
        adapter = AdapterInterfaceAsync()
        for i in range(self.MAX_SCANNER_IF):
            iface = '/org/bluez/hci' + str(i)
            logger.debug(f"try connect to {iface}")
            try:
                adapter._connect('org.bluez', iface, bus=self.dbus)
                logger.debug(f"connected to {iface}")
                adapter_introspect = DbusIntrospectableAsync()
                adapter_introspect._connect('org.bluez', iface, bus=self.dbus)
                self.iface = iface
                self.adapter = adapter
                self.adapter_introspect = adapter_introspect
                return
            except Exception as e:
                logger.error(e)
        raise Exception("no adapter is available")

    async def _start_discovery(self):
        logger.debug(f"Starting discovery... {self.adapter}")
        assert not self.discovery_running
        await self.adapter.start_discovery()
        self.discovery_running = True

        asyncio.create_task(self._find_devices())
        asyncio.create_task(self._stop_discovery())
        logger.debug(f"Task to stop discovery has got created.")

    async def _matches(self, dev, filters):
        """
        Check if the found BLE device matches the filters Scratch specifies.
        """
        logger.debug(f"in matches {dev} {filters}")
        for f in filters:
            if 'services' in f:
                for s in f['services']:
                    logger.debug(f"service to check: {s}")
                    given_uuid = BTUUID(s)
                    logger.debug(f"given UUID: {given_uuid} hash={given_uuid.__hash__()}")
                    dev_uuids = await dev.interface.uuids
                    if not dev_uuids:
                        logger.debug(f"dev UUID not available")
                        continue
                    for uuid in dev_uuids:
                        u = BTUUID(uuid)
                        logger.debug(f"dev UUID: {u} hash={u.__hash__()}")
                        logger.debug(given_uuid == u)
                        if given_uuid == u:
                            logger.debug("match...")
                            return True
            if 'namePrefix' in f:
                logger.debug(f"given namePrefix: {f['namePrefix']}")
                if dev.name:
                    logger.debug(f"name: {dev. name}")
                    if dev.name.startswith(f['namePrefix']):
                        logger.debug(f"match...")
                        return True
            if 'name' in f or 'manufactureData' in f:
                logger.error("name/manufactureData filters not implemented")
                # TODO: implement other filters defined:
                # ref: https://github.com/LLK/scratch-link/blob/develop/Documentation/BluetoothLE.md
        return False

    async def _notify_device(self, device) -> None:
        params = { 'rssi': -80, 'name': 'Unknown' }
        try:
            params['rssi'] = await device.interface.rssi
        except Exception:
            None
        if device.name:
            params['name'] = device.name
        params['peripheralId'] = device.node_name
        await self._send_notification('didDiscoverPeripheral', params)

    async def _find_devices(self) -> None:
        assert self.discovery_running
        while self.discovery_running:
            await sleep(1)
            s = await self.adapter_introspect.dbus_introspect()
            parser = ET.fromstring(s)
            nodes = parser.findall("./node")
            if not nodes:
                logger.info("device not found")
                continue
            logger.debug(f"{len(nodes)} device(s) found")
            for node in nodes:
                node_name = node.attrib['name']
                logger.debug(f"  {node_name}")
                if self.found_devices.get(node_name):
                    continue
                devpath = self.iface + "/" + node_name
                if BLEDBusSession.connected_devices.get(devpath):
                    continue
                interface = DeviceInterfaceAsync()
                interface._connect('org.bluez', devpath, bus=self.dbus)
                try:
                    devname = await interface.name
                except Exception as e:
                    logger.debug(f"device {node_name} does not have name: {e}")
                devaddr = await interface.address
                device = self.Device(interface, devpath, node_name, devname,
                                     devaddr)
                if not await self._matches(device, self.discover_filters):
                    await interface.disconnect()
                    continue
                self.found_devices[node_name] = device
                await self._notify_device(device)

        logger.debug("end _find_device.")

    async def _stop_discovery(self) -> None:
        assert self.discovery_running
        logger.debug(f"Wait discovery for {self.scan_seconds} seconds")
        await sleep(self.scan_seconds)
        logger.debug(f"Stopping discovery... {self.adapter}")
        self.discovery_running = False
        await self.adapter.stop_discovery()

    def __init__(self, websocket, loop, scan_seconds):
        super().__init__(websocket, loop, scan_seconds)
        logger.debug("dbus init")
        self.status = self.INITIAL
        self.dbus = sd_bus_open_system()
        self.discovery_running = False
        self.iface = None
        self.services = {}
        self.chars = {}
        self.chars_cache = {}
        self.notifications = {}
        self._connect_to_adapters()
        self.found_devices = {}

    async def _get_characteristics(self, service_path):
        service_introspect = DbusInterfaceCommonAsync()
        service_introspect._connect('org.bluez', service_path, bus=self.dbus)
        s = await service_introspect.dbus_introspect()
        parser = ET.fromstring(s)
        nodes = parser.findall("./node")
        if not nodes:
            logger.error(f"characteristic not found at {service_path}")
            return
        for node in nodes:
            path = service_path + '/' + node.attrib['name']
            if self.chars.get(path):
                continue
            logger.debug(f"getting GATT characteristic at {path}")
            char = GattCharacteristicInterfaceAsync()
            char._connect('org.bluez', path, bus=self.dbus)
            self.chars[path] = char
            cid = await char.uuid
            logger.debug(f"found char {cid}")

    async def _get_services(self):
        # do D-Bus introspect to the device path and get service paths under it
        for i in range(5):
            dev_introspect = DbusInterfaceCommonAsync()
            dev_introspect._connect('org.bluez', self.device.path,
                                    bus=self.dbus)
            s = await dev_introspect.dbus_introspect()
            parser = ET.fromstring(s)
            nodes = parser.findall("./node")
            if nodes:
                break
            else:
                logger.error("Service not found. Try again.")
                await sleep(1)
        if not nodes:
            return []
        for node in nodes:
            path = self.device.path + '/' + node.attrib['name']
            if self.services.get(path):
                continue
            logger.debug(f"getting GATT service at {path}")
            service = GattServiceInterfaceAsync()
            service._connect('org.bluez', path, bus=self.dbus)
            self.services[path] = service
            sid = await service.uuid
            logger.debug(f"found service {sid}")
            await self._get_characteristics(path)

    async def _get_char(self, id):
        char = self.chars_cache.get(id)
        if char:
            return char
        for i in range(5):
            await self._get_services()
            btuuid = BTUUID(id)
            for char in self.chars.values():
                raw_uuid = await char.uuid
                char_uuid = BTUUID(raw_uuid)
                if char_uuid == btuuid:
                    self.chars_cache[id] = char
                    return char
            logger.error(f"Can not get characteristic: {id}. Retry.")
        logger.error(f"Abandoned to get characteristic: {id}.")
        return None

    async def _start_notification(self, sid, cid, char):
        logger.debug('startNotification')
        (acquired_fd, mtu) = await char.acquire_notify({})
        fd = dup(acquired_fd)
        fp = fdopen(fd, mode='rb', buffering=0, newline=None)
        self.loop.add_reader(fd, self._read_notification, fd)
        notification = self.Notification(self.loop, acquired_fd, fd, fp, {
            'serviceId': sid,
            'characteristicId': cid,
            'encoding': 'base64'
        })
        self.notifications[fd] = notification
        logger.debug(f'added notification reader: {notification}')

    def _stop_notifications(self):
        for n in self.notifications.values():
            n.close()

    def _read_notification(self, *args):
        fd = args[0]
        notification = self.notifications[fd]
        data = notification.fp.read()
        if len(data) == 0:
            logger.debug(f'empty notification data')
            asyncio.create_task(self.async_close())
            return
        params = notification.params.copy()
        params['message'] = base64.standard_b64encode(data).decode('ascii')
        self.loop.create_task(self._send_notification('characteristicDidChange', params))

    def handle_request(self, method, params):
        logger.debug("handle request")

    async def async_handle_request(self, method, params):
        logger.debug(f"async handle request: {method} {params}")

        res = { "jsonrpc": "2.0" }
        err_msg = None

        if self.status == self.INITIAL and method == 'discover':
            self.discover_filters = params['filters']
            logger.debug(f"discover: {self.discover_filters}")
            try:
                await self._start_discovery()
                logger.debug(f"discover started: {self.discover_filters}")
                res["result"] = None
                self.status = self.DISCOVERY
            except Exception as e:
                res["error"] = { "message": "Failed to start device discovery" }
                self.status = self.DONE

        elif self.status == self.DISCOVERY and method == 'connect':
            logger.debug("connecting to the BLE device")
            dev = self.found_devices[params['peripheralId']]
            try:
                logger.debug(f"  {dev}")
                await dev.interface.connect()
                res["result"] = None
                self.device = dev
                self.status = self.CONNECTED
                logger.info(f"Connected: '{dev.name}'@{dev.address}")
                BLEDBusSession.connected_devices[dev.path] = dev
            except NotImplementedError as e:
                logger.error(e)
                res["error"] = { "message": "Failed to connect to device" }
                self.status = self.DONE
            except Exception as e:
                logger.error(f"failed to connect: {e}")
                res["error"] = { "message": "Failed to connect to device" }
                self.status = self.DONE

        elif self.status == self.CONNECTED and method == 'read':
            logger.debug("handle read request")
            service_id = params['serviceId']
            chara_id = params['characteristicId']
            c = await self._get_char(chara_id)
            value = await c.read_value({})
            message = base64.standard_b64encode(value).decode('ascii')
            res['result'] = { 'message': message, 'encode': 'base64' }
            if params.get('startNotifications') == True:
                await self._start_notification(service_id, chara_id, c)

        elif self.status == self.CONNECTED and method == 'write':
            logger.debug(f"handle write request {params}")
            service_id = params['serviceId']
            chara_id = params['characteristicId']
            c = await self._get_char(chara_id)
            if params['encoding'] != 'base64':
                logger.error("encoding other than base 64 is not "
                             "yet supported: ", params['encoding'])
            else:
                msg_bstr = params['message'].encode('ascii')
                data = base64.standard_b64decode(msg_bstr)
                await c.write_value(data, {})
                res['result'] = len(data)

        logger.debug(res)
        return res

    def end_request(self):
        logger.debug("end request")
        return False

    async def async_close(self):
        if not self.device:
            return
        dev = self.device
        logger.info(f"Disconnecting from '{dev.name}'@{dev.address}")
        self._stop_notifications()
        await dev.interface.disconnect()
        BLEDBusSession.connected_devices.pop(dev.path)
        logger.info(f"Disconnected from '{dev.name}'@{dev.address}")
        self.device = None
        await self.websocket.close()
        return

    def close(self):
        logger.debug("close")
        return
