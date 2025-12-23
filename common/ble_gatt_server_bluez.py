"""BlueZ GATT Server helper using dbus-next.

Provides a minimal GATT Service + Characteristics for the SIC project.

- Service contains two characteristics:
  - SIC_DATA_CHARACTERISTIC_UUID: write-only (Nodes can write DTLS Inbox messages)
  - SIC_NOTIFY_CHARACTERISTIC_UUID: notify (Sink will send Heartbeats)

This implementation is intentionally minimal and defensive: if dbus-next or
BlueZ are not available it will raise a RuntimeError so callers can fallback.

Note: Emitting notifications is implemented by sending a PropertiesChanged
signal for the characteristic's interface with the 'Value' property updated.
This matches how BlueZ expects server implementations to notify subscribed
centrals.
"""

from __future__ import annotations

import asyncio
import logging
import struct
import uuid
from typing import Optional, Callable, Dict

try:
    from dbus_next.aio import MessageBus
    from dbus_next.service import ServiceInterface, dbus_property, method, signal
    from dbus_next import Variant, BusType
except Exception as e:
    MessageBus = None  # type: ignore
    ServiceInterface = object  # type: ignore
    Variant = None  # type: ignore
    BusType = None
    dbus_next_import_error = e

logger = logging.getLogger(__name__)

# UUIDs (should match those used elsewhere)
SIC_SERVICE_UUID = "d227d8e8-d4d1-4475-a835-189f7823f64c"
SIC_DATA_CHARACTERISTIC_UUID = "d227d8e8-d4d1-4475-a835-189f7823f64d"
SIC_NOTIFY_CHARACTERISTIC_UUID = "d227d8e8-d4d1-4475-a835-189f7823f64e"


class GattCharacteristic(ServiceInterface):
    """Implements a minimal org.bluez.GattCharacteristic1 interface."""

    def __init__(self, path: str, uuid_str: str, flags: list, on_write: Optional[Callable[[bytes], None]] = None):
        super().__init__('org.bluez.GattCharacteristic1')
        self.path = path
        self.uuid = uuid_str
        self.flags = flags
        self.on_write = on_write
        self._notifying = False
        self._value = b''
        # server reference will be attached by the creator if needed
        self._server = None

    @dbus_property(signature='s')
    def UUID(self) -> 's':
        return self.uuid

    @dbus_property(signature='o')
    def Service(self) -> 'o':
        # filled by the server when exporting
        return self._service_path

    @dbus_property(signature='as')
    def Flags(self) -> 'as':
        return self.flags

    @method()
    def ReadValue(self, options: 'a{sv}') -> 'ay':
        # Return current value
        logger.debug('ReadValue called on %s', self.path)
        try:
            print(f"[GATT DEBUG] ReadValue called on {self.path} - current len={len(self._value)}")
        except Exception:
            pass
        return bytes(self._value)

    @method()
    def WriteValue(self, value: 'ay', options: 'a{sv}') -> None:
        # value is a bytearray/list of bytes
        logger.debug('WriteValue called on %s (len=%d)', self.path, len(value))
        try:
            print(f"[GATT DEBUG] WriteValue on {self.path} len={len(value)} payload={bytes(value).hex()[:200]}")
        except Exception:
            pass
        data = bytes(value)
        self._value = data
        if self.on_write:
            try:
                print(f"[GATT DEBUG] Calling on_write callback for {self.path}")
                self.on_write(data)
            except Exception:
                logger.exception('on_write callback failed')

    @method()
    def StartNotify(self) -> None:
        logger.info('StartNotify called on %s', self.path)
        print(f"[GATT DEBUG] StartNotify called on {self.path}")
        self._notifying = True
        # Inform server that a central has subscribed
        try:
            if getattr(self, '_server', None) is not None:
                self._server._on_subscribe(self)
        except Exception:
            logger.exception('Error while handling StartNotify subscription')

    @method()
    def StopNotify(self) -> None:
        logger.info('StopNotify called on %s', self.path)
        print(f"[GATT DEBUG] StopNotify called on {self.path}")
        self._notifying = False
        # Inform server that a central unsubscribed
        try:
            if getattr(self, '_server', None) is not None:
                self._server._on_unsubscribe(self)
        except Exception:
            logger.exception('Error while handling StopNotify unsubscription')


class GattService(ServiceInterface):
    def __init__(self, path: str, uuid_str: str, primary: bool = True):
        super().__init__('org.bluez.GattService1')
        self.path = path
        self.uuid = uuid_str
        self.primary = primary

    @dbus_property(signature='s')
    def UUID(self) -> 's':
        return self.uuid

    @dbus_property(signature='b')
    def Primary(self) -> 'b':
        return self.primary

    @dbus_property(signature='ao')
    def Characteristics(self) -> 'ao':
        return []


class BlueZGattServer:
    """High-level helper to register a GATT application with BlueZ and handle
    writes/notifications for the SIC service.

    Usage:
      server = BlueZGattServer(on_write=callback, adapter='hci0')
      await server.start()
      await server.notify_all(b"payload")
      await server.stop()
    """

    def __init__(self, on_write: Callable[[bytes], None], adapter: str = 'hci0'):
        if MessageBus is None:
            raise RuntimeError(f"dbus-next not available: {dbus_next_import_error}")
        self.on_write = on_write
        self.adapter = adapter
        self.bus: Optional[MessageBus] = None
        self.app_path = '/com/sic/gatt_app'
        self.service_path = f'{self.app_path}/service0'
        self.char_write_path = f'{self.service_path}/char_write0'
        self.char_notify_path = f'{self.service_path}/char_notify0'
        self._exported_objects = []
        self._characteristics: Dict[str, GattCharacteristic] = {}
        # Track number of active notify subscribers (approximation)
        self._subscriber_count = 0

    async def start(self) -> None:
        logger.info('Starting BlueZ GATT server (adapter=%s)', self.adapter)
        print(f"[GATT DEBUG] Starting GATT server on adapter={self.adapter} app_path={self.app_path}")
        # Connect to system bus
        try:
            self.bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
        except Exception:
            # fallback
            self.bus = await MessageBus().connect()

        # Create service and characteristics
        service = GattService(self.service_path, SIC_SERVICE_UUID)
        char_write = GattCharacteristic(self.char_write_path, SIC_DATA_CHARACTERISTIC_UUID, ['write-without-response', 'write'], on_write=self._on_write)
        char_notify = GattCharacteristic(self.char_notify_path, SIC_NOTIFY_CHARACTERISTIC_UUID, ['notify'], on_write=None)

        # Attach service path to characteristics for Service property
        char_write._service_path = self.service_path
        char_notify._service_path = self.service_path
        # Give the characteristic a back-reference to the server so it can
        # inform us when StartNotify/StopNotify are called by BlueZ.
        char_write._server = self
        char_notify._server = self

        # Export objects
        self.bus.export(self.service_path, service)
        self.bus.export(self.char_write_path, char_write)
        self.bus.export(self.char_notify_path, char_notify)

        self._exported_objects.extend([self.service_path, self.char_write_path, self.char_notify_path])
        self._characteristics['write'] = char_write
        self._characteristics['notify'] = char_notify

        print(f"[GATT DEBUG] Exported objects: {self._exported_objects}")

        # Register application with BlueZ GattManager1
        adapter_path = f'/org/bluez/{self.adapter}'
        introspection = await self.bus.introspect('org.bluez', adapter_path)
        manager = self.bus.get_proxy_object('org.bluez', adapter_path, introspection)
        if asyncio.iscoroutine(manager):
            manager = await manager
        gatt_manager = manager.get_interface('org.bluez.GattManager1')

        # Call RegisterApplication
        try:
            await gatt_manager.call_register_application(self.app_path, {})
            logger.info('GATT application registered at %s', self.app_path)
            print(f"[GATT DEBUG] Registered GATT application at {self.app_path} with BlueZ GattManager1")
        except Exception as e:
            logger.exception('Failed to register GATT application: %s', e)
            # Cleanup exported objects
            for p in self._exported_objects:
                try:
                    self.bus.unexport(p)
                except Exception:
                    pass
            raise

    def _on_subscribe(self, char: GattCharacteristic) -> None:
        """Called when a central subscribes (StartNotify) to a notify characteristic."""
        # We don't have the device identity here, but a subscription implies
        # there's at least one central interested in notifications. Track a
        # simple counter so the Sink can know there are subscribers.
        self._subscriber_count += 1
        logger.info('GATT subscriber added (count=%d) for %s', self._subscriber_count, char.path)

    def _on_unsubscribe(self, char: GattCharacteristic) -> None:
        """Called when a central unsubscribes (StopNotify)."""
        try:
            self._subscriber_count = max(0, self._subscriber_count - 1)
        except Exception:
            self._subscriber_count = 0
        logger.info('GATT subscriber removed (count=%d) for %s', self._subscriber_count, char.path)

    def get_subscriber_count(self) -> int:
        """Return the number of active notify subscribers (best-effort)."""
        return self._subscriber_count

    async def stop(self) -> None:
        # Unregister application and unexport objects
        try:
            if self.bus:
                adapter_path = f'/org/bluez/{self.adapter}'
                introspection = await self.bus.introspect('org.bluez', adapter_path)
                manager = self.bus.get_proxy_object('org.bluez', adapter_path, introspection)
                if asyncio.iscoroutine(manager):
                    manager = await manager
                gatt_manager = manager.get_interface('org.bluez.GattManager1')
                try:
                    await gatt_manager.call_unregister_application(self.app_path)
                except Exception:
                    pass
        finally:
            if self.bus:
                for p in self._exported_objects:
                    try:
                        print(f"[GATT DEBUG] Unexporting {p}")
                        self.bus.unexport(p)
                    except Exception as e:
                        print(f"[GATT DEBUG] Error unexporting {p}: {e}")
                        pass
                self._exported_objects = []
                self._characteristics = {}
                self.bus = None
                logger.info('GATT server stopped')
                print('[GATT DEBUG] GATT server stopped and cleaned up')

    def _on_write(self, data: bytes) -> None:
        # Called in event loop context
        try:
            self.on_write(data)
        except Exception:
            logger.exception('on_write handler failed')

    async def notify_all(self, data: bytes) -> None:
        """Notify all subscribed centrals by emitting PropertiesChanged for the
        notify characteristic with Value set to the payload (as 'ay')."""
        if not self.bus or 'notify' not in self._characteristics:
            logger.warning('Cannot notify: GATT server not running')
            return

        char = self._characteristics['notify']
        # Update internal value
        char._value = data

        # Build changed dict: a{sv} with 'Value': Variant('ay', bytes)
        changed = {'Value': Variant('ay', bytes(data))}

        # Emit PropertiesChanged signal on org.freedesktop.DBus.Properties
        try:
            # dbus-next low-level signal emitter: destination=None, path, interface, name, signature, body
            # Body is [interface_name, changed_dict, invalidated_array]
            self.bus.emit_signal(
                None,
                char.path,
                'org.freedesktop.DBus.Properties',
                'PropertiesChanged',
                'sa{sv}as',
                [
                    'org.bluez.GattCharacteristic1',
                    changed,
                    []
                ]
            )
            logger.debug('Emitted PropertiesChanged for notification (len=%d)', len(data))
        except Exception:
            logger.exception('Failed to emit notification')


__all__ = ['BlueZGattServer']
