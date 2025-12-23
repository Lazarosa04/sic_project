"""common/ble_advertiser_bluez.py

BlueZ (Linux) LE Advertising helper using D-Bus (dbus-next).

This module provides a minimal advertiser that registers an
org.bluez.LEAdvertisement1 object with BlueZ's LEAdvertisingManager1.

Notes:
- Requires BlueZ (Linux) and the `dbus-next` package.
- Must be run on a system with a BLE adapter (hci0) and BlueZ >=5.42.
- This implementation is defensive: if BlueZ or dbus-next are not
  available it will raise a clear exception or log a warning.

Usage (async):
  from common.ble_advertiser_bluez import BlueZAdvertiser
  adv = BlueZAdvertiser(nid, hop_count)
  await adv.start()   # registers advertisement
  await adv.stop()    # unregisters advertisement

This is intentionally small and focused on ManufacturerData advertising
to match the project's format (Company ID 0xFFFF + NID(16) + HopCount(4)).
"""

from __future__ import annotations

import asyncio
import struct
import uuid
import logging
from typing import Optional, Dict

try:
    from dbus_next.aio import MessageBus
    from dbus_next.service import (ServiceInterface, dbus_property, method, PropertyAccess)
    from dbus_next import Variant
except Exception as e:
    MessageBus = None  # type: ignore
    ServiceInterface = object  # type: ignore
    Variant = None  # type: ignore
    PropertyAccess = None
    dbus_next_import_error = e

logger = logging.getLogger(__name__)


def _dbus_prop(signature: str):
    """Returns a read-only dbus_property decorator."""
    if MessageBus is None:
        def _noop(f):
            return f
        return _noop

    # dbus-next >= 0.2.3 uses PropertyAccess enum.
    if PropertyAccess:
        # dbus_property takes (access, name=None, disabled=False).
        # Use READ by default; individual properties can be made
        # writable if a setter is implemented. This avoids requiring
        # setters for every property and prevents ValueError on init.
        return dbus_property(PropertyAccess.READ)

    # Fallback for environments where PropertyAccess is not found,
    # call dbus_property with no args (defaults to READWRITE).
    logger.warning("dbus_next.service.PropertyAccess not found. Using default dbus_property decorator.")
    return dbus_property()


def _dbus_method():
    """Return a method decorator compatible with the installed dbus-next, or a noop."""
    try:
        _m = method  # type: ignore
    except NameError:
        def _noop(*args, **kwargs):
            def _dec(f):
                return f
            return _dec
        return _noop
    else:
        # dbus-next's `method` is a decorator factory; return the decorated factory
        # so callers can use `_dbus_method()` (which should evaluate to a decorator).
        return method()


def _build_manufacturer_data(nid: str, hop_count: int) -> Dict[int, 'ay']:
    """Return a dict suitable for BlueZ ManufacturerData: {company_id: Variant('ay', bytes)}"""
    nid_bytes = uuid.UUID(nid).bytes
    hop_bytes = struct.pack('<i', hop_count)
    payload = nid_bytes + hop_bytes
    # BlueZ expects a{qv} where the value for 'ay' is a bytes object
    return {0xFFFF: Variant('ay', payload)}


class Advertisement(ServiceInterface):
    """Implements org.bluez.LEAdvertisement1 minimal interface."""

    def __init__(self, path: str, nid: str, hop_count: int):
        super().__init__('org.bluez.LEAdvertisement1')
        self.path = path
        self.nid = nid
        self.hop_count = hop_count

    # dbus-next v0.2.x expects dbus_property to be called with a PropertyAccess
    # and the function must have a return annotation with the DBus type string.
    @_dbus_prop('s')
    def Type(self) -> 's':
        return 'peripheral'

    @_dbus_prop('as')
    def ServiceUUIDs(self) -> 'as':
        return []

    @_dbus_prop('a{qv}')
    def ManufacturerData(self) -> 'a{qv}':
        return _build_manufacturer_data(self.nid, self.hop_count)

    @_dbus_prop('s')
    def LocalName(self) -> 's':
        # optional: use short local name
        return f"SIC-{self.nid[:8]}"

    @_dbus_prop('as')
    def Includes(self) -> 'as':
        # list of include flags accepted by BlueZ, e.g. ['tx-power']
        return []

    @_dbus_prop('n')
    def TxPower(self) -> 'n':
        # Some BlueZ versions may emit or expect a TxPower property change.
        # Provide a stable default (0 dBm). Returning an integer avoids
        # dbus-next raising when it receives a PropertiesChanged
        # containing 'TxPower'. This is benign and keeps compatibility.
        return 0

    @_dbus_method()
    def Release(self):  # called by BlueZ when released
        logger.info('BlueZ Advertisement released')


class BlueZAdvertiser:
    """High-level helper to register/unregister a manufacturer-data advertisement.

    Example:
        adv = BlueZAdvertiser(nid, hop_count)
        await adv.start()
        # ... later
        await adv.stop()
    """

    def __init__(self, nid: str, hop_count: int = 0, adapter: str = 'hci0'):
        if MessageBus is None:
            raise RuntimeError(f"dbus-next not available: {dbus_next_import_error}")

        self.nid = nid
        self.hop_count = hop_count
        self.adapter = adapter
        self.bus: Optional[MessageBus] = None
        self.advertisement: Optional[Advertisement] = None
        self.ad_path = f'/com/sic/advertisement/{self.nid.replace('-', '')[:16]}'
        self._registered = False

    async def start(self) -> None:
        """Register advertisement with BlueZ LEAdvertisingManager1."""
        if self._registered:
            logger.debug('Advertisement already registered')
            return

        # Connect to the system bus. Different dbus-next versions accept
        # different constructors/parameters; try a few patterns for
        # compatibility with older/newer releases.
        self.bus = None
        try:
            # Preferred: default ctor and connect()
            self.bus = await MessageBus().connect()
        except Exception:
            try:
                # Fallback: explicit system bus type if available
                from dbus_next import BusType
                self.bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
            except Exception as e:
                logger.exception('Failed to connect to D-Bus system bus: %s', e)
                raise

        # Find adapter path (simple heuristic)
        adapter_path = f'/org/bluez/{self.adapter}'

        # Create advertisement service object
        # Build manufacturer payload and log it for debugging so we can
        # inspect exactly what is being registered with BlueZ.
        try:
            md = _build_manufacturer_data(self.nid, self.hop_count)
            # md is {company_id: Variant('ay', bytes)}
            company = next(iter(md.keys())) if md else None
            raw = md[company].value if company is not None and hasattr(md[company], 'value') else md[company]
            logger.info('Preparing ManufacturerData: company=0x%04X len=%d bytes payload=%s',
                        company if company is not None else 0, len(raw), raw.hex() if isinstance(raw, (bytes, bytearray)) else repr(raw))
        except Exception:
            logger.exception('Failed to build ManufacturerData for logging')

        self.advertisement = Advertisement(self.ad_path, self.nid, self.hop_count)
        self.bus.export(self.ad_path, self.advertisement)

        # Register with LEAdvertisingManager1
        try:
            # Get introspection data and obtain proxy object
            introspection = await self.bus.introspect('org.bluez', adapter_path)
            # dbus-next versions differ: get_proxy_object may be sync or async.
            manager = self.bus.get_proxy_object('org.bluez', adapter_path, introspection)
            if asyncio.iscoroutine(manager):
                manager = await manager
            ad_manager = manager.get_interface('org.bluez.LEAdvertisingManager1')
            logger.info('Registering advertisement on BlueZ adapter %s', adapter_path)
            await ad_manager.call_register_advertisement(self.ad_path, {})
            self._registered = True
            logger.info('Advertisement registered: NID=%s Hop=%s', self.nid, self.hop_count)
        except Exception as e:
            logger.warning('Failed to register advertisement: %s', e)
            # Cleanup exported object
            try:
                if self.bus and self.advertisement:
                    self.bus.unexport(self.ad_path)
            except Exception:
                pass
            raise

    async def stop(self) -> None:
        """Unregister advertisement and cleanup."""
        if not self._registered:
            return

        adapter_path = f'/org/bluez/{self.adapter}'
        try:
            introspection = await self.bus.introspect('org.bluez', adapter_path)
            manager = self.bus.get_proxy_object('org.bluez', adapter_path, introspection)
            if asyncio.iscoroutine(manager):
                manager = await manager
            ad_manager = manager.get_interface('org.bluez.LEAdvertisingManager1')
            await ad_manager.call_unregister_advertisement(self.ad_path)
            logger.info('Advertisement unregistered')
        except Exception as e:
            logger.warning('Error while unregistering advertisement: %s', e)
        finally:
            try:
                if self.bus and self.advertisement:
                    self.bus.unexport(self.ad_path)
            except Exception:
                pass
            self._registered = False

    def update_hop_count(self, new_hop: int):
        """Update hop count for future advertisements (requires re-registration to take effect)."""
        self.hop_count = new_hop
        logger.info('Updated hop count to %s (re-register to apply)', new_hop)
