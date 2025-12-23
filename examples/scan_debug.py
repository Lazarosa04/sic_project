#!/usr/bin/env python3
"""examples/scan_debug.py

Debug scanner that prints raw advertisement fields (manufacturer/service data).

Usage:
  # scan on default adapter for 5s
  .venv/bin/python3 examples/scan_debug.py

  # scan on specific adapter for 10s
  .venv/bin/python3 examples/scan_debug.py hci0 10
"""

import asyncio
import sys

from bleak import BleakScanner


async def main(adapter: str | None = None, duration: float = 5.0):
    print(f"Debug scan started - adapter={adapter} duration={duration}s")

    def callback(device, adv):
        print("------------------------------")
        print(f"Device: {device.address} | Name: {device.name} | RSSI: {adv.rssi}")
        if adv.manufacturer_data:
            print("  Manufacturer Data:")
            for k, v in adv.manufacturer_data.items():
                print(f"    Company: 0x{k:04X} ({k}) -> {bytes(v).hex()}")
        if adv.service_data:
            print("  Service Data:")
            for k, v in adv.service_data.items():
                print(f"    {k} -> {v.hex()}" if isinstance(v, (bytes, bytearray)) else f"    {k} -> {v}")
        # Print raw adv object for deeper inspection
        print(f"  Raw adv: {adv}")

    scanner = BleakScanner(callback, adapter=adapter) if adapter else BleakScanner(callback)
    await scanner.start()
    await asyncio.sleep(duration)
    await scanner.stop()
    print("Debug scan finished")


if __name__ == '__main__':
    adapter = sys.argv[1] if len(sys.argv) > 1 else None
    duration = float(sys.argv[2]) if len(sys.argv) > 2 else 5.0
    asyncio.run(main(adapter=adapter, duration=duration))
