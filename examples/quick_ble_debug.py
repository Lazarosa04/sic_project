#!/usr/bin/env python3
"""examples/quick_ble_debug.py

Debug BLE scanner that prints raw advertisement data for troubleshooting.

Run while another device is advertising (or while you run the project's advertiser
on another machine). This helps verify whether manufacturer data (company id
0xFFFF) and the NID+Hop payload arrive as expected.
"""

import os
import sys
import asyncio
import argparse

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

from bleak import BleakScanner


async def debug_scan(duration: float):
    print(f"Starting debug scan for {duration}s...\n")

    def cb(device, adv):
        try:
            print("-" * 60)
            # Read RSSI defensively: some bleak/backends attach it to device, others to adv
            rssi = getattr(device, 'rssi', None)
            if rssi is None:
                rssi = getattr(adv, 'rssi', None)

            name = getattr(device, 'name', None) or getattr(adv, 'local_name', None) or 'N/A'
            address = getattr(device, 'address', 'N/A')

            print(f"Device: {address} | Name: {name} | RSSI: {rssi if rssi is not None else 'N/A'}")

            # Try to print advertisement details; be defensive about attributes
            try:
                print(f"  AdvertisementData: {adv}")
            except Exception:
                # Fall back to explicit fields when __repr__ is not helpful
                try:
                    print(f"  .local_name: {getattr(adv, 'local_name', None)}")
                    print(f"  .manufacturer_data: {getattr(adv, 'manufacturer_data', None)}")
                    print(f"  .service_data: {getattr(adv, 'service_data', None)}")
                    print(f"  .service_uuids: {getattr(adv, 'service_uuids', None)}")
                except Exception:
                    pass
        except Exception as e:
            # Prevent unhandled exceptions inside the DBus message handler
            print(f"Error while processing advertisement callback: {e}")

    scanner = BleakScanner(cb)
    await scanner.start()
    await asyncio.sleep(duration)
    await scanner.stop()

    print("\nScan complete.")


def main():
    parser = argparse.ArgumentParser(description="Quick BLE debug scanner")
    parser.add_argument("-t", "--time", type=float, default=5.0, help="scan duration in seconds")
    args = parser.parse_args()

    try:
        asyncio.run(debug_scan(args.time))
    except KeyboardInterrupt:
        print("\nInterrupted")


if __name__ == '__main__':
    main()
