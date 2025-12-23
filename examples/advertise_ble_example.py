#!/usr/bin/env python3
"""Example to test BlueZ advertising via `BlueZAdvertiser`.

Run this on Linux with BlueZ and an active BLE adapter (hci0).
"""

import argparse
import asyncio
import logging
import sys

sys.path.append(__file__.rpartition('/')[0] + '/..')

from common.ble_advertiser_bluez import BlueZAdvertiser


async def main(adapter: str, duration: int):
    logging.basicConfig(level=logging.INFO)
    nid = "00000000-0000-0000-0000-000000000001"
    adv = BlueZAdvertiser(nid=nid, hop_count=1, adapter=adapter)

    try:
        await adv.start()
        print(f"Advertising started on {adapter}. Sleeping {duration}s...")
        await asyncio.sleep(duration)
    except Exception as e:
        print(f"Error while advertising: {e}")
    finally:
        await adv.stop()
        print("Advertising stopped.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Example BlueZ advertiser (accepts --adapter)')
    parser.add_argument('--adapter', default='hci0', help='HCI adapter to use (e.g. hci0, hci1)')
    parser.add_argument('--duration', type=int, default=10, help='Advertising duration in seconds')
    args = parser.parse_args()
    asyncio.run(main(adapter=args.adapter, duration=args.duration))
