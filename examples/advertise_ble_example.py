#!/usr/bin/env python3
"""Example to test BlueZ advertising via `BlueZAdvertiser`.

Run this on Linux with BlueZ and an active BLE adapter (hci0).
"""

import asyncio
import logging
import sys

sys.path.append(__file__.rpartition('/')[0] + '/..')

from common.ble_advertiser_bluez import BlueZAdvertiser


async def main():
    logging.basicConfig(level=logging.INFO)
    nid = "00000000-0000-0000-0000-000000000001"
    adv = BlueZAdvertiser(nid=nid, hop_count=1)

    try:
        await adv.start()
        print("Advertising started. Sleeping 10s...")
        await asyncio.sleep(10)
    except Exception as e:
        print(f"Error while advertising: {e}")
    finally:
        await adv.stop()
        print("Advertising stopped.")


if __name__ == '__main__':
    asyncio.run(main())
