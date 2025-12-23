#!/usr/bin/env python3
"""Run a Node in runtime mode: scan -> connect -> keep connection.

Usage:
  python3 examples/run_node_runtime.py --adapter hci0 --scan 5

This script creates an `IoTNode`, performs BLE scanning using the
project `BLEConnectionManager`, chooses the best uplink, attempts to
connect and then keeps the process running to receive notifications.
"""

import argparse
import asyncio
import os
import sys

# Ensure repo root is on path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

from node.iot_node import IoTNode


async def main(adapter: str, scan_duration: float):
    node = IoTNode(name="Node A", is_sink=False)

    if not node.nid:
        print("[ERROR] Node identity not loaded. Run support/ca_manager.py to generate certs.")
        return

    # Perform scanning for uplinks
    print(f"[{node.name}] Scanning for uplinks (adapter={adapter}) for {scan_duration}s...")
    try:
        candidates = await node.find_uplink_candidates(scan_duration=scan_duration, adapter=adapter)
    except Exception as e:
        print(f"[ERROR] Scanning failed: {e}")
        return

    if not candidates:
        print(f"[{node.name}] No uplink candidates found.")
        return

    print(f"[{node.name}] Candidates found:")
    for nid, hop in candidates.items():
        print(f"  - {nid} (hop={hop})")

    selected = node.choose_uplink(candidates)
    if not selected:
        print(f"[{node.name}] No uplink selected.")
        return

    print(f"[{node.name}] Attempting to connect to uplink {selected[:8]}...")
    try:
        success = await node.connect_to_uplink(selected)
    except Exception as e:
        print(f"[ERROR] Connection attempt failed: {e}")
        success = False

    if not success:
        print(f"[{node.name}] Failed to connect to {selected[:8]}...")
        return

    print(f"[{node.name}] Connected. Entering main loop — press Ctrl+C to exit.")

    try:
        while True:
            await asyncio.sleep(5)
            node.print_status()
    except KeyboardInterrupt:
        print("\n[INFO] Interrupt received — disconnecting...")
        if node.ble_manager:
            await node.ble_manager.disconnect_all()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run Node runtime: scan -> connect -> keep connection')
    parser.add_argument('--adapter', default=None, help='HCI adapter to use (e.g. hci0)')
    parser.add_argument('--scan', type=float, default=5.0, help='Scan duration in seconds')
    args = parser.parse_args()

    try:
        asyncio.run(main(args.adapter, args.scan))
    except Exception as e:
        print(f"[FATAL] {e}")
