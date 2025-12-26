"""examples/device_node.py

Interactive example to run a node that can manually scan and connect to chosen peers.

Usage:
  ./venv/bin/python3 examples/device_node.py

Commands (type at prompt):
  help                - show commands
  scan [secs]         - scan for nearby nodes (default 5s)
  list                - list last scan results
  connect <idx|nid>   - connect to device by index (from list) or NID
  disconnect          - disconnect uplink
  status              - print node status
  send_inbox <nid> <json_payload> - create and send a DTLS Inbox message to destination
  quit / exit         - exit and cleanup

This script uses `IoTNode` and the BLE manager already present in the project.
"""

import asyncio
import json
import os
import sys
from typing import Dict, Tuple, Optional

# Ensure project package path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

from node.iot_node import IoTNode
try:
    from common.ble_gatt_server_bluez import BlueZGattServer
except Exception:
    BlueZGattServer = None


async def interactive_loop(node: IoTNode):
    """Run a simple asyncio-friendly interactive prompt."""
    scan_results: Dict[str, int] = {}

    async def run_input(prompt: str) -> str:
        # run blocking input in a thread to avoid blocking the event loop
        return await asyncio.to_thread(input, prompt)

    print("\nDevice Node - Interactive CLI")
    print("Type 'help' for available commands.\n")

    while True:
        try:
            cmdline = (await run_input('> ')).strip()
        except (EOFError, KeyboardInterrupt):
            print('\nExiting...')
            break

        if not cmdline:
            continue

        parts = cmdline.split(None, 2)
        cmd = parts[0].lower()

        if cmd in ('quit', 'exit'):
            break

        if cmd == 'help':
            print("Commands: help, scan [secs], list, connect <idx|nid>, disconnect, status, send_inbox <nid> <json>, quit")
            continue

        if cmd == 'scan':
            secs = 5.0
            if len(parts) > 1:
                try:
                    secs = float(parts[1])
                except Exception:
                    print('Invalid duration; using 5s')
            print(f"Scanning for {secs}s...")
            try:
                # Run scan; the BLE manager caches discovered BLEDevice objects
                # Use the adapter chosen when starting the script (node.adapter)
                _ = await node.find_uplink_candidates(scan_duration=secs, adapter=node.adapter)

                # Use the BLE manager's discovered_devices to include addresses
                if not node.ble_manager or not node.ble_manager.discovered_devices:
                    scan_results = {}
                    print('No devices found.')
                else:
                    scan_results = {nid: (dev.address, hop) for nid, (dev, hop) in node.ble_manager.discovered_devices.items()}
                    for i, (nid, (addr, hop)) in enumerate(scan_results.items()):
                        print(f"[{i}] {nid} (hop={hop}) address={addr}")
            except Exception as e:
                print(f"Scan failed: {e}")
            continue

        if cmd == 'list':
            if not scan_results:
                print('No cached scan results. Run scan first.')
            else:
                for i, (nid, (addr, hop)) in enumerate(scan_results.items()):
                    print(f"[{i}] {nid} (hop={hop}) address={addr}")
            continue

        if cmd == 'connect':
            if len(parts) < 2:
                print('Usage: connect <idx|nid>')
                continue
            target = parts[1]
            target_nid = None
            # if numeric index
            if target.isdigit():
                idx = int(target)
                try:
                    target_nid = list(scan_results.keys())[idx]
                except Exception:
                    print('Index out of range or no scan results.')
                    continue
            else:
                # treat as NID
                target_nid = target

            print(f'Connecting to {target_nid[:8]}...')
            try:
                success = await node.connect_to_uplink(target_nid)
                if success:
                    print('Connected successfully.')
                else:
                    print('Connection failed.')
            except Exception as e:
                print(f'Error during connect: {e}')
            continue

        if cmd == 'disconnect':
            if node.ble_manager and node.ble_manager.is_connected_to_uplink():
                await node.disconnect_uplink()
                print('Disconnected uplink.')
            else:
                print('No uplink to disconnect.')
            continue

        if cmd == 'status':
            node.print_status()
            continue

        if cmd == 'send_inbox':
            if len(parts) < 3:
                print('Usage: send_inbox <destination_nid> <json_payload>')
                continue
            dest = parts[1]
            payload_raw = parts[2]
            try:
                payload = json.loads(payload_raw)
            except Exception as e:
                print(f'Invalid JSON payload: {e}')
                continue

            msg = node.send_inbox_message(destination_nid=dest, payload=payload)
            if not msg:
                print('Failed to build inbox message (are you connected?).')
                continue
            # send
            try:
                sent = await node.send_message_ble(msg)
                print('Sent.' if sent else 'Send failed.')
            except Exception as e:
                print(f'Error sending: {e}')
            continue

        print('Unknown command. Type help.')


async def main(name: str = 'Device Node', adapter: Optional[str] = None):
    # Allow passing a friendly identity name so the script can reuse
    # certificates already generated by `support/ca_manager.py` (e.g. "Node A", "Sink Host").
    # Determine adapter (explicit arg > env > default)
    adapter = adapter or os.environ.get('SIC_BLE_ADAPTER') or 'hci0'
    node = IoTNode(name=name, is_sink=False, adapter=adapter)

    # Start advertiser if present (BlueZAdvertiser.start() or fallback start_advertising())
    advertiser = getattr(node, 'ble_advertiser', None)
    started_advertiser = False
    if advertiser is not None:
        try:
            if hasattr(advertiser, 'start') and asyncio.iscoroutinefunction(advertiser.start):
                await advertiser.start()
                started_advertiser = True
                print('[ADV] Advertiser started (BlueZ).')
            elif hasattr(advertiser, 'start_advertising') and asyncio.iscoroutinefunction(advertiser.start_advertising):
                await advertiser.start_advertising()
                started_advertiser = True
                print('[ADV] Advertiser started (fallback).')
        except Exception as e:
            print(f'[ADV] Failed to start advertiser: {e}')

    # Try to start a GATT server if available (makes node connectable via GATT write/notify)
    gatt = None
    if BlueZGattServer is not None:
        try:
            gatt_adapter = adapter or os.environ.get('SIC_BLE_ADAPTER', 'hci0')

            def _on_gatt_write(data: bytes):
                try:
                    import json
                    message = json.loads(data.decode('utf-8'))
                except Exception:
                    message = {'raw': list(data)}
                try:
                    node.process_incoming_message(message, source_link_nid='BLE_GATT')
                except Exception:
                    print(f"[{node.name}] Error processing GATT write")

            gatt = BlueZGattServer(on_write=_on_gatt_write, adapter=gatt_adapter)
            await gatt.start()
            print('[GATT] GATT server started (BlueZ).')
        except Exception as e:
            print(f'[GATT] Failed to start GATT server: {e}')
            gatt = None

    try:
        await interactive_loop(node)
    finally:
        print('Cleaning up...')
        # stop advertiser
        if started_advertiser and advertiser is not None:
            try:
                if hasattr(advertiser, 'stop') and asyncio.iscoroutinefunction(advertiser.stop):
                    await advertiser.stop()
                elif hasattr(advertiser, 'stop_advertising') and asyncio.iscoroutinefunction(advertiser.stop_advertising):
                    await advertiser.stop_advertising()
                print('[ADV] Advertiser stopped.')
            except Exception as e:
                print(f'[ADV] Warning stopping advertiser: {e}')

        # stop gatt
        if gatt is not None:
            try:
                await gatt.stop()
                print('[GATT] GATT server stopped.')
            except Exception as e:
                print(f'[GATT] Warning stopping gatt: {e}')

        # disconnect BLE
        if node.ble_manager:
            try:
                await node.ble_manager.disconnect_all()
            except Exception as e:
                print(f'[BLE] Warning during disconnect_all: {e}')


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Run interactive Device Node')
    parser.add_argument('--name', default='Device Node', help='Friendly name matching generated identity files (e.g. "Node A", "Sink Host")')
    parser.add_argument('--adapter', default=None, help='HCI adapter to use (e.g. hci0, hci1)')
    args = parser.parse_args()

    try:
        asyncio.run(main(name=args.name, adapter=args.adapter))
    except KeyboardInterrupt:
        print('\nInterrupted by user.')
