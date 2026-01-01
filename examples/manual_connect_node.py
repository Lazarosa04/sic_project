"""examples/manual_connect_node.py

Interactive example to run a node that can manually scan and connect to chosen peers.

Usage:
  ./venv/bin/python3 examples/manual_connect_node.py

Commands (type at prompt):
  help                - show commands
  scan [secs]         - scan for nearby nodes (default 5s)
  list                - list last scan results
  connect <idx|nid>   - connect to device by index (from list) or NID
  disconnect          - disconnect uplink
  status              - print node status
    send_inbox <text>    - send Inbox message to Sink (end-to-end protected)
    stop_hb <down_nid>   - stop forwarding heartbeats to a direct downlink
    start_hb <down_nid>  - resume forwarding heartbeats to a downlink
    blocked_hb           - list blocked downlinks
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

    print("\nManual Connect Node - Interactive CLI")
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
            print("Commands: help, scan [secs], list, connect <idx|nid>, disconnect, status, send_inbox <text>, stop_hb <nid>, start_hb <nid>, blocked_hb, quit")
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
                results = await node.find_uplink_candidates(scan_duration=secs, adapter=os.environ.get('SIC_BLE_ADAPTER'))
                scan_results = results
                if not results:
                    print('No devices found.')
                else:
                    for i, (nid, hop) in enumerate(results.items()):
                        print(f"[{i}] {nid} (hop={hop})")
            except Exception as e:
                print(f"Scan failed: {e}")
            continue

        if cmd == 'list':
            if not scan_results:
                print('No cached scan results. Run scan first.')
            else:
                for i, (nid, hop) in enumerate(scan_results.items()):
                    print(f"[{i}] {nid} (hop={hop})")
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
            if len(parts) < 2:
                print('Usage: send_inbox <text>')
                continue
            text = cmdline[len('send_inbox'):].strip()
            if not text:
                print('Usage: send_inbox <text>')
                continue
            try:
                ok = await node.send_inbox_message(text)
                print('Inbox sent.' if ok else 'Failed to send Inbox.')
            except Exception as e:
                print(f'Error sending Inbox: {e}')
            continue

        if cmd == 'stop_hb':
            if len(parts) < 2:
                print('Usage: stop_hb <downlink_nid>')
                continue
            nid = parts[1]
            node.block_heartbeat_to_downlink(nid)
            print(f'Blocked heartbeat forwarding to {nid[:8]}...')
            continue

        if cmd == 'start_hb':
            if len(parts) < 2:
                print('Usage: start_hb <downlink_nid>')
                continue
            nid = parts[1]
            node.unblock_heartbeat_to_downlink(nid)
            print(f'Unblocked heartbeat forwarding to {nid[:8]}...')
            continue

        if cmd == 'blocked_hb':
            blocked = node.list_blocked_heartbeats()
            if not blocked:
                print('No blocked downlinks.')
            else:
                print('Blocked downlinks:')
                for b in blocked:
                    print(f'  - {b}')
            continue

        print('Unknown command. Type help.')


async def main():
    node = IoTNode(name='Manual Node', is_sink=False)

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
            adapter = os.environ.get('SIC_BLE_ADAPTER', 'hci0')

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

            gatt = BlueZGattServer(on_write=_on_gatt_write, adapter=adapter)
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
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print('\nInterrupted by user.')
