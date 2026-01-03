# sync/sink_runtime.py
"""
Sink Runtime - Interface interativa do Sink Host.

Este módulo fornece uma CLI completa para o Sink com todos os controlos
de rede especificados na Secção 4 e a interface de utilizador da Secção 6.

Comandos disponíveis:
  help                  - Mostra comandos disponíveis
  scan [secs]           - Procura dispositivos vizinhos e mostra hop count
  list                  - Lista resultados do último scan
  connect <idx|nid>     - Conecta a um dispositivo como downlink
  stop_hb <nid>         - Para de enviar heartbeats para um downlink
  start_hb <nid>        - Retoma envio de heartbeats
  blocked_hb            - Lista downlinks com heartbeat bloqueado
  inbox                 - Mostra mensagens Inbox recebidas
  status                - Mostra estado completo do Sink
  quit/exit             - Encerra o Sink

Uso:
    python sync/sink_runtime.py [--adapter hci0]
"""

import asyncio
import os
import sys
from typing import Dict

# Ensure repo root on path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

from common.heartbeat import HEARTBEAT_PACING_SECONDS
from sync.sink_host import SinkHost


def print_banner():
    """Imprime banner do Sink Runtime."""
    print("\n" + "=" * 60)
    print(r"""
   _____ _____ _   _ _  __  _    _  ____   _____ _______ 
  / ____|_   _| \ | | |/ / | |  | |/ __ \ / ____|__   __|
 | (___   | | |  \| | ' /  | |__| | |  | | (___    | |   
  \___ \  | | | . ` |  <   |  __  | |  | |\___ \   | |   
  ____) |_| |_| |\  | . \  | |  | | |__| |____) |  | |   
 |_____/|_____|_| \_|_|\_\ |_|  |_|\____/|_____/   |_|   
                                                          
    """)
    print("=" * 60)
    print(" SIC Project - Secure IoT Ad-Hoc Network ")
    print(" Sink Host Interactive Runtime ")
    print("=" * 60 + "\n")


async def interactive_loop(sink: SinkHost):
    """Loop interativo principal do Sink."""
    scan_results: Dict[str, int] = {}

    async def run_input(prompt: str) -> str:
        return await asyncio.to_thread(input, prompt)

    print("\nType 'help' for available commands.\n")

    while True:
        try:
            cmdline = (await run_input('sink> ')).strip()
        except (EOFError, KeyboardInterrupt):
            print('\nExiting...')
            break

        if not cmdline:
            continue

        parts = cmdline.split(None, 2)
        cmd = parts[0].lower()

        # ==================== QUIT ====================
        if cmd in ('quit', 'exit'):
            break

        # ==================== HELP ====================
        if cmd == 'help':
            print("""
╔═══════════════════════════════════════════════════════════════╗
║                    COMANDOS DISPONÍVEIS                        ║
╠═══════════════════════════════════════════════════════════════╣
║ NETWORK CONTROLS (Secção 4):                                   ║
║   scan [secs]         - Procura dispositivos vizinhos          ║
║   list                - Lista resultados do último scan        ║
║   connect <idx|nid>   - Conecta a um dispositivo               ║
║   stop_hb <nid>       - Bloqueia heartbeat para downlink       ║
║   start_hb <nid>      - Desbloqueia heartbeat                  ║
║   blocked_hb          - Lista downlinks bloqueados             ║
╠═══════════════════════════════════════════════════════════════╣
║ USER INTERFACE (Secção 6):                                     ║
║   status              - Mostra estado completo do Sink         ║
║   inbox               - Mostra mensagens Inbox recebidas       ║
║   ft                  - Mostra forwarding table                ║
╠═══════════════════════════════════════════════════════════════╣
║ GERAL:                                                         ║
║   help                - Mostra esta ajuda                      ║
║   quit/exit           - Encerra o Sink                         ║
╚═══════════════════════════════════════════════════════════════╝
            """)
            continue

        # ==================== SCAN (Sec. 4) ====================
        if cmd == 'scan':
            secs = 5.0
            if len(parts) > 1:
                try:
                    secs = float(parts[1])
                except Exception:
                    print('Duração inválida; usando 5s')
            try:
                print(f"\nScanning por {secs}s...")
                results = await sink.scan_nearby(duration=secs)
                scan_results = results
                if not results:
                    print('Nenhum dispositivo encontrado.')
                else:
                    print(f"\n{len(results)} dispositivo(s) encontrado(s):")
                    print("-" * 50)
                    for i, (nid, hop) in enumerate(results.items()):
                        hop_str = f"hop={hop}" if hop >= 0 else "hop=N/A (desconectado)"
                        print(f"[{i}] {nid} ({hop_str})")
                    print("-" * 50)
            except Exception as e:
                print(f"Scan falhou: {e}")
            continue

        # ==================== LIST ====================
        if cmd == 'list':
            if not scan_results:
                print('Sem resultados de scan. Execute "scan" primeiro.')
            else:
                print(f"\nÚltimos resultados do scan ({len(scan_results)} dispositivos):")
                print("-" * 50)
                for i, (nid, hop) in enumerate(scan_results.items()):
                    hop_str = f"hop={hop}" if hop >= 0 else "hop=N/A"
                    print(f"[{i}] {nid} ({hop_str})")
                print("-" * 50)
            continue

        # ==================== CONNECT (Sec. 4) ====================
        if cmd == 'connect':
            if len(parts) < 2:
                print('Uso: connect <idx|nid>')
                continue
            target = parts[1]
            target_nid = None
            if target.isdigit():
                idx = int(target)
                try:
                    target_nid = list(scan_results.keys())[idx]
                except Exception:
                    print('Índice fora de alcance ou sem resultados de scan.')
                    continue
            else:
                target_nid = target

            print(f'Conectando a {target_nid[:8]}...')
            try:
                ok = await sink.connect_downlink(target_nid)
                if ok:
                    print(f'Conectado a {target_nid[:8]}...')
                else:
                    print(f'Falha ao conectar.')
            except Exception as e:
                print(f'Erro: {e}')
            continue

        # ==================== STOP_HB (Sec. 4) ====================
        if cmd == 'stop_hb':
            if len(parts) < 2:
                print('Uso: stop_hb <downlink_nid>')
                continue
            nid = parts[1]
            # Aceitar índice ou NID
            if nid.isdigit() and int(nid) < len(list(sink.downlinks.keys())):
                nid = list(sink.downlinks.keys())[int(nid)]
            sink.stop_heartbeat_to(nid)
            print(f'Heartbeat bloqueado para {nid[:8]}...')
            continue

        # ==================== START_HB (Sec. 4) ====================
        if cmd == 'start_hb':
            if len(parts) < 2:
                print('Uso: start_hb <downlink_nid>')
                continue
            nid = parts[1]
            if nid.isdigit() and int(nid) < len(list(sink.downlinks.keys())):
                nid = list(sink.downlinks.keys())[int(nid)]
            sink.start_heartbeat_to(nid)
            print(f'Heartbeat desbloqueado para {nid[:8]}...')
            continue

        # ==================== BLOCKED_HB ====================
        if cmd == 'blocked_hb':
            blocked = sorted(list(sink.blocked_heartbeat_downlinks))
            if not blocked:
                print('Nenhum downlink bloqueado.')
            else:
                print(f'\nDownlinks com heartbeat bloqueado ({len(blocked)}):')
                for b in blocked:
                    print(f'  - {b}')
            continue

        # ==================== INBOX (Sec. 6) ====================
        if cmd == 'inbox':
            msgs = sink.inbox_messages
            if not msgs:
                print('Inbox vazia.')
            else:
                print(f'\nInbox ({len(msgs)} mensagens):')
                print("-" * 60)
                for i, m in enumerate(msgs[-20:], 1):
                    frm = (m.get('from_nid') or 'UNKNOWN')[:8]
                    ts = m.get('timestamp', 'N/A')
                    msg = m.get('message', '')
                    cid = m.get('client_id', 'N/A')
                    print(f"[{i}] {ts} | De: {frm}... | client_id={cid}")
                    print(f"    {msg}")
                print("-" * 60)
            continue

        # ==================== STATUS (Sec. 6) ====================
        if cmd == 'status':
            sink.print_status()
            continue

        # ==================== FORWARDING TABLE ====================
        if cmd == 'ft':
            ft = sink.forwarding_table
            if not ft:
                print('Forwarding table vazia.')
            else:
                print(f'\nForwarding Table ({len(ft)} entradas):')
                print("-" * 60)
                print(f"{'Destination':<40} {'Next Hop':<20}")
                print("-" * 60)
                for dest, hop in ft.items():
                    print(f"{dest[:36]}... -> {hop[:16]}...")
                print("-" * 60)
            continue

        print(f'Comando desconhecido: {cmd}. Digite "help" para ajuda.')


async def heartbeat_loop(sink: SinkHost):
    """Loop de envio de heartbeats."""
    counter = 0
    while True:
        counter += 1
        try:
            await sink.send_heartbeat_ble(counter)
        except Exception as e:
            print(f"[Sink] Heartbeat error: {e}")
        await asyncio.sleep(HEARTBEAT_PACING_SECONDS)


async def main(adapter: str = None):
    """Função principal do Sink Runtime."""
    os.environ.setdefault('SIC_BLE_ADAPTER', adapter or 'hci0')
    
    print_banner()
    
    sink = SinkHost(name='Sink Host', adapter=adapter)

    # Iniciar advertiser
    advertiser = getattr(sink, 'ble_advertiser', None)
    started_advertiser = False
    try:
        if advertiser is not None:
            if hasattr(advertiser, 'start') and asyncio.iscoroutinefunction(advertiser.start):
                await advertiser.start()
                started_advertiser = True
                print(f"Advertiser iniciado (adapter={sink.adapter})")
            elif hasattr(advertiser, 'start_advertising') and asyncio.iscoroutinefunction(advertiser.start_advertising):
                await advertiser.start_advertising()
                started_advertiser = True
    except Exception as e:
        print(f"Advertiser não iniciado: {e}")

    # Iniciar GATT server
    gatt = getattr(sink, 'ble_gatt_server', None)
    started_gatt = False
    if gatt is not None and hasattr(gatt, 'start') and asyncio.iscoroutinefunction(gatt.start):
        try:
            await gatt.start()
            started_gatt = True
            print(f"GATT server iniciado")
        except Exception as e:
            print(f"GATT server não iniciado: {e}")

    print(f"\nSink NID: {sink.nid}")
    print(f"Heartbeat interval: {HEARTBEAT_PACING_SECONDS}s\n")

    # Iniciar loop de heartbeat em background
    hb_task = asyncio.create_task(heartbeat_loop(sink))
    
    try:
        await interactive_loop(sink)
    finally:
        hb_task.cancel()
        try:
            await hb_task
        except Exception:
            pass

        if started_gatt and gatt is not None:
            try:
                await gatt.stop()
            except Exception:
                pass

        if started_advertiser and advertiser is not None:
            try:
                if hasattr(advertiser, 'stop') and asyncio.iscoroutinefunction(advertiser.stop):
                    await advertiser.stop()
                elif hasattr(advertiser, 'stop_advertising') and asyncio.iscoroutinefunction(advertiser.stop_advertising):
                    await advertiser.stop_advertising()
            except Exception:
                pass


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Sink Runtime - Interactive CLI')
    parser.add_argument('--adapter', default=None, help='HCI adapter (e.g., hci0, hci1)')
    args = parser.parse_args()
    
    try:
        asyncio.run(main(adapter=args.adapter))
    except KeyboardInterrupt:
        print('\n\nSink encerrado pelo utilizador.')
