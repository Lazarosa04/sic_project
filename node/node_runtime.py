# node/node_runtime.py
"""
Node Runtime - Interface interativa do IoT Node.

Este módulo fornece uma CLI completa para o IoT Node com todos os controlos
de rede especificados na Secção 4 e a interface de utilizador da Secção 6.

Comandos disponíveis:
  help                  - Mostra comandos disponíveis
  scan [secs]           - Procura dispositivos vizinhos e mostra hop count
  list                  - Lista resultados do último scan
  connect <idx|nid>     - Conecta a um dispositivo como uplink
  disconnect            - Desconecta do uplink atual
  stop_hb <nid>         - Para de enviar heartbeats para um downlink
  start_hb <nid>        - Retoma envio de heartbeats
  blocked_hb            - Lista downlinks com heartbeat bloqueado
  send_inbox <text>     - Envia mensagem Inbox para o Sink (E2E protegido)
  status                - Mostra estado completo do Node
  quit/exit             - Encerra o Node

Uso:
    python node/node_runtime.py [--name "Node A"] [--adapter hci0]
"""

import asyncio
import os
import sys
import json
from typing import Dict, Optional

# Ensure repo root on path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

from node.iot_node import IoTNode, DISCONNECTED_HOP_COUNT
from common.heartbeat import HEARTBEAT_PACING_SECONDS
from common.network_utils import (
    BLE_FRAG_SINGLE,
    BLE_FRAG_START,
    BLE_FRAG_MIDDLE,
    BLE_FRAG_END,
)

try:
    from common.ble_gatt_server_bluez import BlueZGattServer
except Exception:
    BlueZGattServer = None


def print_banner(node_name: str):
    """Imprime banner do Node Runtime."""
    print("\n" + "=" * 60)
    print(r"""
  _   _  ____  _____  ______   _____ _______ 
 | \ | |/ __ \|  __ \|  ____| |_   _|__   __|
 |  \| | |  | | |  | | |__      | |    | |   
 | . ` | |  | | |  | |  __|     | |    | |   
 | |\  | |__| | |__| | |____   _| |_   | |   
 |_| \_|\____/|_____/|______| |_____|  |_|   
                                              
    """)
    print("=" * 60)
    print(f" SIC Project - {node_name} ")
    print(" IoT Node Interactive Runtime ")
    print("=" * 60 + "\n")


class NodeRuntime:
    """
    Runtime interativo para IoT Node com todos os controlos de rede.
    
    Implementa:
    - Secção 4: Network Controls
    - Secção 6: User Interface
    """
    
    def __init__(self, node_name: str = "Node A", adapter: Optional[str] = None):
        self.node_name = node_name
        self.adapter = adapter or os.environ.get('SIC_BLE_ADAPTER', 'hci0')
        
        # Criar IoT Node
        self.node = IoTNode(name=node_name, is_sink=False, adapter=self.adapter)
        
        # GATT server para aceitar conexões de downlinks
        self.gatt_server = None
        if BlueZGattServer is not None:
            try:
                # RX fragmentation buffer for incoming writes
                self._rx_frag_buf: bytearray = bytearray()
                self._rx_in_progress: bool = False

                def _on_gatt_write(data: bytes):
                    try:
                        if not data:
                            return
                        flag = data[0]
                        payload = data[1:]
                        if flag == BLE_FRAG_SINGLE:
                            message = json.loads(payload.decode('utf-8'))
                        elif flag == BLE_FRAG_START:
                            self._rx_frag_buf = bytearray(payload)
                            self._rx_in_progress = True
                            return
                        elif flag == BLE_FRAG_MIDDLE and self._rx_in_progress:
                            self._rx_frag_buf.extend(payload)
                            return
                        elif flag == BLE_FRAG_END and self._rx_in_progress:
                            self._rx_frag_buf.extend(payload)
                            assembled = bytes(self._rx_frag_buf)
                            self._rx_frag_buf = bytearray()
                            self._rx_in_progress = False
                            message = json.loads(assembled.decode('utf-8'))
                        else:
                            # Fallback: parse as plain JSON for backward compatibility
                            message = json.loads(data.decode('utf-8'))
                        try:
                            source_nid = message.get("source_nid", "BLE_GATT")
                            self.node.process_incoming_message(message, source_link_nid=source_nid)
                        except Exception as e:
                            print(f"[{self.node_name}] Erro GATT: {e}")
                    except Exception:
                        print(f"[{self.node_name}] Erro ao descodificar escrita GATT (fragmentos)")

                self.gatt_server = BlueZGattServer(on_write=_on_gatt_write, adapter=self.adapter)
                self.node.ble_gatt_server = self.gatt_server
            except Exception as e:
                print(f"[{self.node_name}] Aviso: GATT server não disponível: {e}")
        
        # Cache de resultados de scan
        self.scan_results: Dict[str, int] = {}
        
        # Debug mode
        self.debug_mode = False

    async def start(self):
        """Inicia o Node Runtime."""
        print_banner(self.node_name)
        
        # Iniciar advertiser
        if self.node.ble_advertiser:
            try:
                if hasattr(self.node.ble_advertiser, 'start'):
                    await self.node.ble_advertiser.start()
                    print(f"Advertiser iniciado (hop={self.node.hop_count})")
            except Exception as e:
                print(f"Advertiser não iniciado: {e}")
        
        # Iniciar GATT server
        if self.gatt_server:
            try:
                await self.gatt_server.start()
                print(f"GATT server iniciado")
            except Exception as e:
                print(f"GATT server não iniciado: {e}")
        
        print(f"\nNode NID: {self.node.nid}")
        print(f"Hop Count: {self.node.hop_count}")
        print(f"Uplink: {'Nenhum' if not self.node.uplink_nid else self.node.uplink_nid[:8] + '...'}\n")

    async def stop(self):
        """Para o Node Runtime."""
        if self.gatt_server:
            try:
                await self.gatt_server.stop()
            except Exception:
                pass
        
        if self.node.ble_advertiser:
            try:
                if hasattr(self.node.ble_advertiser, 'stop'):
                    await self.node.ble_advertiser.stop()
            except Exception:
                pass

    def print_status(self):
        """Imprime estado completo do Node (Secção 6)."""
        n = self.node
        print("\n" + "=" * 60)
        print(f" {self.node_name} STATUS ".center(60, "="))
        print("=" * 60)
        print(f"| NID: {n.nid}")
        print(f"| Hop Count: {n.hop_count}")
        
        # Uplink status
        if n.uplink_nid:
            print(f"| Uplink: OK {n.uplink_nid[:8]}...")
            session = n.link_sessions.get(n.uplink_nid)
            if session:
                print(f"|   └─ Sessão de link estabelecida")
        else:
            print(f"| Uplink: Desconectado")
        
        # Downlinks
        print(f"| Downlinks ({len(n.downlinks)}):")
        for nid in n.downlinks.keys():
            blocked = "BLOQUEADO" if nid in n.blocked_heartbeat_downlinks else "OK"
            print(f"|   {blocked} {nid[:8]}...")
        
        # Forwarding table
        print(f"| Forwarding Table ({len(n.forwarding_table)} entradas):")
        for dest, hop in n.forwarding_table.items():
            print(f"|   {dest[:8]}... via {hop[:8]}...")
        
        # Estatísticas
        print(f"| Lost Heartbeats: {n.lost_heartbeats}")
        print(f"| Messages Routed Uplink: {n.messages_routed_uplink}")
        
        # E2E Sessions
        print(f"| E2E Sessions: {len(n.e2e_sessions)}")
        
        print("=" * 60)

    async def run_command(self, cmdline: str) -> bool:
        """
        Executa um comando.
        
        Returns:
            False se deve sair, True caso contrário
        """
        if not cmdline:
            return True

        parts = cmdline.split(None, 2)
        cmd = parts[0].lower()

        # ==================== QUIT ====================
        if cmd in ('quit', 'exit'):
            return False

        # ==================== HELP ====================
        if cmd == 'help':
            print("""
╔═══════════════════════════════════════════════════════════════╗
║                    COMANDOS DISPONÍVEIS                        ║
╠═══════════════════════════════════════════════════════════════╣
║ NETWORK CONTROLS (Secção 4):                                   ║
║   scan [secs]         - Procura dispositivos vizinhos          ║
║   list                - Lista resultados do último scan        ║
║   connect <idx|nid>   - Conecta a um dispositivo como uplink   ║
║   disconnect          - Desconecta do uplink atual             ║
║   stop_hb <nid>       - Bloqueia heartbeat para downlink       ║
║   start_hb <nid>      - Desbloqueia heartbeat                  ║
║   blocked_hb          - Lista downlinks bloqueados             ║
╠═══════════════════════════════════════════════════════════════╣
║ SERVICES (Secção 5.7):                                         ║
║   send_inbox <text>   - Envia mensagem Inbox para o Sink       ║
╠═══════════════════════════════════════════════════════════════╣
║ USER INTERFACE (Secção 6):                                     ║
║   status              - Mostra estado completo do Node         ║
║   ft                  - Mostra forwarding table                ║
║   debug [on|off]      - Ativa/desativa debug de mensagens      ║
╠═══════════════════════════════════════════════════════════════╣
║ GERAL:                                                         ║
║   help                - Mostra esta ajuda                      ║
║   quit/exit           - Encerra o Node                         ║
╚═══════════════════════════════════════════════════════════════╝
            """)
            return True

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
                results = await self.node.find_uplink_candidates(scan_duration=secs)
                self.scan_results = results
                if not results:
                    print('Nenhum dispositivo encontrado.')
                else:
                    print(f"\n{len(results)} dispositivo(s) encontrado(s):")
                    print("-" * 50)
                    for i, (nid, hop) in enumerate(results.items()):
                        hop_str = f"hop={hop}" if hop >= 0 else "hop=N/A (desconectado)"
                        marker = "(sink)" if hop == 0 else ""
                        prefix = f"{marker} " if marker else ""
                        print(f"[{i}] {prefix}{nid} ({hop_str})")
                    print("-" * 50)
            except Exception as e:
                print(f"Scan falhou: {e}")
            return True

        # ==================== LIST ====================
        if cmd == 'list':
            if not self.scan_results:
                print('Sem resultados de scan. Execute "scan" primeiro.')
            else:
                print(f"\nÚltimos resultados ({len(self.scan_results)} dispositivos):")
                print("-" * 50)
                for i, (nid, hop) in enumerate(self.scan_results.items()):
                    hop_str = f"hop={hop}" if hop >= 0 else "hop=N/A"
                    print(f"[{i}] {nid} ({hop_str})")
                print("-" * 50)
            return True

        # ==================== CONNECT (Sec. 4) ====================
        if cmd == 'connect':
            if len(parts) < 2:
                print('Uso: connect <idx|nid>')
                return True
            
            if self.node.uplink_nid:
                print(f'Já conectado a {self.node.uplink_nid[:8]}...')
                print('   Use "disconnect" primeiro.')
                return True
            
            target = parts[1]
            target_nid = None
            if target.isdigit():
                idx = int(target)
                try:
                    target_nid = list(self.scan_results.keys())[idx]
                except Exception:
                    print('Índice fora de alcance.')
                    return True
            else:
                target_nid = target

            print(f'Conectando a {target_nid[:8]}...')
            try:
                ok = await self.node.connect_to_uplink(target_nid)
                if ok:
                    print(f'Conectado! Novo hop count: {self.node.hop_count}')
                else:
                    print(f'Falha ao conectar.')
            except Exception as e:
                print(f'Erro: {e}')
            return True

        # ==================== DISCONNECT ====================
        if cmd == 'disconnect':
            if not self.node.uplink_nid:
                print('Não está conectado a nenhum uplink.')
                return True
            
            print(f'Desconectando de {self.node.uplink_nid[:8]}...')
            try:
                await self.node.disconnect_uplink()
                print(f'Desconectado. Hop count: {self.node.hop_count}')
            except Exception as e:
                print(f'Erro: {e}')
            return True

        # ==================== STOP_HB (Sec. 4) ====================
        if cmd == 'stop_hb':
            if len(parts) < 2:
                print('Uso: stop_hb <downlink_nid>')
                return True
            nid = parts[1]
            if nid.isdigit() and int(nid) < len(list(self.node.downlinks.keys())):
                nid = list(self.node.downlinks.keys())[int(nid)]
            self.node.block_heartbeat_to_downlink(nid)
            print(f'Heartbeat bloqueado para {nid[:8]}...')
            return True

        # ==================== START_HB (Sec. 4) ====================
        if cmd == 'start_hb':
            if len(parts) < 2:
                print('Uso: start_hb <downlink_nid>')
                return True
            nid = parts[1]
            if nid.isdigit() and int(nid) < len(list(self.node.downlinks.keys())):
                nid = list(self.node.downlinks.keys())[int(nid)]
            self.node.unblock_heartbeat_to_downlink(nid)
            print(f'Heartbeat desbloqueado para {nid[:8]}...')
            return True

        # ==================== BLOCKED_HB ====================
        if cmd == 'blocked_hb':
            blocked = self.node.list_blocked_heartbeats()
            if not blocked:
                print('Nenhum downlink bloqueado.')
            else:
                print(f'\nDownlinks bloqueados ({len(blocked)}):')
                for b in blocked:
                    print(f'  - {b}')
            return True

        # ==================== SEND_INBOX (Sec. 5.7) ====================
        if cmd == 'send_inbox':
            if len(parts) < 2:
                print('Uso: send_inbox <mensagem>')
                return True
            
            if not self.node.uplink_nid:
                print('Não conectado. Use "connect" primeiro.')
                return True
            
            text = ' '.join(parts[1:])
            print(f'Enviando Inbox: "{text}"')
            try:
                ok = await self.node.send_inbox_message(text)
                if ok:
                    print('Mensagem enviada com sucesso (E2E protegida)')
                else:
                    print('Falha ao enviar mensagem')
            except Exception as e:
                print(f'Erro: {e}')
            return True

        # ==================== STATUS (Sec. 6) ====================
        if cmd == 'status':
            self.print_status()
            return True

        # ==================== FORWARDING TABLE ====================
        if cmd == 'ft':
            ft = self.node.forwarding_table
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
            return True

        # ==================== DEBUG ====================
        if cmd == 'debug':
            if len(parts) > 1:
                arg = parts[1].lower()
                if arg in ('on', '1', 'true'):
                    self.debug_mode = True
                    self.node._debug_mode = True
                elif arg in ('off', '0', 'false'):
                    self.debug_mode = False
                    self.node._debug_mode = False
            else:
                self.debug_mode = not self.debug_mode
                self.node._debug_mode = self.debug_mode
            print(f'Debug mode: {"ON" if self.debug_mode else "OFF"}')
            return True

        print(f'Comando desconhecido: {cmd}. Digite "help" para ajuda.')
        return True


async def liveness_monitor(node: IoTNode):
    """Monitora liveness (heartbeats perdidos)."""
    while True:
        try:
            await node.check_liveness()
        except Exception:
            pass
        await asyncio.sleep(HEARTBEAT_PACING_SECONDS)


async def interactive_loop(runtime: NodeRuntime):
    """Loop interativo principal."""
    
    async def run_input(prompt: str) -> str:
        return await asyncio.to_thread(input, prompt)

    print("\nType 'help' for available commands.\n")

    while True:
        try:
            cmdline = (await run_input(f'{runtime.node_name}> ')).strip()
        except (EOFError, KeyboardInterrupt):
            print('\nExiting...')
            break

        should_continue = await runtime.run_command(cmdline)
        if not should_continue:
            break


async def main(node_name: str = "Node A", adapter: str = None):
    """Função principal do Node Runtime."""
    os.environ.setdefault('SIC_BLE_ADAPTER', adapter or 'hci0')
    
    runtime = NodeRuntime(node_name=node_name, adapter=adapter)
    await runtime.start()
    
    # Iniciar monitor de liveness em background
    liveness_task = asyncio.create_task(liveness_monitor(runtime.node))
    
    try:
        await interactive_loop(runtime)
    finally:
        liveness_task.cancel()
        try:
            await liveness_task
        except Exception:
            pass
        await runtime.stop()


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Node Runtime - Interactive CLI')
    parser.add_argument('--name', default='Node A', help='Node name (e.g., "Node A", "Node B")')
    parser.add_argument('--adapter', default=None, help='HCI adapter (e.g., hci0, hci1)')
    args = parser.parse_args()
    
    try:
        asyncio.run(main(node_name=args.name, adapter=args.adapter))
    except KeyboardInterrupt:
        print('\n\nNode encerrado pelo utilizador.')
