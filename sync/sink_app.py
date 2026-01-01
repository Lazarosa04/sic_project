# sync/sink_app.py
"""
Sink Application - Loop principal do Sink Host.

Este módulo estende o IoTNode para criar o Sink Host que:
- Gera Heartbeats assinados periodicamente (Sec. 3.2)
- Broadcasting para todos os downlinks via BLE
- Suporta GATT server para aceitar conexões de nodes

Uso:
    python sync/sink_app.py [--adapter hci0]
"""

import os
import sys
import asyncio
import json
from typing import Optional

# --- CORREÇÃO DE AMBIENTE ---
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

from node.iot_node import IoTNode
from common.heartbeat import sign_heartbeat, load_sink_keys, HEARTBEAT_PACING_SECONDS
from common.network_utils import SIC_SERVICE_UUID

try:
    from common.ble_gatt_server_bluez import BlueZGattServer
except Exception:
    BlueZGattServer = None


class SinkApplication(IoTNode):
    """
    O Host Sink da rede. Responsável por:
    - Iniciar o Heartbeat periodicamente (Sec. 3.2)
    - Gerir a raiz da árvore (hop count = 0)
    - Aceitar conexões de IoT Nodes
    """
    
    def __init__(self, adapter: Optional[str] = None):
        # Sink é um IoTNode especial com hop count = 0
        super().__init__(name="Sink Host", is_sink=True, adapter=adapter)
        
        # Carrega as chaves para assinar Heartbeats
        self.private_key, self.public_key = load_sink_keys()
        if not self.private_key:
            raise Exception("Chave privada do Sink não carregada! Execute ca_manager.py primeiro.")
        
        self.heartbeat_counter = 0
        
        # GATT server para aceitar conexões
        if BlueZGattServer is not None and self.ble_gatt_server is None:
            try:
                adapter_to_use = adapter or os.environ.get('SIC_BLE_ADAPTER', 'hci0')

                def _on_gatt_write(data: bytes):
                    try:
                        message = json.loads(data.decode('utf-8'))
                    except Exception:
                        message = {"raw": list(data)}
                    try:
                        self.process_incoming_message(message, source_link_nid='BLE_GATT')
                    except Exception:
                        print(f"[{self.name}] Erro ao processar mensagem GATT")

                self.ble_gatt_server = BlueZGattServer(on_write=_on_gatt_write, adapter=adapter_to_use)
            except Exception as e:
                print(f"[{self.name}] Aviso: falha ao inicializar GATT server: {e}")
        
        print(f"\n[SINK] Aplicação inicializada com NID: {self.nid}")
        print(f"[SINK] Heartbeat a cada {HEARTBEAT_PACING_SECONDS}s")

    async def send_heartbeat(self):
        """
        Gera, assina e envia o Heartbeat para todos os Downlinks (Sec. 3.2).
        
        O Heartbeat contém:
        - Counter monotónico
        - Timestamp
        - Assinatura ECDSA do Sink
        """
        self.heartbeat_counter += 1
        
        # Assinar a mensagem
        hb_msg = sign_heartbeat(self.heartbeat_counter, self.private_key)
        
        # Serializar
        serializable_hb = hb_msg.copy()
        if isinstance(serializable_hb.get('data'), (bytes, bytearray)):
            serializable_hb['data'] = serializable_hb['data'].hex()

        data = json.dumps({
            "source_nid": self.nid,
            "destination_nid": "BROADCAST",
            "is_heartbeat": True,
            "heartbeat_data": serializable_hb
        }).encode('utf-8')

        # Enviar via GATT notify
        if self.ble_gatt_server is not None:
            try:
                await self.ble_gatt_server.notify_all(data)
                sub_count = getattr(self.ble_gatt_server, 'get_subscriber_count', lambda: 0)()
                print(f"[{self.name}][HB:{self.heartbeat_counter}] GATT notify (subscribers={sub_count})")
            except Exception as e:
                print(f"[{self.name}] Erro GATT: {e}")

        # Enviar via BLE manager (downlinks conectados)
        if self.ble_manager:
            downlink_count = self.ble_manager.get_downlink_count()
            if downlink_count > 0:
                try:
                    success_count = await self.ble_manager.broadcast_to_downlinks(data)
                    print(f"[{self.name}][HB:{self.heartbeat_counter}] BLE: {success_count}/{downlink_count}")
                except Exception as e:
                    print(f"[{self.name}] Erro BLE: {e}")

    async def heartbeat_loop(self):
        """Loop principal de envio de Heartbeats."""
        while True:
            try:
                await self.send_heartbeat()
            except Exception as e:
                print(f"[{self.name}] Erro heartbeat: {e}")
            await asyncio.sleep(HEARTBEAT_PACING_SECONDS)


async def main(adapter: Optional[str] = None):
    """Função principal do Sink."""
    if adapter:
        os.environ['SIC_BLE_ADAPTER'] = adapter
        print(f"[SINK] Usando adapter: {adapter}")

    sink_app = SinkApplication(adapter=adapter)
    
    # Iniciar advertiser
    advertiser = getattr(sink_app, 'ble_advertiser', None)
    started_advertiser = False

    try:
        if advertiser is not None:
            if hasattr(advertiser, 'start') and asyncio.iscoroutinefunction(advertiser.start):
                await advertiser.start()
                started_advertiser = True
                print(f"[{sink_app.name}] Advertiser iniciado")
            elif hasattr(advertiser, 'start_advertising') and asyncio.iscoroutinefunction(advertiser.start_advertising):
                await advertiser.start_advertising()
                started_advertiser = True

        # Iniciar GATT server
        gatt = getattr(sink_app, 'ble_gatt_server', None)
        started_gatt = False
        if gatt is not None and hasattr(gatt, 'start') and asyncio.iscoroutinefunction(gatt.start):
            try:
                await gatt.start()
                started_gatt = True
                print(f"[{sink_app.name}] GATT server iniciado")
            except Exception as e:
                print(f"[{sink_app.name}] Erro GATT: {e}")

        # Loop de heartbeat
        await sink_app.heartbeat_loop()

    finally:
        # Cleanup
        if started_advertiser and advertiser is not None:
            try:
                if hasattr(advertiser, 'stop') and asyncio.iscoroutinefunction(advertiser.stop):
                    await advertiser.stop()
                elif hasattr(advertiser, 'stop_advertising') and asyncio.iscoroutinefunction(advertiser.stop_advertising):
                    await advertiser.stop_advertising()
            except Exception:
                pass
        
        gatt = getattr(sink_app, 'ble_gatt_server', None)
        if gatt is not None and started_gatt:
            try:
                await gatt.stop()
            except Exception:
                pass


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Sink Application - Heartbeat Loop')
    parser.add_argument('--adapter', default=None, help='HCI adapter (e.g., hci0)')
    args = parser.parse_args()

    try:
        asyncio.run(main(adapter=args.adapter))
    except KeyboardInterrupt:
        print("\n[SINK] Encerrado pelo utilizador.")
