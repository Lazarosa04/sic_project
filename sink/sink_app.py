# sink/sink_app.py

import os
import sys
import asyncio
import time
from typing import Dict, Optional, Tuple
from cryptography.hazmat.primitives.asymmetric import ec

# --- CORREÇÃO DE AMBIENTE ---
# Necessário para encontrar módulos 'common' e 'support'
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

# Importar módulos essenciais
from node.iot_node import IoTNode # O Sink é um tipo especial de IoTNode
from common.heartbeat import sign_heartbeat, load_sink_keys, HEARTBEAT_PACING_SECONDS
from common.network_utils import SIC_SERVICE_UUID # Usado para identificação BLE
try:
    from common.ble_gatt_server_bluez import BlueZGattServer
except Exception:
    BlueZGattServer = None

class SinkApplication(IoTNode):
    """
    O Host Sink da rede. Responsável por iniciar o Heartbeat e gerir a raiz da árvore.
    """
    def __init__(self):
        # O Sink é um IoTNode especial, Hop Count é 0, NID é carregado via certificado
        super().__init__(name="Sink Host", is_sink=True)
        
        # Carrega as chaves privadas para assinar o Heartbeat
        self.private_key, self.public_key = load_sink_keys()
        if not self.private_key:
            raise Exception("Chave privada do Sink não carregada! A aplicação não pode iniciar.")
        
        self.heartbeat_counter = 0
        
        # Simulação de Downlinks iniciais para envio do Heartbeat
        # Estes seriam adicionados dinamicamente com novas conexões BLE
        self.downlinks = {
            "NODE_B_NID_SIMULADO": True, 
            "NODE_C_NID_SIMULADO": True
        }

        # GATT server (if available)
        self.ble_gatt_server = None
        # Try to instantiate a GATT server if available (for accepting central subscriptions)
        if BlueZGattServer is not None:
            try:
                adapter = os.environ.get('SIC_BLE_ADAPTER', 'hci0')

                def _on_gatt_write(data: bytes):
                    try:
                        import json
                        message = json.loads(data.decode('utf-8'))
                    except Exception:
                        message = {"raw": list(data)}
                    try:
                        self.process_incoming_message(message, source_link_nid='BLE_GATT')
                    except Exception:
                        print(f"[{self.name}] Erro ao processar mensagem GATT escrita")

                self.ble_gatt_server = BlueZGattServer(on_write=_on_gatt_write, adapter=adapter)
            except Exception as e:
                print(f"[{self.name}] Aviso: falha ao inicializar GATT server: {e}")
                self.ble_gatt_server = None
        
        print(f"\n[SINK] Aplicação Sink inicializada com NID: {self.nid}")
        print(f"[SINK] Pronto para enviar Heartbeats a cada {HEARTBEAT_PACING_SECONDS}s.")

    async def send_heartbeat(self):
        """
        Gera, assina e envia o Heartbeat para todos os Downlinks (multi-unicast) via BLE.
        """
        self.heartbeat_counter += 1
        
        # 1. Assinar a mensagem
        hb_msg = sign_heartbeat(self.heartbeat_counter, self.private_key)
        
        # 2. Verificar se há BLE Manager disponível
        if not self.ble_manager and not getattr(self, 'ble_gatt_server', None):
            print(f"[{self.name}][HB:{self.heartbeat_counter}] BLE Manager/GATT server não disponível. Modo simulação.")
            return
        
        # 3. Enviar via BLE para todos os Downlinks conectados
        # Ensure heartbeat payload is JSON-serializable (convert raw bytes to hex)
        import json
        serializable_hb = hb_msg.copy()
        if isinstance(serializable_hb.get('data'), (bytes, bytearray)):
            serializable_hb['data'] = serializable_hb['data'].hex()

        # Serializar para JSON
        data = json.dumps({
            "source_nid": self.nid,
            "destination_nid": "BROADCAST",
            "is_heartbeat": True,
            "heartbeat_data": serializable_hb
        }).encode('utf-8')

        # Preferir notificar via GATT server (centrals inscritos)
        if getattr(self, 'ble_gatt_server', None) is not None:
            try:
                await self.ble_gatt_server.notify_all(data)
                sub_count = getattr(self.ble_gatt_server, 'get_subscriber_count', lambda: 0)()
                if sub_count > 0:
                    print(f"[{self.name}][HB:{self.heartbeat_counter}] Enviado via GATT server (subscribers={sub_count}).")
                    return
            except Exception:
                pass


        downlink_count = self.ble_manager.get_downlink_count() if self.ble_manager else 0

        if downlink_count == 0:
            return
        
        # Estrutura da mensagem de rede
        message_payload = {
            "source_nid": self.nid,
            "destination_nid": "BROADCAST",
            "is_heartbeat": True,
            "heartbeat_data": serializable_hb
        }
        
        # Serializar para JSON
        import json
        data = json.dumps(message_payload).encode('utf-8')
        
        # Enviar via BLE
        success_count = await self.ble_manager.broadcast_to_downlinks(data)
        print(f"[{self.name}][HB:{self.heartbeat_counter}] Enviado para {success_count}/{downlink_count} Downlinks via BLE.")
            
    async def heartbeat_loop(self):
        """
        Loop assíncrono para enviar o Heartbeat periodicamente.
        """
        while True:
            await self.send_heartbeat()
            await asyncio.sleep(HEARTBEAT_PACING_SECONDS)

# --- Função principal para iniciar o Sink ---
async def main(adapter: str | None = None):
    # Se foi fornecido um adapter via CLI, exporta para a variável de ambiente
    if adapter:
        import os
        os.environ['SIC_BLE_ADAPTER'] = adapter
        print(f"[SINK] Usando adapter solicitado: {adapter}")

    sink_app = SinkApplication()
    # Se houver um advertiser, tenta iniciá-lo (suporta BlueZAdvertiser.start()
    # ou o fallback BLEAdvertiser.start_advertising()).
    advertiser = getattr(sink_app, 'ble_advertiser', None)
    started_advertiser = False

    try:
        if advertiser is not None:
            # BlueZAdvertiser exposes async `start()`; fallback exposes async `start_advertising()`
            if hasattr(advertiser, 'start') and asyncio.iscoroutinefunction(advertiser.start):
                await advertiser.start()
                started_advertiser = True
                print(f"[{sink_app.name}] BlueZAdvertiser iniciado (advertising registrado).")
            elif hasattr(advertiser, 'start_advertising') and asyncio.iscoroutinefunction(advertiser.start_advertising):
                await advertiser.start_advertising()
                started_advertiser = True
                print(f"[{sink_app.name}] BLEAdvertiser fallback iniciado (modo log).")

        # Start GATT server if present
        gatt = getattr(sink_app, 'ble_gatt_server', None)
        started_gatt = False
        if gatt is not None and hasattr(gatt, 'start') and asyncio.iscoroutinefunction(gatt.start):
            try:
                await gatt.start()
                started_gatt = True
                print(f"[{sink_app.name}] GATT server iniciado (registrado).")
            except Exception as e:
                print(f"[{sink_app.name}] Aviso: falha ao iniciar GATT server: {e}")

        # Executa o loop do Heartbeat (em um ambiente real, esta seria a thread principal)
        await sink_app.heartbeat_loop()

    finally:
        # Tenta parar o advertiser corretamente no encerramento
        if started_advertiser and advertiser is not None:
            try:
                if hasattr(advertiser, 'stop') and asyncio.iscoroutinefunction(advertiser.stop):
                    await advertiser.stop()
                elif hasattr(advertiser, 'stop_advertising') and asyncio.iscoroutinefunction(advertiser.stop_advertising):
                    await advertiser.stop_advertising()
                print(f"[{sink_app.name}] Advertiser parado.")
            except Exception as e:
                print(f"[{sink_app.name}] Aviso: falha ao parar advertiser: {e}")
        # Parar GATT server se existir
        gatt = getattr(sink_app, 'ble_gatt_server', None)
        if gatt is not None and started_gatt:
            try:
                await gatt.stop()
                print(f"[{sink_app.name}] GATT server parado.")
            except Exception as e:
                print(f"[{sink_app.name}] Aviso: falha ao parar GATT server: {e}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Run Sink application (starts advertiser + heartbeat)')
    parser.add_argument('--adapter', default=None, help='HCI adapter to use for advertising (e.g. hci0, hci1)')
    args = parser.parse_args()

    try:
        asyncio.run(main(adapter=args.adapter))
    except KeyboardInterrupt:
        print("\n[SINK] Aplicação encerrada pelo usuário.")
