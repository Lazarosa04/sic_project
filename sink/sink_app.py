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
        if not self.ble_manager:
            print(f"[{self.name}][HB:{self.heartbeat_counter}] BLE Manager não disponível. Modo simulação.")
            return
        
        # 3. Enviar via BLE para todos os Downlinks conectados
        downlink_count = self.ble_manager.get_downlink_count()
        
        if downlink_count == 0:
            print(f"[{self.name}][HB:{self.heartbeat_counter}] Nenhum Downlink conectado. Aguardando conexões...")
            return
        
        # Estrutura da mensagem de rede
        message_payload = {
            "source_nid": self.nid,
            "destination_nid": "BROADCAST",
            "is_heartbeat": True,
            "heartbeat_data": hb_msg 
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
async def main():
    sink_app = SinkApplication()
    
    # Executa o loop do Heartbeat (em um ambiente real, esta seria a thread principal)
    await sink_app.heartbeat_loop()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[SINK] Aplicação encerrada pelo usuário.")
