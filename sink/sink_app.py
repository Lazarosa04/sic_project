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

    def send_heartbeat(self):
        """
        Gera, assina e envia o Heartbeat para todos os Downlinks (multi-unicast).
        """
        self.heartbeat_counter += 1
        
        # 1. Assinar a mensagem
        hb_msg = sign_heartbeat(self.heartbeat_counter, self.private_key)
        
        print(f"[{self.name}][HB:{self.heartbeat_counter}] Enviando Heartbeat assinado para {len(self.downlinks)} Downlinks.")
        
        # 2. Multi-Unicast (Simulação)
        for downlink_nid in self.downlinks.keys():
            # No mundo real: Usaria BLE para enviar a mensagem através da conexão Bluetooth
            # Aqui simulamos o roteamento no módulo Node (o Sink não roteia para si próprio)
            
            # Estrutura da mensagem de rede (Simplificada)
            message_payload = {
                "source_nid": self.nid, # O Sink é a origem
                "destination_nid": downlink_nid, # O Heartbeat inunda, mas o Node receptor decide o que fazer
                "is_heartbeat": True,
                "heartbeat_data": hb_msg 
            }
            
            print(f"  -> [BLE] Enviado para {downlink_nid[:8]}...")
            
    async def heartbeat_loop(self):
        """
        Loop assíncrono para enviar o Heartbeat periodicamente.
        """
        while True:
            self.send_heartbeat()
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
