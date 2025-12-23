# sink/sink_host.py

import os
import sys
import json
import time
import asyncio
from typing import Optional, Dict, Any, List
from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate 
from cryptography.hazmat.primitives.asymmetric import ec

# --- CORREÇÃO DE AMBIENTE ---
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))
# ------------------------------------------------------------------------------------

from common.heartbeat import sign_heartbeat 
from common.dtls_service import unseal_inbox_message 
from common.ble_manager import BLEConnectionManager, BLEAdvertiser
# Prefer BlueZAdvertiser on Linux if available (BlueZ + dbus-next)
try:
    from common.ble_advertiser_bluez import BlueZAdvertiser
except Exception:
    BlueZAdvertiser = None
try:
    from common.ble_gatt_server_bluez import BlueZGattServer
except Exception:
    BlueZGattServer = None
from support.ca_manager import OUTPUT_DIR 
from node.iot_node import IoTNode 


# --- Constantes ---
SINK_NID_STR = "44c7f5ca-bda5-458c-bfad-7cd2075cf862"
HEARTBEAT_COUNTER = 0

# Variável global para armazenar o NID real do Node A (usado para debugging)
NODE_A_NID: Optional[str] = None
NODE_A_NAME = "Node A"


class SinkHost:
    """
    Representa o Sink Host. Responsável por iniciar a rede, 
    gerar Heartbeats e processar mensagens de serviço seguras.
    """
    def __init__(self, name: str = "Sink Host"):
        self.name = name
        self.is_sink = True
        self.nid: Optional[str] = None
        self.private_key: Optional[ec.EllipticCurvePrivateKey] = None
        self.certificate: Optional[x509.Certificate] = None
        self._load_identity()
        
        # Mapeamento NID -> Chave Pública (para verificar Heartbeats e DTLS)
        self.node_public_keys: Dict[str, ec.EllipticCurvePublicKey] = {}
        # O _load_all_node_certificates original é mantido para carregar chaves estáticas.
        self._load_all_node_certificates()
        
        # BLE Manager (Sink como central/peripheral)
        self.ble_manager: Optional[BLEConnectionManager] = None
        self.ble_advertiser: Optional[BLEAdvertiser] = None
        
        if self.nid:
            self.ble_manager = BLEConnectionManager(
                device_nid=self.nid,
                on_message_received=self._on_ble_message_received
            )
            # Sink tem Hop Count 0. Preferir BlueZAdvertiser quando possível.
            # Determina o adapter a usar a partir da variável de ambiente `SIC_BLE_ADAPTER`.
            adapter = os.getenv('SIC_BLE_ADAPTER', 'hci0')
            print(f"[{self.name}] Inicializando advertiser com adapter={adapter}")
            if BlueZAdvertiser is not None:
                try:
                    self.ble_advertiser = BlueZAdvertiser(self.nid, 0, adapter=adapter)
                except Exception as e:
                    print(f"[{self.name}] Aviso: Falha ao inicializar BlueZAdvertiser: {e}. Usando fallback BLEAdvertiser.")
                    self.ble_advertiser = BLEAdvertiser(self.nid, 0)
            else:
                self.ble_advertiser = BLEAdvertiser(self.nid, 0)
            # Tentar criar um GATT server para aceitar ligações/notifications
            if BlueZGattServer is not None:
                try:
                    # on_write callback: parse incoming JSON bytes and forward
                    def _on_gatt_write(data: bytes):
                        try:
                            import json
                            message = json.loads(data.decode('utf-8'))
                        except Exception:
                            # If not JSON, wrap raw bytes
                            message = {"raw": list(data)}
                        # call process_incoming_message in event loop
                        try:
                            self.process_incoming_message(message, source_link_nid='BLE_GATT')
                        except Exception:
                            print(f"[{self.name}] Erro ao processar mensagem GATT escrita")

                    self.ble_gatt_server = BlueZGattServer(on_write=_on_gatt_write, adapter=adapter)
                except Exception as e:
                    print(f"[{self.name}] Aviso: falha ao inicializar GATT server: {e}")
                    self.ble_gatt_server = None
            else:
                self.ble_gatt_server = None
        
        print(f"[{self.name}] Inicializado. NID: {self.nid}")

    def _load_identity(self):
        """ Carrega o certificado X.509 e a chave privada do Sink. """
        file_name = self.name.lower().replace(" ", "_")
        cert_path = os.path.join(OUTPUT_DIR, f"{file_name}_certificate.pem")
        key_path = os.path.join(OUTPUT_DIR, f"{file_name}_private.pem") 

        if not os.path.exists(cert_path) or not os.path.exists(key_path):
             print(f"[ERRO] Ficheiros de identidade do Sink não encontrados. Execute o ca_manager.py!")
             return

        with open(cert_path, "rb") as f:
            self.certificate = x509.load_pem_x509_certificate(f.read())
        with open(key_path, "rb") as f:
            self.private_key = load_pem_private_key(f.read(), password=None)
        
        try:
            nid_attribute = self.certificate.subject.get_attributes_for_oid(x509.NameOID.USER_ID)[-1]
            self.nid = nid_attribute.value
        except IndexError:
            self.nid = SINK_NID_STR

    def _load_all_node_certificates(self):
        """ Carrega todos os certificados de nó emitidos pela CA para extrair chaves públicas. """
        
        for filename in os.listdir(OUTPUT_DIR):
            # Filtra certificados de nó (não CA e não Sink)
            if filename.endswith("_certificate.pem") and "ca" not in filename and "sink" not in filename:
                node_name = filename.split("_")[0]
                cert_path = os.path.join(OUTPUT_DIR, filename)
                
                with open(cert_path, "rb") as f:
                    cert = x509.load_pem_x509_certificate(f.read())
                
                try:
                    nid_attribute = cert.subject.get_attributes_for_oid(x509.NameOID.USER_ID)[-1]
                    node_nid = nid_attribute.value
                    
                    self.node_public_keys[node_nid] = cert.public_key()
                    print(f"[{self.name}] Chave Pública Carregada para: {node_name} ({node_nid[:8]}...)")
                except IndexError:
                    print(f"[AVISO] Certificado de {node_name} não tem NID. Ignorado.")
    
    # --- NOVO MÉTODO PARA ADICIONAR CHAVES DINAMICAMENTE (CORREÇÃO) ---
    def add_node_key(self, node_name: str, node_nid: str):
        """ Carrega o certificado de um nó específico (Node A) e adiciona ao mapa de chaves públicas. """
        
        file_name = node_name.lower().replace(" ", "_")
        cert_path = os.path.join(OUTPUT_DIR, f"{file_name}_certificate.pem")
        
        if os.path.exists(cert_path):
            with open(cert_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
            
            self.node_public_keys[node_nid] = cert.public_key()
            print(f"[{self.name}] CHAVE ADICIONADA: {node_name} ({node_nid[:8]}...)")
        else:
            print(f"[{self.name}] AVISO: Certificado de {node_name} ausente para adição manual.")
    
    def _on_ble_message_received(self, message: Dict, sender_handle: int):
        """Callback para mensagens BLE recebidas pelo Sink"""
        print(f"[{self.name}] Mensagem BLE recebida (handle: {sender_handle})")
        source_link_nid = message.get("source_nid", "UNKNOWN")
        self.process_incoming_message(message, source_link_nid)

                    
    def process_incoming_message(self, message: Dict, source_link_nid: str):
        """
        Processa mensagens recebidas. Se for uma mensagem de Inbox, desempacota-a.
        """
        source_nid = message.get("source_nid") 
        
        if message.get("type") == "DTLS_INBOX":
            secure_packet = message.get("secure_packet")
            
            # 1. Obter a chave pública do Nó 
            sender_public_key = self.node_public_keys.get(source_nid)
            
            if not sender_public_key:
                print(f"[{self.name}] ERRO: Não é possível processar Inbox. Chave de {source_nid[:8]}... não encontrada.")
                return

            # 2. Desempacotar e Verificar (Validação de Assinatura End-to-End)
            payload = unseal_inbox_message(secure_packet, sender_public_key)
            
            if payload:
                print("\n" + "*"*60)
                print(f"*** {self.name}: MENSAGEM INBOX SEGURO RECEBIDA ***".center(60))
                print(f"  De Nó: {source_nid[:8]}...")
                print(f"  Conteúdo:")
                print(json.dumps(payload, indent=4))
                print("*"*60 + "\n")
                
            return
            
        elif message.get("is_heartbeat", False):
            print(f"[{self.name}] Recebeu o seu próprio Heartbeat (ou eco). Ignorado.")
            return
            
        else:
            print(f"[{self.name}] Mensagem de dados genérica recebida de {source_nid[:8]}... (Descartada)")
    
    async def send_heartbeat_ble(self, heartbeat_counter: int) -> int:
        """Envia Heartbeat para todos os Downlinks via BLE"""
        if not self.private_key:
            print(f"[{self.name}] ERRO: Chave privada não disponível para assinar Heartbeat.")
            return 0
        
        if not self.ble_manager:
            print(f"[{self.name}] ERRO: BLE Manager não disponível.")
            return 0
        
        # Assinar Heartbeat
        hb_msg = sign_heartbeat(heartbeat_counter, self.private_key)
        
        # Criar mensagem de rede
        message = {
            "source_nid": self.nid,
            "destination_nid": "BROADCAST",
            "is_heartbeat": True,
            "heartbeat_data": hb_msg
        }
        
        # Serializar e enviar via BLE para todos os Downlinks
        data = json.dumps(message).encode('utf-8')

        # Preferir notificar via GATT server se estiver disponível (clientes inscritos)
        if getattr(self, 'ble_gatt_server', None) is not None:
            try:
                await self.ble_gatt_server.notify_all(data)
                print(f"[{self.name}][HB:{heartbeat_counter}] Notificado via GATT server.")
                # We cannot know success_count easily here; report 1 as at least one subscriber
                return 1
            except Exception as e:
                print(f"[{self.name}] Aviso: falha ao notificar via GATT server: {e}")

        success_count = await self.ble_manager.broadcast_to_downlinks(data)
        
        print(f"[{self.name}][HB:{heartbeat_counter}] Enviado para {success_count} Downlinks via BLE.")
        return success_count


async def simulate_secure_service():
    """ Simula um Node A a enviar uma mensagem Inbox segura para o Sink usando BLE. """
    
    # 1. Inicializar Node A (precisa carregar a sua própria chave privada)
    node_a = IoTNode(name=NODE_A_NAME, is_sink=False)

    # 2. Inicializar Sink (Carrega a sua identidade)
    sink = SinkHost()
    
    # 3. Adicionar o NID real do Node A ao mapa de chaves públicas do Sink (CORREÇÃO CRÍTICA)
    if node_a.nid:
        sink.add_node_key(NODE_A_NAME, node_a.nid)
    
    if node_a.nid is None or sink.nid is None:
        print("[ERRO FATAL] Identidade de Nó/Sink ausente. Certifique-se que o ca_manager.py foi executado.")
        return

    print("\n[INFO] Modo de simulação (BLE real requer hardware). Pulando scanning/conexão BLE...")
    
    # Simulação da Conexão Uplink (para permitir o envio)
    node_a.uplink_nid = sink.nid 
    node_a.hop_count = 1 
    
    # Mensagem de teste
    test_payload = {
        "sensor_id": "temp_001",
        "value": 25.4,
        "units": "Celsius",
        "priority": "HIGH"
    }
    
    print("\n" + "#"*60)
    print(f"## TESTE DE SERVIÇO SEGURO DTLS INBOX ##".center(60))
    print("#"*60 + "\n")

    # A. Cenário de Sucesso (Assinatura Válida)
    inbox_message_valid = node_a.send_inbox_message(
        destination_nid=sink.nid,
        payload=test_payload
    )

    if inbox_message_valid:
        # Simular o Sink a receber a mensagem de A
        print("\n--- SIMULANDO: Sink a receber mensagem VÁLIDA do Node A ---")
        sink.process_incoming_message(inbox_message_valid, source_link_nid=node_a.nid)
        
    
    # B. Cenário de Falha (Simular um Ataque de Modificação)
    print("\n--- SIMULANDO: Ataque de MODIFICAÇÃO no Pacote ---")
    
    if inbox_message_valid:
        
        malicious_message = inbox_message_valid.copy()
        
        # ATACANTE: Altera o valor (viola a integridade)
        malicious_message['secure_packet']['inbox_data']['payload']['value'] = 999.9 
        
        print(f"[{node_a.name}] O Node A enviou o valor original: {test_payload['value']}")
        print(f"[{sink.name}] Recebido um pacote com valor MODIFICADO: 999.9")
        print("\n--- SIMULANDO: Sink a tentar desempacotar e verificar ataque ---")
        
        # O Sink tenta verificar a assinatura, que falhará devido à alteração
        sink.process_incoming_message(malicious_message, source_link_nid=node_a.nid)


if __name__ == "__main__":
    import asyncio
    asyncio.run(simulate_secure_service())
