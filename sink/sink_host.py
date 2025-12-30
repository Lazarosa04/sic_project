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
        Processa mensagens recebidas. Neste projeto, apenas Heartbeats são relevantes.
        """
        source_nid = message.get("source_nid") 
        
        if message.get("is_heartbeat", False):
            print(f"[{self.name}] Heartbeat recebido de {source_nid[:8]}... (eco ou teste). Ignorado.")
            return
        
        # Ignorar mensagens de dados (DTLS Inbox) e outras
        if message.get("type") == "DTLS_INBOX":
            return
        
        # Para depuração, registar mensagens não-HB
        if source_nid:
            print(f"[{self.name}] Mensagem não suportada recebida de {source_nid[:8]}... (ignorada)")
    
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
                    sub_count = getattr(self, 'ble_gatt_server').get_subscriber_count() if getattr(self, 'ble_gatt_server', None) else 0
                    print(f"[{self.name}][HB:{heartbeat_counter}] GATT notify emitido (subscribers={sub_count}).")
                except Exception as e:
                    print(f"[{self.name}] Aviso: falha ao notificar via GATT server: {e}")

            if self.ble_manager and self.ble_manager.get_downlink_count() > 0:
                try:
                    success_count = await self.ble_manager.broadcast_to_downlinks(data)
                except Exception as e:
                    print(f"[{self.name}] Aviso: falha no broadcast BLE: {e}")
                    success_count = 0
                print(f"[{self.name}][HB:{heartbeat_counter}] Broadcast BLE: {success_count}/{self.ble_manager.get_downlink_count()} downlinks.")
                return success_count
            else:
                # No BLE-manager downlinks; rely on GATT notify above
                return 0
        success_count = await self.ble_manager.broadcast_to_downlinks(data)
        
        print(f"[{self.name}][HB:{heartbeat_counter}] Enviado para {success_count} Downlinks via BLE.")
        return success_count


if __name__ == "__main__":
    print("[SinkHost] Este módulo fornece a classe SinkHost e envio de Heartbeats. Use sink_app.py para executar.")
