# sink/sink_host.py

import os
import sys
import json
import time
import asyncio
from typing import Optional, Dict, Any, List, Tuple
from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate 
from cryptography.hazmat.primitives.asymmetric import ec

# --- CORREÇÃO DE AMBIENTE ---
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))
# ------------------------------------------------------------------------------------

from common.heartbeat import sign_heartbeat 
from common.ble_manager import BLEConnectionManager, BLEAdvertiser
from common.link_security import (
    LinkSession,
    build_link_auth2,
    derive_link_key,
    wrap_link_secure,
    unwrap_link_secure,
    validate_auth1,
)
from common.e2e_security import (
    E2ESession,
    build_e2e_hello2,
    derive_e2e_key,
    unwrap_e2e_record,
    validate_hello1,
    wrap_e2e_record,
)
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
from common.network_utils import (
    BLE_FRAG_SINGLE,
    BLE_FRAG_START,
    BLE_FRAG_MIDDLE,
    BLE_FRAG_END,
)


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
        
        # Track direct children/downlinks for UI/controls
        self.downlinks: Dict[str, bool] = {}
        self.blocked_heartbeat_downlinks: set[str] = set()
        # Cache last scan results (NID -> hop)
        self.last_scan_results: Dict[str, int] = {}

        if self.nid:
            adapter = os.getenv('SIC_BLE_ADAPTER', 'hci0')
            self.ble_manager = BLEConnectionManager(
                device_nid=self.nid,
                on_message_received=self._on_ble_message_received,
                adapter=adapter,
            )
            # Sink tem Hop Count 0. Preferir BlueZAdvertiser quando possível.
            # Determina o adapter a usar a partir da variável de ambiente `SIC_BLE_ADAPTER`.
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
                    self._rx_frag_buf: bytearray = bytearray()
                    self._rx_in_progress: bool = False

                    def _on_gatt_write(data: bytes):
                        try:
                            if not data:
                                return
                            flag = data[0]
                            payload = data[1:]
                            if flag == BLE_FRAG_SINGLE:
                                import json
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
                                import json
                                message = json.loads(assembled.decode('utf-8'))
                            else:
                                # Fallback: plain JSON
                                import json
                                message = json.loads(data.decode('utf-8'))

                            try:
                                self.process_incoming_message(message, source_link_nid='BLE_GATT')
                            except Exception:
                                print(f"[{self.name}] Erro ao processar mensagem GATT escrita")
                        except Exception:
                            print(f"[{self.name}] Erro ao descodificar escrita GATT (fragmentos)")

                    self.ble_gatt_server = BlueZGattServer(on_write=_on_gatt_write, adapter=adapter)
                except Exception as e:
                    print(f"[{self.name}] Aviso: falha ao inicializar GATT server: {e}")
                    self.ble_gatt_server = None
            else:
                self.ble_gatt_server = None
        
        print(f"[{self.name}] Inicializado. NID: {self.nid}")

        # CA certificate (for peer certificate validation)
        self.ca_certificate: Optional[x509.Certificate] = self._load_ca_certificate()

        # Cache our own cert PEM (needed for LINK_AUTH2)
        self._our_cert_pem: Optional[bytes] = None
        try:
            if self.certificate is not None:
                from cryptography.hazmat.primitives import serialization
                self._our_cert_pem = self.certificate.public_bytes(serialization.Encoding.PEM)
        except Exception:
            self._our_cert_pem = None

        # Per-link sessions and forwarding table (learned from uplink traffic)
        self.link_sessions: Dict[str, LinkSession] = {}
        self.forwarding_table: Dict[str, str] = {}  # destination_nid -> next_hop_nid (direct neighbor)

        # End-to-end (DTLS-like) sessions for service clients
        self.e2e_sessions: Dict[Tuple[str, int], E2ESession] = {}

        # Inbox storage (for UI/demo)
        self.inbox_messages: List[Dict[str, Any]] = []

    async def _send_link_secure(self, neighbor_nid: str, inner_msg: Dict[str, Any]) -> bool:
        """Send LINK_SECURE (per-link MAC+seq) to a direct neighbor.

        Sink typically communicates to directly-connected nodes via GATT notify.
        Notifications are effectively broadcast to subscribed centrals; the MAC
        ensures only the intended neighbor can validate/accept.
        """
        if not self.nid:
            return False
        session = self.link_sessions.get(neighbor_nid)
        if not session:
            return False
        secure = wrap_link_secure(session, self.nid, inner_msg)
        data = json.dumps(secure).encode("utf-8")

        try:
            if getattr(self, 'ble_gatt_server', None) is not None:
                await self.ble_gatt_server.notify_all(data)
                return True
        except Exception:
            pass

        try:
            if self.ble_manager:
                await self.ble_manager.broadcast_to_downlinks(data)
                return True
        except Exception:
            pass

        return False

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

    def _load_ca_certificate(self) -> Optional[x509.Certificate]:
        """Load the CA certificate used to validate peer certs (section 5.4/5.5)."""
        try:
            ca_path = os.path.join(OUTPUT_DIR, "ca_certificate.pem")
            with open(ca_path, "rb") as f:
                return x509.load_pem_x509_certificate(f.read())
        except Exception:
            return None
    
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
        source_link_nid = message.get("link_sender_nid") or message.get("source_nid", "UNKNOWN")
        self.process_incoming_message(message, source_link_nid)

                    
    def process_incoming_message(self, message: Dict, source_link_nid: str):
        """
        Processa mensagens recebidas. Neste projeto, apenas Heartbeats são relevantes.
        """
        source_nid = message.get("source_nid")

        # --- Link mutual authentication (plain messages) ---
        if message.get("type") == "LINK_AUTH1":
            if not self.private_key or not self._our_cert_pem or not self.ca_certificate:
                return
            validated = validate_auth1(message, self.ca_certificate)
            if not validated:
                return
            peer_nid, _peer_pub, peer_eph_pub, peer_nonce = validated

            auth2, eph_priv_b, nonce_b = build_link_auth2(self._our_cert_pem, self.private_key, peer_eph_pub, peer_nonce)
            try:
                key = derive_link_key(eph_priv_b, peer_eph_pub, peer_nonce, nonce_b)
                self.link_sessions[peer_nid] = LinkSession(peer_nid=peer_nid, key=key)
            except Exception:
                return

            try:
                data = json.dumps({**auth2, "link_sender_nid": self.nid}).encode("utf-8")
                if getattr(self, 'ble_gatt_server', None) is not None:
                    asyncio.create_task(self.ble_gatt_server.notify_all(data))
                elif self.ble_manager:
                    asyncio.create_task(self.ble_manager.broadcast_to_downlinks(data))
            except Exception:
                pass
            return

        # --- Per-link authenticated wrapper ---
        if message.get("type") == "LINK_SECURE":
            link_sender = message.get("link_sender_nid")
            if not link_sender:
                return
            session = self.link_sessions.get(link_sender)
            if not session:
                return
            inner = unwrap_link_secure(session, message)
            if not inner:
                return
            message = inner
            source_link_nid = link_sender
            source_nid = message.get("source_nid")

        # Handle REGISTER messages from directly-connected nodes (for UI/forwarding).
        if message.get("type") == "REGISTER":
            if source_nid and source_nid != "UNKNOWN":
                self.downlinks[source_nid] = True
                # direct link
                if source_link_nid and source_link_nid != "UNKNOWN":
                    self.forwarding_table[source_nid] = source_link_nid
                print(f"[{self.name}] ✅ Downlink registado: {source_nid[:8]}...")
            return

        if message.get("is_heartbeat", False):
            if source_nid:
                print(f"[{self.name}] Heartbeat recebido de {source_nid[:8]}... (eco ou teste). Ignorado.")
            return

        if not source_nid or source_nid == "UNKNOWN":
            return

        # Learn forwarding: source_nid is reachable via source_link_nid (direct neighbor)
        if source_link_nid and source_link_nid != "UNKNOWN":
            self.forwarding_table[source_nid] = source_link_nid

        # --- End-to-end handshake (DTLS-like) ---
        if message.get("type") == "E2E_HELLO1":
            if not self.private_key or not self._our_cert_pem or not self.ca_certificate or not self.nid:
                return
            validated = validate_hello1(message, self.ca_certificate)
            if not validated:
                return
            peer_nid, client_id, peer_eph_pub, peer_nonce = validated

            hello2, eph_priv_b, nonce_b = build_e2e_hello2(self._our_cert_pem, self.private_key, int(client_id), peer_eph_pub, peer_nonce)
            try:
                key = derive_e2e_key(eph_priv_b, peer_eph_pub, peer_nonce, nonce_b, int(client_id))
                self.e2e_sessions[(peer_nid, int(client_id))] = E2ESession(peer_nid=peer_nid, client_id=int(client_id), key=key)
            except Exception:
                return

            out = {
                **hello2,
                "source_nid": self.nid,
                "destination_nid": peer_nid,
            }
            next_hop = self.forwarding_table.get(peer_nid) or source_link_nid
            if next_hop and next_hop != "UNKNOWN":
                try:
                    asyncio.create_task(self._send_link_secure(next_hop, out))
                except Exception:
                    pass
            return

        # --- End-to-end secure service traffic ---
        if message.get("type") == "E2E_SECURE":
            if not self.nid:
                return
            try:
                client_id = int(message.get("client_id"))
            except Exception:
                return
            session = self.e2e_sessions.get((source_nid, int(client_id)))
            if not session:
                return
            record = message.get("record")
            if not isinstance(record, dict):
                return
            inner = unwrap_e2e_record(session, record)
            if not inner:
                return

            if inner.get("service") == "inbox":
                entry = {
                    "from_nid": inner.get("from_nid") or source_nid,
                    "message": inner.get("message"),
                    "client_id": int(client_id),
                }
                self.inbox_messages.append(entry)
                print(f"[{self.name}] 📥 Inbox de {entry['from_nid'][:8]}...: {entry['message']}")

                resp_payload = {
                    "service": "inbox",
                    "ack": True,
                    "echo": entry["message"],
                }
                resp_record = wrap_e2e_record(session, resp_payload)
                resp_outer = {
                    "type": "E2E_SECURE",
                    "client_id": int(client_id),
                    "record": resp_record,
                    "source_nid": self.nid,
                    "destination_nid": source_nid,
                }

                next_hop = self.forwarding_table.get(source_nid) or source_link_nid
                if next_hop and next_hop != "UNKNOWN":
                    try:
                        asyncio.create_task(self._send_link_secure(next_hop, resp_outer))
                    except Exception:
                        pass
            return

        print(f"[{self.name}] Mensagem recebida de {source_nid[:8]}... tipo={message.get('type','(sem tipo)')}")
    
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

        # Preferred for controlability: multi-unicast via BLEManager downlink_clients
        downlink_count = self.ble_manager.get_downlink_count() if self.ble_manager else 0
        if downlink_count > 0 and self.ble_manager:
            success_count = 0
            for nid in self.ble_manager.list_downlinks():
                if nid in self.blocked_heartbeat_downlinks:
                    continue
                try:
                    if await self.ble_manager.send_to_downlink(nid, data):
                        success_count += 1
                except Exception:
                    pass
            print(f"[{self.name}][HB:{heartbeat_counter}] Multi-unicast BLE: {success_count}/{downlink_count} downlinks (blocked={len(self.blocked_heartbeat_downlinks)}).")
            return success_count

        # Fallback: GATT notify to all subscribers (cannot block per-node)
        if getattr(self, 'ble_gatt_server', None) is not None:
            try:
                await self.ble_gatt_server.notify_all(data)
                sub_count = self.ble_gatt_server.get_subscriber_count()
                print(f"[{self.name}][HB:{heartbeat_counter}] GATT notify emitido (subscribers={sub_count}).")
                return sub_count
            except Exception as e:
                print(f"[{self.name}] Aviso: falha ao notificar via GATT server: {e}")

        return 0

    async def scan_nearby(self, duration: float = 5.0, show_all: bool = False) -> Dict[str, int]:
        if not self.ble_manager:
            return {}
        results = await self.ble_manager.scan_for_uplinks(duration=duration, adapter=os.getenv('SIC_BLE_ADAPTER', 'hci0'), show_all=show_all)
        self.last_scan_results = dict(results)
        return results

    async def connect_downlink(self, target_nid: str) -> bool:
        """Sink-side control: connect to a nearby node as a downlink client (enables per-node heartbeat stop)."""
        if not self.ble_manager:
            return False
        # Ensure we have a discovered device entry with address
        if target_nid not in self.ble_manager.discovered_devices:
            try:
                await self.scan_nearby(duration=3.0)
            except Exception:
                pass
        if target_nid not in self.ble_manager.discovered_devices:
            return False
        device, _hop = self.ble_manager.discovered_devices[target_nid]
        ok = await self.ble_manager.accept_downlink_connection(device.address, target_nid)
        if ok:
            self.downlinks[target_nid] = True
        return ok

    def stop_heartbeat_to(self, downlink_nid: str) -> None:
        self.blocked_heartbeat_downlinks.add(downlink_nid)

    def start_heartbeat_to(self, downlink_nid: str) -> None:
        self.blocked_heartbeat_downlinks.discard(downlink_nid)


if __name__ == "__main__":
    print("[SinkHost] Este módulo fornece a classe SinkHost e envio de Heartbeats. Use sink_app.py para executar.")
