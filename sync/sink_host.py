# sync/sink_host.py
"""
Sink Host - O gateway central da rede IoT ad-hoc.

Este módulo implementa o Sink Host que:
- Aceita conexões de múltiplos IoT Nodes
- Gera e assina Heartbeats periodicamente
- Processa mensagens do serviço Inbox (end-to-end)
- Mantém forwarding tables para routing downstream
- Suporta múltiplos Sinks (feature bónus)

Secções do enunciado implementadas:
- 3.1: Addressing e routing com forwarding tables
- 3.2: Network liveness com heartbeats assinados
- 4: Network controls (scan, connect, stop_hb)
- 5.1-5.3: Identificação com certificados X.509
- 5.4-5.6: Autenticação mútua e session keys
- 5.7: Serviço Inbox end-to-end (DTLS-like)
- 6: Interface de utilizador
"""

import os
import sys
import json
import time
import asyncio
from typing import Optional, Dict, Any, List, Tuple, Set
from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate 
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# --- CORREÇÃO DE AMBIENTE ---
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

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
from common.network_utils import (
    BLE_FRAG_SINGLE,
    BLE_FRAG_START,
    BLE_FRAG_MIDDLE,
    BLE_FRAG_END,
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


class SinkHost:
    """
    Representa o Sink Host - Gateway central da rede IoT ad-hoc.
    
    O Sink é responsável por:
    1. Iniciar a rede (hop count = 0)
    2. Gerar e assinar Heartbeats periodicamente
    3. Processar mensagens do serviço Inbox (end-to-end protegido)
    4. Manter forwarding tables para routing downstream
    5. Autenticar nodes via certificados X.509
    
    Feature Bónus - Múltiplos Sinks:
    - Cada Sink tem um NID único identificado no certificado
    - Nodes podem detetar mudança de Sink e invalidar sessões DTLS
    """
    
    def __init__(self, name: str = "Sink Host", adapter: Optional[str] = None):
        self.name = name
        self.is_sink = True
        self.hop_count = 0  # Sink sempre tem hop count 0
        self.nid: Optional[str] = None
        self.private_key: Optional[ec.EllipticCurvePrivateKey] = None
        self.certificate: Optional[x509.Certificate] = None
        self._load_identity()
        
        # Adapter BLE (pode ser especificado ou via env var)
        self.adapter = adapter or os.environ.get('SIC_BLE_ADAPTER', 'hci0')
        
        # Mapeamento NID -> Chave Pública (para verificar certificados dos nodes)
        self.node_public_keys: Dict[str, ec.EllipticCurvePublicKey] = {}
        self._load_all_node_certificates()
        
        # BLE Manager (Sink como central/peripheral)
        self.ble_manager: Optional[BLEConnectionManager] = None
        self.ble_advertiser: Optional[BLEAdvertiser] = None
        self.ble_gatt_server = None
        
        # Track direct children/downlinks
        self.downlinks: Dict[str, bool] = {}
        self.blocked_heartbeat_downlinks: Set[str] = set()
        
        # Cache last scan results (NID -> hop)
        self.last_scan_results: Dict[str, int] = {}

        if self.nid:
            self.ble_manager = BLEConnectionManager(
                device_nid=self.nid,
                on_message_received=self._on_ble_message_received,
                adapter=self.adapter,
            )
            
            # Sink tem Hop Count 0 - Preferir BlueZAdvertiser
            print(f"[{self.name}] Inicializando advertiser com adapter={self.adapter}")
            if BlueZAdvertiser is not None:
                try:
                    self.ble_advertiser = BlueZAdvertiser(self.nid, 0, adapter=self.adapter)
                except Exception as e:
                    print(f"[{self.name}] Aviso: Falha ao inicializar BlueZAdvertiser: {e}")
                    self.ble_advertiser = BLEAdvertiser(self.nid, 0)
            else:
                self.ble_advertiser = BLEAdvertiser(self.nid, 0)
            
            # GATT server para aceitar ligações
            if BlueZGattServer is not None:
                try:
                    # RX fragmentation buffer for writes
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
                                # Fallback: treat as plain JSON for backwards compatibility
                                message = json.loads(data.decode('utf-8'))
                            try:
                                self.process_incoming_message(message, source_link_nid='BLE_GATT')
                            except Exception:
                                print(f"[{self.name}] Erro ao processar mensagem GATT")
                        except Exception:
                            print(f"[{self.name}] Erro ao descodificar escrita GATT (fragmentos)")

                    self.ble_gatt_server = BlueZGattServer(on_write=_on_gatt_write, adapter=self.adapter)
                except Exception as e:
                    print(f"[{self.name}] Aviso: falha ao inicializar GATT server: {e}")
                    self.ble_gatt_server = None
        
        print(f"[{self.name}] Inicializado. NID: {self.nid}")

        # CA certificate (for peer certificate validation - Sec. 5.4)
        self.ca_certificate: Optional[x509.Certificate] = self._load_ca_certificate()

        # Cache our own cert PEM (needed for LINK_AUTH2)
        self._our_cert_pem: Optional[bytes] = None
        try:
            if self.certificate is not None:
                self._our_cert_pem = self.certificate.public_bytes(serialization.Encoding.PEM)
        except Exception:
            self._our_cert_pem = None

        # Per-link sessions (Sec. 5.5, 5.6)
        self.link_sessions: Dict[str, LinkSession] = {}
        
        # Forwarding table (Sec. 3.1)
        self.forwarding_table: Dict[str, str] = {}

        # End-to-end sessions for service clients (Sec. 5.7)
        self.e2e_sessions: Dict[Tuple[str, int], E2ESession] = {}

        # Inbox storage (Sec. 5.7, 6)
        self.inbox_messages: List[Dict[str, Any]] = []
        
        # Estatísticas para UI (Sec. 6)
        self.messages_received_count = 0
        self.heartbeats_sent_count = 0

    # ==================== IDENTITY ====================
    
    def _load_identity(self):
        """Carrega o certificado X.509 e a chave privada do Sink (Sec. 5.2)."""
        file_name = self.name.lower().replace(" ", "_")
        cert_path = os.path.join(OUTPUT_DIR, f"{file_name}_certificate.pem")
        key_path = os.path.join(OUTPUT_DIR, f"{file_name}_private.pem") 

        if not os.path.exists(cert_path) or not os.path.exists(key_path):
            print(f"[ERRO] Ficheiros de identidade do Sink não encontrados!")
            print(f"       Execute: python support/ca_manager.py")
            return

        with open(cert_path, "rb") as f:
            self.certificate = x509.load_pem_x509_certificate(f.read())
        with open(key_path, "rb") as f:
            self.private_key = load_pem_private_key(f.read(), password=None)
        
        try:
            nid_attribute = self.certificate.subject.get_attributes_for_oid(x509.NameOID.USER_ID)[-1]
            self.nid = nid_attribute.value
        except IndexError:
            self.nid = None
            print(f"[ERRO] Certificado do Sink não contém NID!")

    def _load_all_node_certificates(self):
        """Carrega certificados de todos os nodes (Sec. 5.3)."""
        if not os.path.exists(OUTPUT_DIR):
            return
            
        for filename in os.listdir(OUTPUT_DIR):
            if filename.endswith("_certificate.pem") and "ca" not in filename and "sink" not in filename:
                node_name = filename.split("_")[0]
                cert_path = os.path.join(OUTPUT_DIR, filename)
                
                try:
                    with open(cert_path, "rb") as f:
                        cert = x509.load_pem_x509_certificate(f.read())
                    
                    nid_attribute = cert.subject.get_attributes_for_oid(x509.NameOID.USER_ID)[-1]
                    node_nid = nid_attribute.value
                    
                    self.node_public_keys[node_nid] = cert.public_key()
                    print(f"[{self.name}] Chave Pública carregada: {node_name} ({node_nid[:8]}...)")
                except Exception as e:
                    print(f"[AVISO] Erro ao carregar certificado de {node_name}: {e}")

    def _load_ca_certificate(self) -> Optional[x509.Certificate]:
        """Carrega certificado da CA (Sec. 5.3)."""
        try:
            ca_path = os.path.join(OUTPUT_DIR, "ca_certificate.pem")
            with open(ca_path, "rb") as f:
                return x509.load_pem_x509_certificate(f.read())
        except Exception:
            return None

    # ==================== LINK SECURITY (Sec. 5.4-5.6) ====================
    
    async def _send_link_secure(self, neighbor_nid: str, inner_msg: Dict[str, Any]) -> bool:
        """Envia mensagem com MAC de integridade por link (Sec. 5.6)."""
        if not self.nid:
            return False
        session = self.link_sessions.get(neighbor_nid)
        if not session:
            return False
        secure = wrap_link_secure(session, self.nid, inner_msg)
        data = json.dumps(secure).encode("utf-8")

        try:
            if self.ble_gatt_server is not None:
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

    # ==================== MESSAGE PROCESSING ====================
    
    def _on_ble_message_received(self, message: Dict, sender_handle: int):
        """Callback para mensagens BLE recebidas."""
        self.messages_received_count += 1
        source_link_nid = message.get("link_sender_nid") or message.get("source_nid", "UNKNOWN")
        self.process_incoming_message(message, source_link_nid)
                    
    def process_incoming_message(self, message: Dict, source_link_nid: str):
        """
        Processa mensagens recebidas pelo Sink.
        
        Implementa:
        - Autenticação mútua de link (Sec. 5.4, 5.5)
        - Verificação de MAC e anti-replay (Sec. 5.6)
        - Routing com forwarding table (Sec. 3.1)
        - Serviço Inbox end-to-end (Sec. 5.7)
        """
        source_nid = message.get("source_nid")

        # --- Link mutual authentication (Sec. 5.4, 5.5) ---
        if message.get("type") == "LINK_AUTH1":
            if not self.private_key or not self._our_cert_pem or not self.ca_certificate:
                return
            validated = validate_auth1(message, self.ca_certificate)
            if not validated:
                print(f"[{self.name}] ❌ LINK_AUTH1 inválido - certificado não validado pela CA")
                return
            peer_nid, _peer_pub, peer_eph_pub, peer_nonce = validated

            auth2, eph_priv_b, nonce_b = build_link_auth2(self._our_cert_pem, self.private_key, peer_eph_pub, peer_nonce)
            try:
                # Derivar session key (Sec. 5.5)
                key = derive_link_key(eph_priv_b, peer_eph_pub, peer_nonce, nonce_b)
                self.link_sessions[peer_nid] = LinkSession(peer_nid=peer_nid, key=key)
                print(f"[{self.name}] ✅ Sessão de link estabelecida com {peer_nid[:8]}...")
            except Exception as e:
                print(f"[{self.name}] ❌ Erro ao derivar chave de sessão: {e}")
                return

            # Registar como downlink direto
            self.downlinks[peer_nid] = True
            self.forwarding_table[peer_nid] = peer_nid

            try:
                data = json.dumps({**auth2, "link_sender_nid": self.nid}).encode("utf-8")
                if self.ble_gatt_server is not None:
                    asyncio.create_task(self.ble_gatt_server.notify_all(data))
                elif self.ble_manager:
                    asyncio.create_task(self.ble_manager.broadcast_to_downlinks(data))
            except Exception:
                pass
            return

        # --- Per-link authenticated wrapper (Sec. 5.6) ---
        if message.get("type") == "LINK_SECURE":
            link_sender = message.get("link_sender_nid")
            if not link_sender:
                return
            session = self.link_sessions.get(link_sender)
            if not session:
                print(f"[{self.name}] ⚠️ LINK_SECURE de peer sem sessão: {link_sender[:8]}...")
                return
            inner = unwrap_link_secure(session, message)
            if not inner:
                print(f"[{self.name}] ❌ LINK_SECURE inválido (MAC/replay)")
                return
            message = inner
            source_link_nid = link_sender
            source_nid = message.get("source_nid")

        # Handle REGISTER messages
        if message.get("type") == "REGISTER":
            if source_nid and source_nid != "UNKNOWN":
                self.downlinks[source_nid] = True
                if source_link_nid and source_link_nid != "UNKNOWN":
                    self.forwarding_table[source_nid] = source_link_nid
                print(f"[{self.name}] ✅ Downlink registado: {source_nid[:8]}...")
            return

        # Sink não processa heartbeats
        if message.get("is_heartbeat", False):
            return

        if not source_nid or source_nid == "UNKNOWN":
            return

        # Learn forwarding (Sec. 3.1)
        if source_link_nid and source_link_nid != "UNKNOWN":
            self.forwarding_table[source_nid] = source_link_nid

        # --- End-to-end handshake DTLS-like (Sec. 5.7) ---
        if message.get("type") == "E2E_HELLO1":
            if not self.private_key or not self._our_cert_pem or not self.ca_certificate or not self.nid:
                return
            validated = validate_hello1(message, self.ca_certificate)
            if not validated:
                print(f"[{self.name}] ❌ E2E_HELLO1 inválido")
                return
            peer_nid, client_id, peer_eph_pub, peer_nonce = validated

            hello2, eph_priv_b, nonce_b = build_e2e_hello2(self._our_cert_pem, self.private_key, int(client_id), peer_eph_pub, peer_nonce)
            try:
                key = derive_e2e_key(eph_priv_b, peer_eph_pub, peer_nonce, nonce_b, int(client_id))
                self.e2e_sessions[(peer_nid, int(client_id))] = E2ESession(peer_nid=peer_nid, client_id=int(client_id), key=key)
                print(f"[{self.name}] ✅ Sessão E2E estabelecida: {peer_nid[:8]}... (client_id={client_id})")
            except Exception as e:
                print(f"[{self.name}] ❌ Erro ao derivar chave E2E: {e}")
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

        # --- E2E secure service traffic - Inbox (Sec. 5.7) ---
        if message.get("type") == "E2E_SECURE":
            if not self.nid:
                return
            try:
                client_id = int(message.get("client_id"))
            except Exception:
                return
            session = self.e2e_sessions.get((source_nid, int(client_id)))
            if not session:
                print(f"[{self.name}] ⚠️ E2E_SECURE sem sessão estabelecida")
                return
            record = message.get("record")
            if not isinstance(record, dict):
                return
            inner = unwrap_e2e_record(session, record)
            if not inner:
                print(f"[{self.name}] ❌ E2E_SECURE inválido (AES-GCM/replay)")
                return

            if inner.get("service") == "inbox":
                entry = {
                    "from_nid": inner.get("from_nid") or source_nid,
                    "message": inner.get("message"),
                    "client_id": int(client_id),
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                }
                self.inbox_messages.append(entry)
                print(f"[{self.name}] 📥 Inbox de {entry['from_nid'][:8]}...: {entry['message']}")

                # Enviar ACK
                resp_payload = {"service": "inbox", "ack": True, "echo": entry["message"]}
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

        # Routing downstream (Sec. 3.1)
        destination_nid = message.get("destination_nid")
        if destination_nid and destination_nid != self.nid and destination_nid in self.forwarding_table:
            next_hop = self.forwarding_table[destination_nid]
            if next_hop != source_link_nid:
                try:
                    asyncio.create_task(self._send_link_secure(next_hop, message))
                except Exception:
                    pass

    # ==================== HEARTBEAT (Sec. 3.2) ====================
    
    async def send_heartbeat_ble(self, heartbeat_counter: int) -> int:
        """
        Envia Heartbeat assinado para todos os Downlinks via BLE (Sec. 3.2).
        
        O heartbeat é assinado com a chave privada do Sink (ECDSA).
        É enviado via multi-unicast para permitir stop_hb por nó.
        """
        if not self.private_key:
            print(f"[{self.name}] ERRO: Chave privada não disponível")
            return 0
        
        hb_msg = sign_heartbeat(heartbeat_counter, self.private_key)
        self.heartbeats_sent_count += 1
        
        message = {
            "source_nid": self.nid,
            "destination_nid": "BROADCAST",
            "is_heartbeat": True,
            "heartbeat_data": hb_msg
        }
        
        data = json.dumps(message).encode('utf-8')

        # Multi-unicast para permitir stop_hb por nó (Sec. 4)
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
            blocked = len(self.blocked_heartbeat_downlinks)
            print(f"[{self.name}][HB:{heartbeat_counter}] Enviado: {success_count}/{downlink_count} (blocked={blocked})")
            return success_count

        # Fallback: GATT notify
        if self.ble_gatt_server is not None:
            try:
                await self.ble_gatt_server.notify_all(data)
                sub_count = getattr(self.ble_gatt_server, 'get_subscriber_count', lambda: 0)()
                print(f"[{self.name}][HB:{heartbeat_counter}] GATT notify (subscribers={sub_count})")
                return sub_count
            except Exception as e:
                print(f"[{self.name}] Erro GATT: {e}")

        return 0

    # ==================== NETWORK CONTROLS (Sec. 4) ====================
    
    async def scan_nearby(self, duration: float = 5.0, show_all: bool = False) -> Dict[str, int]:
        """Scan para dispositivos vizinhos e mostra hop count (Sec. 4)."""
        if not self.ble_manager:
            return {}
        results = await self.ble_manager.scan_for_uplinks(duration=duration, adapter=self.adapter, show_all=show_all)
        self.last_scan_results = dict(results)
        return results

    async def connect_downlink(self, target_nid: str) -> bool:
        """Conecta a um node como downlink (Sec. 4)."""
        if not self.ble_manager:
            return False
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
        """Para de enviar heartbeats para um downlink específico (Sec. 4)."""
        self.blocked_heartbeat_downlinks.add(downlink_nid)
        print(f"[{self.name}] 🚫 Heartbeat bloqueado para {downlink_nid[:8]}...")

    def start_heartbeat_to(self, downlink_nid: str) -> None:
        """Retoma envio de heartbeats para um downlink (Sec. 4)."""
        self.blocked_heartbeat_downlinks.discard(downlink_nid)
        print(f"[{self.name}] ✅ Heartbeat desbloqueado para {downlink_nid[:8]}...")

    # ==================== USER INTERFACE (Sec. 6) ====================
    
    def get_status(self) -> Dict[str, Any]:
        """Retorna estado completo do Sink para UI (Sec. 6)."""
        return {
            "nid": self.nid,
            "hop_count": self.hop_count,
            "downlinks": list(self.downlinks.keys()),
            "downlinks_count": len(self.downlinks),
            "forwarding_table": dict(self.forwarding_table),
            "forwarding_table_count": len(self.forwarding_table),
            "link_sessions": list(self.link_sessions.keys()),
            "e2e_sessions": [(nid, cid) for (nid, cid) in self.e2e_sessions.keys()],
            "blocked_heartbeats": list(self.blocked_heartbeat_downlinks),
            "inbox_count": len(self.inbox_messages),
            "messages_received": self.messages_received_count,
            "heartbeats_sent": self.heartbeats_sent_count,
        }

    def print_status(self):
        """Imprime estado formatado do Sink (Sec. 6)."""
        status = self.get_status()
        print("\n" + "=" * 60)
        print(" SINK HOST STATUS ".center(60, "="))
        print("=" * 60)
        print(f"| NID: {status['nid']}")
        print(f"| Hop Count: {status['hop_count']}")
        print(f"| Downlinks ({status['downlinks_count']}):")
        for nid in status['downlinks']:
            blocked = "🚫" if nid in self.blocked_heartbeat_downlinks else "✅"
            print(f"|   {blocked} {nid[:8]}...")
        print(f"| Forwarding Table ({status['forwarding_table_count']} entradas):")
        for dest, hop in status['forwarding_table'].items():
            print(f"|   {dest[:8]}... via {hop[:8]}...")
        print(f"| Link Sessions: {len(status['link_sessions'])}")
        print(f"| E2E Sessions: {len(status['e2e_sessions'])}")
        print(f"| Inbox Messages: {status['inbox_count']}")
        print(f"| Heartbeats Sent: {status['heartbeats_sent']}")
        print(f"| Messages Received: {status['messages_received']}")
        print("=" * 60)


if __name__ == "__main__":
    print("[SinkHost] Use sync/sink_runtime.py para executar o Sink interativo.")
