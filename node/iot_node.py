# node/iot_node.py (CÓDIGO FINAL DE LÓGICA + CORREÇÃO DE AMBIENTE MOVIDA PARA O TOPO)


import os
import sys 
import time
import threading
import struct 
import asyncio 
import json
from typing import Optional, Dict, Any, Tuple
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate 
from common.heartbeat import verify_heartbeat, load_sink_keys, sign_heartbeat 
from common.heartbeat import HEARTBEAT_PACING_SECONDS
from common.ble_manager import BLEConnectionManager, BLEAdvertiser 
# Prefer BlueZAdvertiser on Linux if available (BlueZ + dbus-next)
try:
    from common.ble_advertiser_bluez import BlueZAdvertiser
except Exception:
    BlueZAdvertiser = None

# --- CORREÇÃO DE AMBIENTE: MOVIDA PARA O TOPO ---
# Adiciona o diretório raiz ao caminho de pesquisa antes de qualquer outra importação local.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))
# ------------------------------------------------------------------------------------

# As importações são ABSOLUTAS.
from common.network_utils import build_advertisement_data, bytes_to_string_nid, SIC_SERVICE_UUID
from support.ca_manager import OUTPUT_DIR 
# Serviço Inbox end-to-end protegido (DTLS-like), roteado pela rede.

from common.link_security import (
    LinkSession,
    build_link_auth1,
    build_link_auth2,
    validate_auth1,
    validate_auth2,
    derive_link_key,
    wrap_link_secure,
    unwrap_link_secure,
)

from common.e2e_security import (
    E2ESession,
    build_e2e_hello1,
    derive_e2e_key,
    unwrap_e2e_record,
    validate_hello2,
    wrap_e2e_record,
)

# --- Constantes ---
DISCONNECTED_HOP_COUNT = -1 
SINK_NID_STR = "44c7f5ca-bda5-458c-bfad-7cd2075cf862"
NODE_B_NID_STR = "b328a1c9-1a73-45f8-84e0-77a8d5f47c0d" 
NODE_SUBA_NID = "77777777-1111-4567-8901-c00000000001" 
MAX_LOST_HEARTBEATS = 3 


class IoTNode:
    """
    Representa um dispositivo IoT (sensor/roteador) no projeto SIC.
    
    Contém a lógica de:
    - Identidade (certificados X.509, NID de 128 bits)
    - Estado de rede (hop count, uplink, downlinks)
    - Roteamento (forwarding table)
    - Liveness (heartbeats)
    - Segurança por link (autenticação mútua, session keys, MACs)
    - Segurança end-to-end (DTLS-like para serviço Inbox)
    
    FEATURE BÓNUS - Múltiplos Sinks:
    - Suporta cenário com múltiplos Sinks na rede
    - Deteta mudança de Sink através do NID no heartbeat
    - Invalida sessões DTLS automaticamente quando o Sink muda
    - Permite reconexão a Sink diferente
    """
    def __init__(self, name: str, is_sink: bool = False, adapter: Optional[str] = None, ble_gatt_server=None):
        self.name = name
        self.is_sink = is_sink
        self._debug_mode = False  # Toggle for BLE message logging
        
        # 1. IDENTIDADE
        self.nid: Optional[str] = None
        self.certificate: Optional[x509.Certificate] = None
        self.private_key = None 
        self._load_identity()

        # Link-security state (per-neighbor)
        self.ca_certificate: Optional[x509.Certificate] = self._load_ca_certificate()
        self._our_cert_pem: Optional[bytes] = None
        if self.certificate is not None:
            try:
                self._our_cert_pem = self.certificate.public_bytes(serialization.Encoding.PEM)
            except Exception:
                self._our_cert_pem = None

        self.link_sessions: Dict[str, LinkSession] = {}
        # Pending AUTH2 futures keyed by target peer NID
        self._pending_auth2: Dict[str, asyncio.Future] = {}
        # Pending AUTH1 ephemeral state keyed by peer NID
        self._pending_auth1_state: Dict[str, Dict[str, Any]] = {}

        # End-to-end (DTLS-like) sessions to Sink
        # Keyed by (sink_nid, client_id)
        self.e2e_sessions: Dict[Tuple[str, int], E2ESession] = {}
        # Pending HELLO2 futures keyed by client_id
        self._pending_e2e_hello2: Dict[int, asyncio.Future] = {}
        # Pending HELLO1 ephemeral state keyed by client_id
        self._pending_e2e_state: Dict[int, Dict[str, Any]] = {}
        
        # MULTI-SINK SUPPORT (Feature Bónus)
        # O sink_nid é o NID do Sink atualmente conhecido
        # Pode ser atualizado dinamicamente se detetarmos um Sink diferente
        self.sink_certificate = self._load_sink_certificate() 
        self.sink_nid: Optional[str] = None
        self._current_network_sink_nid: Optional[str] = None  # Sink da rede atual
        if self.sink_certificate:
            try:
                nid_attr = self.sink_certificate.subject.get_attributes_for_oid(x509.NameOID.USER_ID)[-1]
                self.sink_nid = nid_attr.value
                self._current_network_sink_nid = self.sink_nid
            except Exception:
                self.sink_nid = None
        
        # 2. ESTADO DA REDE
        self.hop_count: int = 0 if self.is_sink else DISCONNECTED_HOP_COUNT
        self.uplink_nid: Optional[str] = None 
        self.downlinks: Dict[str, bool] = {} 
        self.forwarding_table: Dict[str, str] = {}
        
        # 3. MONITORIZAÇÃO
        self.lost_heartbeats: int = 0
        self.messages_routed_uplink: int = 0

        # Network control: block forwarding heartbeats to specific direct downlinks
        self.blocked_heartbeat_downlinks: set[str] = set()
        
        # 4. BLE MANAGER (Conexões BLE reais)
        self.ble_manager: Optional[BLEConnectionManager] = None
        self.ble_advertiser: Optional[BLEAdvertiser] = None
        self.ble_gatt_server = ble_gatt_server  # GATT server for downlink notifications
        # Adapter used for BLE operations (hci0, hci1, etc.)
        # If not provided, fall back to environment variable `SIC_BLE_ADAPTER` or 'hci0'.
        self.adapter = adapter or os.environ.get('SIC_BLE_ADAPTER', 'hci0')
        
        # Inicializar BLE Manager se NID estiver disponível
        if self.nid:
            self.ble_manager = BLEConnectionManager(
                device_nid=self.nid,
                on_message_received=self._on_ble_message_received,
                adapter=self.adapter,
                on_uplink_lost=self._on_uplink_lost,
                on_downlink_lost=self._on_downlink_lost
            )
            # Prefer a real BlueZ advertiser when available, otherwise use fallback
            try:
                if BlueZAdvertiser is not None:
                    self.ble_advertiser = BlueZAdvertiser(self.nid, self.hop_count, adapter=self.adapter)
                else:
                    self.ble_advertiser = BLEAdvertiser(self.nid, self.hop_count)
            except Exception as e:
                print(f"[{self.name}] Aviso: Falha ao inicializar BlueZAdvertiser: {e}. Usando fallback BLEAdvertiser.")
                self.ble_advertiser = BLEAdvertiser(self.nid, self.hop_count)
        
        print(f"[{self.name}] Inicializado. NID: {self.nid}, Hop Count: {self.hop_count}")

    def _load_ca_certificate(self) -> Optional[x509.Certificate]:
        try:
            ca_path = os.path.join(OUTPUT_DIR, "ca_certificate.pem")
            with open(ca_path, "rb") as f:
                return x509.load_pem_x509_certificate(f.read())
        except Exception:
            return None

    def _load_identity(self):
        """ Carrega o certificado X.509, a chave privada e extrai o NID. """
        
        file_name = self.name.lower().replace(" ", "_")
        cert_path = os.path.join(OUTPUT_DIR, f"{file_name}_certificate.pem")
        key_path = os.path.join(OUTPUT_DIR, f"{file_name}_private.pem") 

        if not os.path.exists(cert_path) or not os.path.exists(key_path):
            if self.name != "Sink Host": 
                 print(f"[ERRO] Ficheiros de identidade não encontrados. Execute o ca_manager.py!")
            return

        with open(cert_path, "rb") as f:
            self.certificate = x509.load_pem_x509_certificate(f.read())
        with open(key_path, "rb") as f:
            self.private_key = load_pem_private_key(f.read(), password=None)
        
        try:
            nid_attribute = self.certificate.subject.get_attributes_for_oid(x509.NameOID.USER_ID)[-1]
            self.nid = nid_attribute.value
        except IndexError:
            self.nid = "NID_ERROR"

    def _load_sink_certificate(self):
        """ Carrega o certificado público do Sink para verificar Heartbeats. """
        try:
            cert_path = os.path.join(OUTPUT_DIR, f"sink_host_certificate.pem")
            with open(cert_path, "rb") as f:
                return load_pem_x509_certificate(f.read())
        except FileNotFoundError:
            print("[AVISO] Certificado do Sink ausente para verificação de Heartbeat.")
            return None
    
    def _on_ble_message_received(self, message: Dict, sender_handle: int):
        """Callback chamado quando uma mensagem BLE é recebida"""
        # Determinar o NID do vizinho imediato (link sender).
        # Para mensagens encaminhadas, source_nid é a origem final; link_sender_nid é o próximo salto.
        source_link_nid = message.get("link_sender_nid") or message.get("source_nid", "UNKNOWN")
        
        if self._debug_mode:
            source_short = source_link_nid[:8] if source_link_nid != "UNKNOWN" else "UNKNOWN"
            # Check if sender is uplink - show both origin and relay
            if self.uplink_nid and source_link_nid == self.uplink_nid:
                # This is direct from uplink - it's the origin
                print(f"[{self.name}] Mensagem BLE recebida de {source_short}... (Uplink direto) (handle: {sender_handle})")
            elif self.uplink_nid:
                # Message originated elsewhere but relayed by uplink
                uplink_short = self.uplink_nid[:8]
                print(f"[{self.name}] Mensagem BLE recebida: origem={source_short}... via Uplink {uplink_short}... (handle: {sender_handle})")
            else:
                print(f"[{self.name}] Mensagem BLE recebida de {source_short}... (handle: {sender_handle})")
        
        # Processar mensagem através da lógica de roteamento existente
        self.process_incoming_message(message, source_link_nid)

    async def _send_plain_to_neighbor(self, neighbor_nid: str, msg: Dict[str, Any]) -> bool:
        """Send a JSON message to an adjacent neighbor without per-link MAC.

        Used for link authentication messages (LINK_AUTH1/2).
        """
        # Prefer GATT notify for downlinks (we act as peripheral). BLEManager
        # has no client connection to downlinks unless we explicitly accepted
        # them, so use notify when sending to non-uplink neighbors.
        if not self.ble_manager and not self.ble_gatt_server:
            return False
        msg = dict(msg)
        msg.setdefault("link_sender_nid", self.nid)
        data = json.dumps(msg).encode("utf-8")
        # If targeting uplink, use client write
        if self.uplink_nid and neighbor_nid == self.uplink_nid and self.ble_manager:
            return await self.ble_manager.send_to_uplink(data)
        # Otherwise, use GATT notify to reach subscribed downlinks
        try:
            if self.ble_gatt_server is not None:
                await self.ble_gatt_server.notify_all(data)
                return True
        except Exception:
            pass
        # Fallback: if we do have a client connection to the downlink, use it
        if self.ble_manager:
            return await self.ble_manager.send_to_downlink(neighbor_nid, data)
        return False

    async def _send_secure_to_neighbor(self, neighbor_nid: str, inner_msg: Dict[str, Any]) -> bool:
        """Send a per-link authenticated message (HMAC+seq) to an adjacent neighbor."""
        if not self.nid:
            return False
        session = self.link_sessions.get(neighbor_nid)
        if not session:
            return False
        secure = wrap_link_secure(session, self.nid, inner_msg)
        data = json.dumps(secure).encode("utf-8")
        # Uplink: use client write
        if self.uplink_nid and neighbor_nid == self.uplink_nid and self.ble_manager:
            return await self.ble_manager.send_to_uplink(data)
        # Downlink: prefer GATT notify broadcast to subscribers
        try:
            if self.ble_gatt_server is not None:
                await self.ble_gatt_server.notify_all(data)
                return True
        except Exception:
            pass
        # Fallback to BLEManager downlink client if available
        if self.ble_manager:
            return await self.ble_manager.send_to_downlink(neighbor_nid, data)
        return False

    async def _initiate_link_auth(self, neighbor_nid: str) -> bool:
        """Initiate mutual authentication + session key establishment with an adjacent neighbor."""
        if not self.private_key or not self._our_cert_pem or not self.ca_certificate:
            return False
        if neighbor_nid in self.link_sessions:
            return True

        auth1, eph_priv, nonce_a = build_link_auth1(self._our_cert_pem, self.private_key)
        # Save initiator state so we can validate AUTH2
        self._pending_auth1_state[neighbor_nid] = {
            "eph_priv": eph_priv,
            "eph_pub": __import__("base64").b64decode(auth1["eph_pub_b64"]),
            "nonce_a": nonce_a,
        }

        fut = asyncio.get_event_loop().create_future()
        self._pending_auth2[neighbor_nid] = fut

        ok = await self._send_plain_to_neighbor(neighbor_nid, auth1)
        if not ok:
            self._pending_auth2.pop(neighbor_nid, None)
            self._pending_auth1_state.pop(neighbor_nid, None)
            return False

        try:
            auth2 = await asyncio.wait_for(fut, timeout=8.0)
        except Exception:
            self._pending_auth2.pop(neighbor_nid, None)
            self._pending_auth1_state.pop(neighbor_nid, None)
            return False

        state = self._pending_auth1_state.pop(neighbor_nid, None)
        self._pending_auth2.pop(neighbor_nid, None)
        if not state:
            return False

        validated = validate_auth2(auth2, self.ca_certificate, state["eph_pub"], state["nonce_a"])
        if not validated:
            return False
        peer_nid, _peer_pub, peer_eph_pub, nonce_b = validated
        if peer_nid != neighbor_nid:
            return False

        key = derive_link_key(state["eph_priv"], peer_eph_pub, state["nonce_a"], nonce_b)
        self.link_sessions[neighbor_nid] = LinkSession(peer_nid=neighbor_nid, key=key)
        return True

    def _on_uplink_lost(self, address: str):
        """Callback called by BLE manager when uplink disconnects."""
        # Trigger chain reaction: disconnect uplink and all downlinks, set hop=-1, then rejoin lazily
        async def _handle():
            await self.disconnect_uplink()
            await asyncio.sleep(0)  # yield
            await self.rejoin_network()
        try:
            asyncio.create_task(_handle())
        except Exception:
            pass

    def _on_downlink_lost(self, nid: str):
        """Callback on individual downlink disconnect (for logging)."""
        try:
            if nid in self.downlinks:
                del self.downlinks[nid]
        except Exception:
            pass

    # --- LÓGICA DE SERVIÇOS SEGUROS ---
    # Removida: não enviamos mensagens entre dispositivos neste projeto.

    # --- LÓGICA DE LIVENESS ---

    def _check_sink_change(self, heartbeat_msg: Dict) -> bool:
        """
        FEATURE BÓNUS - Múltiplos Sinks:
        Verifica se o Sink da rede mudou comparando o source_nid do heartbeat.
        
        Se o Sink mudou:
        1. Invalida todas as sessões E2E (DTLS-like)
        2. Atualiza o sink_nid atual
        3. Retorna True para indicar mudança
        
        Returns:
            True se o Sink mudou, False caso contrário
        """
        hb_source_nid = heartbeat_msg.get("source_nid")
        if not hb_source_nid:
            return False
        
        # Se ainda não temos um Sink conhecido, aceitar este
        if not self._current_network_sink_nid:
            self._current_network_sink_nid = hb_source_nid
            print(f"[{self.name}] 🔗 Sink da rede identificado: {hb_source_nid[:8]}...")
            return False
        
        # Verificar se o Sink mudou
        if hb_source_nid != self._current_network_sink_nid:
            old_sink = self._current_network_sink_nid[:8]
            new_sink = hb_source_nid[:8]
            print(f"[{self.name}] ⚠️ SINK MUDOU: {old_sink}... → {new_sink}...")
            
            # Invalidar todas as sessões E2E com o Sink antigo
            old_sessions = [k for k in self.e2e_sessions.keys() if k[0] == self._current_network_sink_nid]
            for session_key in old_sessions:
                del self.e2e_sessions[session_key]
                print(f"[{self.name}] 🗑️ Sessão E2E invalidada: client_id={session_key[1]}")
            
            # Atualizar o Sink atual
            self._current_network_sink_nid = hb_source_nid
            self.sink_nid = hb_source_nid
            
            return True
        
        return False

    def process_heartbeat(self, heartbeat_msg: Dict):
        """
        Verifica a assinatura do HB e reinicia o contador de perdas.
        
        FEATURE BÓNUS: Também verifica se o Sink mudou (multi-sink support).
        """
        if not self.uplink_nid or self.hop_count == DISCONNECTED_HOP_COUNT: 
            return
        
        # Verificar mudança de Sink (Feature Bónus)
        sink_changed = self._check_sink_change(heartbeat_msg)
        if sink_changed:
            print(f"[{self.name}] ℹ️ Sessões E2E serão re-estabelecidas na próxima comunicação")
            
        if self.sink_certificate:
            sink_public_key = self.sink_certificate.public_key()
            is_valid = verify_heartbeat(heartbeat_msg["heartbeat_data"], sink_public_key)
            
            if is_valid:
                self.lost_heartbeats = 0
                # Forward heartbeat to all downlinks
                if self.downlinks:
                    asyncio.create_task(self._forward_heartbeat_to_downlinks(heartbeat_msg))
            else:
                pass  # Invalid signature, will be tracked in check_liveness
    
    async def _forward_heartbeat_to_downlinks(self, heartbeat_msg: Dict):
        """ Reenvia heartbeat para todos os downlinks conectados via GATT notify. """
        if not self.downlinks:
            return
        
        # Prefer GATT server notification (for devices connected as centrals)
        # Note: BlueZGattServer notifications are broadcast to subscribers; per-downlink
        # blocking cannot be enforced in that mode.
        if self.ble_gatt_server and not self.blocked_heartbeat_downlinks:
            try:
                hb_json = json.dumps(heartbeat_msg)
                hb_bytes = hb_json.encode('utf-8')
                await self.ble_gatt_server.notify_all(hb_bytes)
            except Exception as e:
                print(f"[{self.name}] Erro ao notificar HB via GATT: {e}")
        # Fallback to BLE manager for client-mode connections (if any)
        elif self.ble_manager:
            try:
                hb_json = json.dumps(heartbeat_msg)
                hb_bytes = hb_json.encode('utf-8')
                for downlink_nid in list(self.downlinks.keys()):
                    if downlink_nid in self.blocked_heartbeat_downlinks:
                        continue
                    try:
                        success = await self.ble_manager.send_to_downlink(downlink_nid, hb_bytes)
                        if not success:
                            print(f"[{self.name}] ⚠️ Falha ao enviar HB para downlink {downlink_nid[:8]}...")
                    except Exception as e:
                        print(f"[{self.name}] Erro ao enviar HB para {downlink_nid[:8]}...: {e}")
            except Exception as e:
                print(f"[{self.name}] Erro ao serializar HB: {e}")

    def block_heartbeat_to_downlink(self, downlink_nid: str) -> None:
        """Network control (sec. 4): stop forwarding heartbeats to a direct downlink."""
        self.blocked_heartbeat_downlinks.add(downlink_nid)

    def unblock_heartbeat_to_downlink(self, downlink_nid: str) -> None:
        self.blocked_heartbeat_downlinks.discard(downlink_nid)

    def list_blocked_heartbeats(self) -> list[str]:
        return sorted(self.blocked_heartbeat_downlinks)

    async def check_liveness(self):
        """ Verifica se o Uplink falhou (Heartbeat Perdido). """
        if self.uplink_nid is None: return

        self.lost_heartbeats += 1
        
        if self.lost_heartbeats > MAX_LOST_HEARTBEATS:
            print(f"[{self.name}] ⚠️ Heartbeat perdido {self.lost_heartbeats}x. Desconectando e reinserindo na rede...")
            await self.disconnect_uplink()
            await self.rejoin_network()

    async def disconnect_uplink(self):
        """ Rotina de desconexão (Secção 3): quebra Uplink, Downlinks, e reseta estado. """
        if not self.uplink_nid: return

        print(f"\n[{self.name}] >>> DISCONEXÃO INICIADA: Uplink {self.uplink_nid[:8]}... CAIU! <<<")
        
        # Desconectar BLE do Uplink
        if self.ble_manager:
            await self.ble_manager.disconnect_uplink()
        
        # Desconectar e limpar Downlinks
        downlink_nids = list(self.downlinks.keys())
        for nid in downlink_nids:
            if self.ble_manager:
                await self.ble_manager.disconnect_downlink(nid)
            del self.downlinks[nid]
            
        self.uplink_nid = None
        self.hop_count = DISCONNECTED_HOP_COUNT
        self.lost_heartbeats = 0
        self.forwarding_table = {} 
        
        # Atualizar advertiser
        if self.ble_advertiser:
            self.ble_advertiser.update_hop_count(DISCONNECTED_HOP_COUNT)
        
        print(f"[{self.name}] 🚨 Uplink desconectado. Reiniciando...")
        
    # --- Funções de Roteamento ---
    
    def update_forwarding_table(self, destination_nid: str, next_hop_nid: str):
        if next_hop_nid != self.nid:
            self.forwarding_table[destination_nid] = next_hop_nid
            
    def process_incoming_message(self, message: Dict, source_link_nid: str):
        source_nid = message.get("source_nid") 

        # --- Link authentication handshake (plain) ---
        if message.get("type") == "LINK_AUTH1":
            if not self.private_key or not self._our_cert_pem or not self.ca_certificate:
                return
            validated = validate_auth1(message, self.ca_certificate)
            if not validated:
                return
            peer_nid, _peer_pub, peer_eph_pub, peer_nonce = validated
            # Respond with AUTH2 and establish session
            auth2, eph_priv_b, nonce_b = build_link_auth2(self._our_cert_pem, self.private_key, peer_eph_pub, peer_nonce)
            try:
                key = derive_link_key(eph_priv_b, peer_eph_pub, peer_nonce, nonce_b)
                self.link_sessions[peer_nid] = LinkSession(peer_nid=peer_nid, key=key)
            except Exception:
                return
            # Ensure link bookkeeping
            if peer_nid and peer_nid != self.uplink_nid:
                self.downlinks.setdefault(peer_nid, True)
            try:
                asyncio.create_task(self._send_plain_to_neighbor(peer_nid, auth2))
            except Exception:
                pass
            return

        if message.get("type") == "LINK_AUTH2":
            peer_nid = None
            try:
                # Determine peer NID from certificate inside AUTH2
                if self.ca_certificate:
                    parsed = __import__("base64").b64decode(message.get("cert_pem_b64", ""))
                    cert = x509.load_pem_x509_certificate(parsed)
                    peer_nid_attr = cert.subject.get_attributes_for_oid(x509.NameOID.USER_ID)[-1]
                    peer_nid = peer_nid_attr.value
            except Exception:
                peer_nid = None
            if peer_nid and peer_nid in self._pending_auth2:
                fut = self._pending_auth2.get(peer_nid)
                if fut and not fut.done():
                    fut.set_result(message)
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

        # Handle registration messages from newly-connected centrals (needs only source_nid)
        if message.get("type") == "REGISTER":
            if source_nid and source_nid not in self.downlinks:
                self.downlinks[source_nid] = True
                print(f"[{self.name}] ✅ Novo Downlink registado: {source_nid[:8]}...")
            if source_nid:
                self.update_forwarding_table(source_nid, source_link_nid)
            return

        # For other messages, destination is required
        destination_nid = message.get("destination_nid")
        if not source_nid or not destination_nid: 
            return

        # If addressed to us, handle end-to-end control/data first
        if destination_nid == self.nid:
            if message.get("type") == "E2E_HELLO2":
                try:
                    client_id = int(message.get("client_id"))
                except Exception:
                    return
                fut = self._pending_e2e_hello2.get(client_id)
                if fut and not fut.done():
                    fut.set_result(message)
                return

            if message.get("type") == "E2E_SECURE":
                try:
                    client_id = int(message.get("client_id"))
                except Exception:
                    return
                if not self.sink_nid:
                    return
                session = self.e2e_sessions.get((self.sink_nid, client_id))
                if not session:
                    return
                record = message.get("record")
                if not isinstance(record, dict):
                    return
                inner = unwrap_e2e_record(session, record)
                if not inner:
                    return
                if inner.get("service") == "inbox":
                    print(f"[{self.name}] 📥 Inbox: {inner}")
                return

        # Checagem de Heartbeat
        if message.get("is_heartbeat", False):
            self.process_heartbeat(message)
            return

        # Mensagens de dados (DTLS Inbox) agora passam pelo roteamento (end-to-end)

        # 1. Atualizar Tabela de Encaminhamento
        self.update_forwarding_table(source_nid, source_link_nid)
        
        # 2. Decisão de Roteamento (Existente e Correta)
        if destination_nid == self.nid:
            return

        # A) Roteamento UPSTREAM (Em direção ao Sink)
        if self.uplink_nid and self.sink_nid and destination_nid == self.sink_nid:
            if source_link_nid != self.uplink_nid:
                self.messages_routed_uplink += 1
            try:
                asyncio.create_task(self._send_secure_to_neighbor(self.uplink_nid, message))
            except Exception:
                pass
            return

        # B) Roteamento DOWNSTREAM (Pesquisa na FT)
        if destination_nid in self.forwarding_table:
            next_hop = self.forwarding_table[destination_nid]
            if next_hop != source_link_nid:
                try:
                    asyncio.create_task(self._send_secure_to_neighbor(next_hop, message))
                except Exception:
                    pass
            return

    async def ensure_e2e_session(self, client_id: int) -> bool:
        """Establish an end-to-end secure session with the Sink (DTLS-like).

        Runs over the routed network; routers do not touch E2E payloads.
        """
        if not self.private_key or not self._our_cert_pem or not self.ca_certificate:
            return False
        if not self.sink_nid or not self.uplink_nid:
            return False

        session_key = (self.sink_nid, int(client_id))
        if session_key in self.e2e_sessions:
            return True

        hello1, eph_priv, nonce_a = build_e2e_hello1(self._our_cert_pem, self.private_key, int(client_id))
        hello1_msg = {
            **hello1,
            "source_nid": self.nid,
            "destination_nid": self.sink_nid,
        }

        self._pending_e2e_state[int(client_id)] = {
            "eph_priv": eph_priv,
            "eph_pub": __import__("base64").b64decode(hello1["eph_pub_b64"]),
            "nonce_a": nonce_a,
        }
        fut = asyncio.get_event_loop().create_future()
        self._pending_e2e_hello2[int(client_id)] = fut

        ok = await self._send_secure_to_neighbor(self.uplink_nid, hello1_msg)
        if not ok:
            self._pending_e2e_state.pop(int(client_id), None)
            self._pending_e2e_hello2.pop(int(client_id), None)
            return False

        try:
            hello2 = await asyncio.wait_for(fut, timeout=12.0)
        except Exception:
            self._pending_e2e_state.pop(int(client_id), None)
            self._pending_e2e_hello2.pop(int(client_id), None)
            return False

        state = self._pending_e2e_state.pop(int(client_id), None)
        self._pending_e2e_hello2.pop(int(client_id), None)
        if not state or not self.ca_certificate:
            return False

        validated = validate_hello2(
            hello2,
            self.ca_certificate,
            expected_client_id=int(client_id),
            expected_peer_eph_pub=state["eph_pub"],
            expected_peer_nonce=state["nonce_a"],
        )
        if not validated:
            return False

        peer_nid, _cid, peer_eph_pub, nonce_b = validated
        if peer_nid != self.sink_nid:
            return False

        key = derive_e2e_key(state["eph_priv"], peer_eph_pub, state["nonce_a"], nonce_b, int(client_id))
        self.e2e_sessions[session_key] = E2ESession(peer_nid=self.sink_nid, client_id=int(client_id), key=key)
        return True

    async def send_inbox_message(self, text: str, client_id: Optional[int] = None) -> bool:
        """Send an Inbox message to the Sink protected end-to-end."""
        if not self.sink_nid or not self.uplink_nid:
            return False
        if client_id is None:
            client_id = int.from_bytes(os.urandom(4), "big")

        ok = await self.ensure_e2e_session(int(client_id))
        if not ok:
            print(f"[{self.name}] ⚠️ Falha ao estabelecer sessão E2E com o Sink")
            return False

        session = self.e2e_sessions[(self.sink_nid, int(client_id))]
        app_payload = {
            "service": "inbox",
            "from_nid": self.nid,
            "message": text,
        }
        record = wrap_e2e_record(session, app_payload)
        outer = {
            "type": "E2E_SECURE",
            "client_id": int(client_id),
            "record": record,
            "source_nid": self.nid,
            "destination_nid": self.sink_nid,
        }
        return await self._send_secure_to_neighbor(self.uplink_nid, outer)
            
    # --- Funções de Publicidade e Descoberta (Mantidas) ---
    def calculate_advertisement_data(self) -> bytes:
        if not self.nid: return b''
        return build_advertisement_data(self.nid, self.hop_count)
        
    async def find_uplink_candidates(self, scan_duration: float = 5.0, adapter: Optional[str] = None) -> Dict[str, int]:
        """Realiza scanning BLE real para descobrir uplinks candidatos

        Args:
            scan_duration: duração do scan em segundos
            adapter: opcional, HCI adapter a usar (ex: 'hci0')
        """
        print(f"[{self.name}] Iniciando Descoberta BLE de Uplink... (adapter={adapter})")
        
        if not self.ble_manager:
            print(f"[{self.name}] ERRO: BLE Manager não inicializado.")
            return {}
        
        try:
            # Realizar scanning BLE real (pass-through do adapter quando fornecido)
            candidates = await self.ble_manager.scan_for_uplinks(duration=scan_duration, adapter=adapter)
            return candidates
        except Exception as e:
            print(f"[{self.name}] ERRO no scanning BLE: {e}")
            # Fallback para simulação em caso de erro
            print(f"[{self.name}] Usando modo simulado...")
            return {SINK_NID_STR: 0, NODE_B_NID_STR: 1}

    def choose_uplink(self, candidates: Dict[str, int]) -> Optional[str]:
        if not candidates:
            return None
        # Ignore invalid/disconnected hop counts (< 0)
        valid = {nid: hop for nid, hop in candidates.items() if hop is not None and hop >= 0}
        if not valid:
            print(f"[{self.name}] Nenhum candidato válido (hop>=0).")
            return None
        # Choose the lowest hop count among valid candidates
        best_candidate_nid = min(valid, key=valid.get)
        return best_candidate_nid
    
    async def connect_to_uplink(self, uplink_nid: str) -> bool:
        """Estabelece conexão BLE com o uplink escolhido"""
        print(f"[{self.name}] Conectando ao Uplink {uplink_nid[:8]}... via BLE")
        
        if not self.ble_manager:
            print(f"[{self.name}] ERRO: BLE Manager não disponível.")
            return False
        
        # Conectar via BLE
        success = await self.ble_manager.connect_to_device(uplink_nid)
        
        if success:
            self.uplink_nid = uplink_nid
            # Atualizar hop count (assumindo que está em discovered_devices)
            if uplink_nid in self.ble_manager.discovered_devices:
                _, uplink_hop = self.ble_manager.discovered_devices[uplink_nid]
            else:
                uplink_hop = None
            # Hop semantics: direct to Sink => 0, otherwise hop = uplink_hop + 1 (fallback to 1 if unknown/negative)
            if self.sink_nid and uplink_nid == self.sink_nid:
                self.hop_count = 0
            else:
                if uplink_hop is not None and uplink_hop >= 0:
                    self.hop_count = uplink_hop + 1
                else:
                    # If we don't know the uplink's hop (e.g., stale -1), assume we are 1 hop away
                    self.hop_count = max(1, self.hop_count)
            
            # Atualizar advertiser
            if self.ble_advertiser:
                self.ble_advertiser.update_hop_count(self.hop_count)
            
            print(f"[{self.name}] ✅ Conectado ao Uplink. Novo Hop Count: {self.hop_count}")
            # Establish per-link authenticated session (mutual auth + session key)
            try:
                auth_ok = await self._initiate_link_auth(uplink_nid)
            except Exception:
                auth_ok = False
            if not auth_ok:
                print(f"[{self.name}] ⚠️ Falha na autenticação mútua com o uplink {uplink_nid[:8]}... (sessão não estabelecida)")
            # After hop update, give BlueZ a brief moment to publish adv
            try:
                await asyncio.sleep(0.2)
            except Exception:
                pass
        
        return success

    async def rejoin_network(self, scan_duration: float = 5.0):
        """Scan devices, choose lowest-hop uplink among valid candidates, and connect.
        Lazy approach: only run on loss; do not switch if current uplink is working.
        """
        # If already connected, respect lazy policy and do nothing
        if self.ble_manager and self.ble_manager.is_connected_to_uplink():
            return
        # Update advertising to reflect disconnected state
        if self.ble_advertiser:
            try:
                self.ble_advertiser.update_hop_count(DISCONNECTED_HOP_COUNT)
            except Exception:
                pass
        # Try multiple attempts: prefer adapter; fallback to default; short backoff
        max_attempts = 3
        delay = 2.0
        for attempt in range(1, max_attempts + 1):
            candidates = {}
            try:
                candidates = await self.find_uplink_candidates(scan_duration=scan_duration, adapter=self.adapter)
            except Exception as e:
                print(f"[{self.name}] Aviso: scan falhou durante rejoin (tentativa {attempt}): {e}")
                # Fallback: scan without adapter hint
                try:
                    candidates = await self.find_uplink_candidates(scan_duration=scan_duration, adapter=None)
                except Exception as e2:
                    print(f"[{self.name}] Aviso: scan fallback falhou (tentativa {attempt}): {e2}")

            target = self.choose_uplink(candidates)
            if target:
                ok = await self.connect_to_uplink(target)
                if ok:
                    return
                print(f"[{self.name}] Falha ao reconectar ao uplink {target[:8]}... (tentativa {attempt})")
            else:
                print(f"[{self.name}] Nenhum uplink válido encontrado (tentativa {attempt}).")
            await asyncio.sleep(delay)
        print(f"[{self.name}] Rejoin falhou após {max_attempts} tentativas.")

    def print_status(self):
        print("\n" + "="*50)
        print(f" ESTADO DO DISPOSITIVO: {self.name} ".center(50, "="))
        print("="*50)
        print(f"| NID: {self.nid}")
        print(f"| Hop Count: {self.hop_count}")
        print(f"| Uplink: {self.uplink_nid if self.uplink_nid else 'NENHUM'}")
        print(f"| Downlinks ({len(self.downlinks)}): {', '.join(self.downlinks.keys()) if self.downlinks else 'Nenhum'}")
        print(f"| Lost Heartbeats: {self.lost_heartbeats}")
        print(f"| Mensagens Roteadas: {self.messages_routed_uplink}")
        
        print(f"| Forwarding Table ({len(self.forwarding_table)} entradas):")
        for dest, next_hop in self.forwarding_table.items():
            print(f"|   -> {dest[:8]}... via {next_hop[:8]}...")
        print("="*50)


# --- Função principal para testar a liveness e failover ---

async def simulate_liveness():
    """ Simula o Node A recebendo Heartbeats e perdendo 4. """
    
    # 1. Inicializar Node A e simular a conexão ao Sink
    node_a = IoTNode(name="Node A", is_sink=False)
    
    # Simulação da Conexão Bem-Sucedida
    node_a.uplink_nid = SINK_NID_STR 
    node_a.hop_count = 1
    node_a.downlinks[NODE_SUBA_NID] = True # Simula Downlink
    
    # Simulação de Carregamento de Chaves do Sink
    sink_private_key, sink_public_key = load_sink_keys()
    
    if not sink_private_key:
        print("\n[ERRO FATAL] Chave do Sink ausente para simulação de Heartbeat.")
        return

    print("\n" + "#"*60)
    print("## TESTE DE LIVENESS: RECEBIMENTO E FALHA (3 PERDAS) ##".center(60))
    print("#"*60 + "\n")
    node_a.print_status()

    
    # --- SIMULAÇÃO DO TEMPO ---
    
    hb_counter = 0

    # Ciclo 1: Recebe HB Válido (Reinicia o contador)
    hb_counter += 1
    hb_msg = sign_heartbeat(hb_counter, sink_private_key)
    
    print("\n--- CICLO 1: RECEBENDO HEARTBEAT VÁLIDO ---")
    node_a.process_incoming_message(
        message={"source_nid": SINK_NID_STR, "destination_nid": node_a.nid, "is_heartbeat": True, "heartbeat_data": hb_msg},
        source_link_nid=SINK_NID_STR # O HB chega pela conexão do Uplink
    )
    await asyncio.sleep(0.1) 
    
    # Ciclo 2: Heartbeat Perdido (Simulação: Heartbeat não chega)
    print("\n--- CICLO 2: SIMULANDO PERDA (1ª Perda) ---")
    await node_a.check_liveness()
    await asyncio.sleep(0.1)

    # Ciclo 3: Heartbeat Perdido (2ª Perda)
    print("\n--- CICLO 3: SIMULANDO PERDA (2ª Perda) ---")
    await node_a.check_liveness()
    await asyncio.sleep(0.1)

    # Ciclo 4: Heartbeat Perdido (3ª Perda -> FALHA!)
    print("\n--- CICLO 4: SIMULANDO PERDA (3ª Perda -> DISCONEXÃO) ---")
    await node_a.check_liveness()
    await asyncio.sleep(0.1)

    # Ciclo 5: Verificação do estado final
    print("\n--- CICLO 5: VERIFICANDO ESTADO FINAL ---")
    await node_a.check_liveness() 

    # Verifica o estado final
    node_a.print_status()

    
if __name__ == "__main__":
    import asyncio
    asyncio.run(simulate_liveness())
