# node/iot_node.py (CÓDIGO FINAL DE LÓGICA + CORREÇÃO DE AMBIENTE MOVIDA PARA O TOPO)


import os
import sys 
import time
import threading
import struct 
import asyncio 
import json
from typing import Optional, Dict, Any
from cryptography import x509
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
# DTLS Inbox desativado neste projeto (propagação apenas de Heartbeats)

# --- Constantes ---
DISCONNECTED_HOP_COUNT = -1 
SINK_NID_STR = "44c7f5ca-bda5-458c-bfad-7cd2075cf862"
NODE_B_NID_STR = "b328a1c9-1a73-45f8-84e0-77a8d5f47c0d" 
NODE_SUBA_NID = "77777777-1111-4567-8901-c00000000001" 
MAX_LOST_HEARTBEATS = 3 


class IoTNode:
    """
    Representa um dispositivo IoT (sensor/roteador) no projeto SIC.
    Contém a lógica de identidade, estado de rede, roteamento e liveness.
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
        
        self.sink_certificate = self._load_sink_certificate() 
        self.sink_nid: Optional[str] = None
        if self.sink_certificate:
            try:
                nid_attr = self.sink_certificate.subject.get_attributes_for_oid(x509.NameOID.USER_ID)[-1]
                self.sink_nid = nid_attr.value
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
        # Determinar o NID do sender (assumindo que vem na mensagem)
        source_link_nid = message.get("source_nid", "UNKNOWN")
        
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

    def process_heartbeat(self, heartbeat_msg: Dict):
        """ Verifica a assinatura do HB e reinicia o contador de perdas. """
        if not self.uplink_nid or self.hop_count == DISCONNECTED_HOP_COUNT: return
            
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
        if self.ble_gatt_server:
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
                    try:
                        success = await self.ble_manager.send_to_downlink(downlink_nid, hb_bytes)
                        if not success:
                            print(f"[{self.name}] ⚠️ Falha ao enviar HB para downlink {downlink_nid[:8]}...")
                    except Exception as e:
                        print(f"[{self.name}] Erro ao enviar HB para {downlink_nid[:8]}...: {e}")
            except Exception as e:
                print(f"[{self.name}] Erro ao serializar HB: {e}")

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

        # Checagem de Heartbeat
        if message.get("is_heartbeat", False):
            self.process_heartbeat(message)
            return

        # Mensagens de dados (DTLS Inbox) não são usadas neste projeto
        if message.get("type") == "DTLS_INBOX":
            return

        # 1. Atualizar Tabela de Encaminhamento
        self.update_forwarding_table(source_nid, source_link_nid)
        
        # 2. Decisão de Roteamento (Existente e Correta)
        if destination_nid == self.nid:
            return

        # A) Roteamento UPSTREAM (Em direção ao Sink)
        if destination_nid == self.uplink_nid: 
            if source_link_nid != self.uplink_nid: 
                self.messages_routed_uplink += 1 
            return
            
        # B) Roteamento DOWNSTREAM (Pesquisa na FT)
        if destination_nid in self.forwarding_table:
            next_hop = self.forwarding_table[destination_nid]
            return
            
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
