# 📜 SIC Project - Bluetooth-based, Secure Ad-hoc Network for IoT Devices

## 👤 1. Identificação do Grupo e Contribuição

| Número | Nome do Autor | Contribuição (%) |
| :--- | :--- | :--- |
| 115931 | Joaquim Martins | 25% |
| 115884 | Lázaro Sá | 25% |
| 112657 | Ricardo Carmo | 25% |
| 115359 | Daniel Oliveira | 25% |


## 🏗 2. Estrutura e Organização do Código

O projeto está organizado conforme os requisitos de entrega (Secção 8 do enunciado):

```
sic_project/
├── sync/                    # Código EXCLUSIVO do Sink (Secção 8)
│   ├── __init__.py
│   ├── sink_host.py         # Classe SinkHost principal
│   ├── sink_app.py          # Aplicação Sink (loop heartbeat)
│   └── sink_runtime.py      # Runtime interativo do Sink
│
├── node/                    # Código EXCLUSIVO dos IoT Nodes
│   ├── __init__.py
│   ├── iot_node.py          # Classe IoTNode principal
│   └── node_runtime.py      # Runtime interativo do Node
│
├── common/                  # Código PARTILHADO entre Sink e Nodes
│   ├── __init__.py
│   ├── ble_manager.py       # Gerenciador BLE (scanning, conexão)
│   ├── ble_advertiser_bluez.py  # Advertiser BLE nativo (BlueZ)
│   ├── ble_gatt_server_bluez.py # GATT server (BlueZ)
│   ├── link_security.py     # Segurança por-link (auth mútua + MAC)
│   ├── e2e_security.py      # Segurança end-to-end (DTLS-like)
│   ├── cert_utils.py        # Utilitários de certificados
│   ├── heartbeat.py         # Heartbeat assinado
│   ├── dtls_service.py      # Serviço DTLS
│   └── network_utils.py     # Utilitários de rede
│
├── support/                 # Ferramentas de SUPORTE (não usadas em runtime)
│   ├── ca_manager.py        # Autoridade Certificadora
│   ├── generate_devices.py  # Gerador de dispositivos
│   └── certs/               # Certificados e chaves geradas
│
├── examples/                # Exemplos e testes
│   ├── device_node.py       # Exemplo de Node interativo
│   ├── test_ble_connection.py
│   └── ...
│
├── README.md                # Este ficheiro
├── requirements.txt         # Dependências Python
└── Makefile                 # Comandos facilitadores
```

### Notas Importantes sobre a Estrutura:
- **`sync/`** contém **apenas** código do Sink (conforme Secção 8)
- **`node/`** contém **apenas** código dos IoT Nodes
- **`common/`** contém código partilhado
- **`support/`** NÃO é usado em runtime (apenas para gerar certificados)


## ⚙️ 3. Funcionalidades Implementadas - Gestão de Rede (20%)

### 3.1. Topologia em Árvore (Secção 3)

**Implementação:** A rede forma uma árvore com raiz no Sink (hop count = 0). Cada Node determina o seu hop count como `uplink_hop + 1`.

**Abordagem Lazy (conforme especificado):**
- O Node seleciona o vizinho com **menor hop count** ao entrar na rede
- **Não muda de uplink** enquanto este funcionar
- Só procura novo uplink após **perda do atual**

```python
# node/iot_node.py
def choose_uplink(self, candidates: Dict[str, int]) -> Optional[str]:
    valid = {nid: hop for nid, hop in candidates.items() if hop >= 0}
    if not valid:
        return None
    return min(valid, key=valid.get)  # Menor hop count
```

### 3.2. Hop Count Negativo (Secção 3)

**Implementação:** Nodes desconectados exibem `hop_count = -1` para sinalizar que não podem ser usados como uplink.

```python
DISCONNECTED_HOP_COUNT = -1

async def disconnect_uplink(self):
    self.hop_count = DISCONNECTED_HOP_COUNT
    if self.ble_advertiser:
        self.ble_advertiser.update_hop_count(DISCONNECTED_HOP_COUNT)
```

### 3.3. Desconexão em Cadeia (Secção 3)

**Implementação:** Quando um Node perde o uplink, desconecta imediatamente todos os downlinks, forçando-os a reentrar na rede.

```python
async def disconnect_uplink(self):
    # Desconectar todos os downlinks (chain reaction)
    for nid in list(self.downlinks.keys()):
        await self.ble_manager.disconnect_downlink(nid)
    self.downlinks.clear()
    self.forwarding_table.clear()
```

### 3.4. Addressing e Routing com Forwarding Tables (Secção 3.1)

**Implementação:** Seguimos o modelo de switch:
- **Aprendizagem:** Memorizamos o link de onde cada NID chegou
- **Upstream:** Tráfego para o Sink vai sempre pelo uplink
- **Downstream:** Pesquisa na forwarding table

```python
def update_forwarding_table(self, destination_nid: str, next_hop_nid: str):
    self.forwarding_table[destination_nid] = next_hop_nid

def process_incoming_message(self, message: Dict, source_link_nid: str):
    # Aprender rota
    self.update_forwarding_table(source_nid, source_link_nid)
    
    # Routing upstream
    if destination_nid == self.sink_nid:
        asyncio.create_task(self._send_secure_to_neighbor(self.uplink_nid, message))
    
    # Routing downstream
    elif destination_nid in self.forwarding_table:
        next_hop = self.forwarding_table[destination_nid]
        asyncio.create_task(self._send_secure_to_neighbor(next_hop, message))
```

### 3.5. Network Liveness - Heartbeat (Secção 3.2)

**Implementação:**
- Sink gera heartbeats assinados (ECDSA) a cada 5 segundos
- Heartbeats são propagados downstream (flood)
- Nodes verificam assinatura antes de usar/propagar
- **3 heartbeats perdidos** → uplink considerado down

```python
# common/heartbeat.py
def sign_heartbeat(counter: int, sink_private_key) -> Dict:
    data_to_sign = HEARTBEAT_STRUCT.pack(counter, timestamp)
    signature = sink_private_key.sign(data_to_sign, ec.ECDSA(HASH_ALGORITHM))
    return {"counter": counter, "timestamp": timestamp, "signature": signature.hex()}

# node/iot_node.py
async def check_liveness(self):
    self.lost_heartbeats += 1
    if self.lost_heartbeats > MAX_LOST_HEARTBEATS:  # 3
        await self.disconnect_uplink()
        await self.rejoin_network()
```


## 🛡️ 4. Opções e Justificativas de Segurança (50%)

### 4.1. Identificação de Dispositivos (Secção 5.1)

**Implementação:**
- Cada dispositivo tem um **certificado X.509** emitido pela CA
- **NID de 128 bits** (UUID) armazenado no campo `USER_ID` do certificado
- Curva elíptica **P-521 (SECP521R1)** conforme especificado

```python
# support/ca_manager.py
CURVE = ec.SECP521R1()
HASH_ALGORITHM = hashes.SHA512()

subject_name = x509.Name([
    x509.NameAttribute(NameOID.USER_ID, nid),  # NID 128-bit
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "IoT Node"),
])
```

### 4.2. Identificação do Sink (Secção 5.2)

**Implementação:** O Sink tem certificado com campo `OU=Sink` que o identifica como Sink.

```python
# common/cert_utils.py
def is_sink_certificate(cert: x509.Certificate) -> bool:
    return certificate_subject_ou(cert) == "Sink"
```

### 4.3. Autoridade Certificadora (Secção 5.3)

**Implementação:** CA centralizada que emite todos os certificados:
- Chave privada protegida (armazenamento seguro)
- Certificados válidos por 1 ano (dispositivos) / 10 anos (CA)

```bash
# Gerar CA e certificados
python support/ca_manager.py
```

### 4.4. Segurança Bluetooth - Autenticação Mútua (Secção 5.4, 5.5)

**Implementação:** Protocolo de autenticação mútua após conexão BLE:

1. **AUTH1:** A envia `(cert, eph_pub_A, nonce_A, sig_A)`
2. **AUTH2:** B valida cert, responde com `(cert, eph_pub_B, nonce_B, sig_B)`
3. **Derivação:** Ambos derivam `session_key = HKDF(ECDH(eph_A, eph_B), nonce_A || nonce_B)`

```python
# common/link_security.py
def derive_link_key(our_eph_priv, peer_eph_pub_bytes, nonce_a, nonce_b) -> bytes:
    shared = our_eph_priv.exchange(ec.ECDH(), peer_eph_pub)
    return HKDF(algorithm=SHA256, salt=nonce_a + nonce_b, info=b"SIC-LINK-SESSION-KEY").derive(shared)
```

**Justificativa:**
- **Chave fresca por sessão:** Cada sessão usa efémeros ECDH novos
- **Prova de posse:** Assinatura ECDSA prova que peer controla chave privada do certificado
- **Validação CA:** Certificados são validados contra a CA

### 4.5. Uso da Session Key - MAC + Anti-Replay (Secção 5.6)

**Implementação:**
- Mensagens protegidas com **HMAC-SHA256** usando session key
- **Número de sequência** monotónico para anti-replay
- Formato: `LINK_SECURE { seq, payload, mac }`

```python
# common/link_security.py
def wrap_link_secure(session: LinkSession, link_sender_nid: str, inner_message: Dict) -> Dict:
    session.send_seq += 1
    mac = HMAC(session.key, SHA256).update(canonical_json(header)).finalize()
    return {"type": "LINK_SECURE", "seq": session.send_seq, "payload_b64": payload, "mac_b64": mac}

def unwrap_link_secure(session: LinkSession, secure_msg: Dict) -> Optional[Dict]:
    if seq <= session.recv_max_seq:  # Anti-replay
        return None
    # Verificar MAC
    mac.verify(tag)
    session.recv_max_seq = seq
    return inner
```

### 4.6. Serviço Inbox End-to-End com DTLS-like (Secção 5.7)

**Implementação:** Canal seguro end-to-end entre Node e Sink:

**Handshake (DTLS-like):**
1. `E2E_HELLO1`: Node → Sink (cert, eph_pub, nonce, client_id, sig)
2. `E2E_HELLO2`: Sink → Node (cert, eph_pub, nonce, sig)
3. Derivação: `e2e_key = HKDF(ECDH, nonces, client_id)`

**Record Layer:**
- **AES-256-GCM** para confidencialidade + integridade
- Número de sequência para anti-replay
- Routers apenas adicionam/removem MAC por-link

```python
# common/e2e_security.py
def wrap_e2e_record(session: E2ESession, plaintext_obj: Dict) -> Dict:
    session.send_seq += 1
    ct = AESGCM(session.key).encrypt(nonce, plaintext, aad)
    return {"type": "E2E_RECORD", "client_id": session.client_id, "seq": seq, "ct_b64": ct}

def unwrap_e2e_record(session: E2ESession, record: Dict) -> Optional[Dict]:
    if seq <= session.recv_max_seq:
        return None
    pt = AESGCM(session.key).decrypt(nonce, ct, aad)
    return json.loads(pt)
```

**Justificativa para DTLS-like (não DTLS padrão RFC 6347):**
- DTLS completo é complexo e inclui features desnecessárias para este caso (negociação de cipher suites, retransmissões/timers, alerts, compatibilidade wire-format)
- Nossa implementação fornece as garantias essenciais exigidas pelo enunciado:
  - ✅ Autenticação end-to-end com certificados X.509
  - ✅ Confidencialidade (AES-GCM)
  - ✅ Integridade (GCM tag)
  - ✅ Anti-replay (número de sequência)
  - ✅ Routers não processam DTLS, apenas encaminham payloads


## 🎁 5. Feature Bónus - Múltiplos Sinks (+10%)

**Implementação:** Suporte para cenário com múltiplos Sinks na rede.

**Funcionalidade:**
- Node deteta mudança de Sink comparando `source_nid` do heartbeat
- Sessões E2E são **invalidadas automaticamente** quando o Sink muda
- Novas sessões E2E são estabelecidas com o novo Sink

```python
# node/iot_node.py
def _check_sink_change(self, heartbeat_msg: Dict) -> bool:
    hb_source_nid = heartbeat_msg.get("source_nid")
    
    if hb_source_nid != self._current_network_sink_nid:
        print(f"[{self.name}] ⚠️ SINK MUDOU: {self._current_network_sink_nid[:8]}... → {hb_source_nid[:8]}...")
        
        # Invalidar sessões E2E com Sink antigo
        old_sessions = [k for k in self.e2e_sessions.keys() 
                       if k[0] == self._current_network_sink_nid]
        for session_key in old_sessions:
            del self.e2e_sessions[session_key]
        
        self._current_network_sink_nid = hb_source_nid
        return True
    return False
```

**Justificativa:**
- Em ambientes IoT reais, Sinks podem falhar ou ser substituídos
- Nodes devem adaptar-se automaticamente sem intervenção manual
- Sessões DTLS devem ser invalidadas pois as chaves foram derivadas com o Sink anterior


## 🎮 6. Controlos de Rede (Secção 4)

### Comandos Disponíveis

| Comando | Descrição | Secção |
|---------|-----------|--------|
| `scan [secs]` | Procura dispositivos vizinhos e mostra hop count | 4 |
| `connect <idx\|nid>` | Conecta a um dispositivo como uplink | 4 |
| `disconnect` | Desconecta do uplink atual | 4 |
| `stop_hb <nid>` | Para heartbeat para um downlink específico | 4 |
| `start_hb <nid>` | Retoma heartbeat para um downlink | 4 |
| `blocked_hb` | Lista downlinks com heartbeat bloqueado | 4 |
| `status` | Mostra estado completo do dispositivo | 6 |
| `inbox` | Mostra mensagens Inbox recebidas (Sink) | 6 |
| `send_inbox <text>` | Envia mensagem Inbox end-to-end (Node) | 5.7 |
| `help` | Mostra ajuda dos comandos | - |
| `quit` | Encerra o programa | - |


## 📋 7. Interface de Utilizador (Secção 6)

A interface mostra todas as informações requeridas:

```
╔══════════════════════════════════════════════════════════════╗
║               NODE A STATUS                                   ║
╠══════════════════════════════════════════════════════════════╣
║ NID: a1b2c3d4-e5f6-7890-abcd-ef1234567890                    ║
║ Hop Count: 1                                                  ║
║ Uplink: ✅ 44c7f5ca-1234-5678-9abc-def012345678              ║
║   └─ Sessão de link: Estabelecida (seq: 42)                  ║
╠══════════════════════════════════════════════════════════════╣
║ Downlinks (2):                                                ║
║   ✅ b328a1c9-... (hop 2, sessão OK)                         ║
║   🚫 77777777-... (heartbeat BLOQUEADO)                      ║
╠══════════════════════════════════════════════════════════════╣
║ Forwarding Table (2 entradas):                                ║
║   b328a1c9... → via b328a1c9... (downlink)                   ║
║   77777777... → via 77777777... (downlink)                   ║
╠══════════════════════════════════════════════════════════════╣
║ Lost Heartbeats: 0/3                                          ║
║ Messages Routed (Up/Down): 15 / 8                             ║
║ E2E Sessions: 1 ativa                                         ║
╚══════════════════════════════════════════════════════════════╝
```


## 🛠 8. Instruções de Execução

### Pré-requisitos

- Python 3.9+
- Linux com BlueZ 5.50+ (recomendado para BLE completo)
- Adaptador Bluetooth Low Energy

### Instalação

```bash
# Criar ambiente virtual
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# ou: venv\Scripts\activate  # Windows

# Instalar dependências
pip install -r requirements.txt
```

### Gerar Certificados (Obrigatório antes de executar)

```bash
python support/ca_manager.py
```

Isto gera:
- `support/certs/ca_cert.pem` - Certificado da CA
- `support/certs/ca_key.pem` - Chave privada da CA
- `support/certs/sink_*` - Certificados do Sink
- `support/certs/node_*` - Certificados dos Nodes

### Executar o Sink

```bash
# Sink interativo com todos os controlos (RECOMENDADO)
python sync/sink_runtime.py --adapter hci0

# Ou apenas o loop de heartbeat automático
python sync/sink_app.py --adapter hci0
```

### Executar um Node

```bash
# Node interativo
python node/node_runtime.py --name "Node A" --adapter hci1

# Executar mais nodes em terminais separados
python node/node_runtime.py --name "Node B" --adapter hci2
python node/node_runtime.py --name "Node C" --adapter hci3
```

### Cenário de Teste Típico

**Terminal 1 - Sink:**
```bash
python sync/sink_runtime.py --adapter hci0
> scan 5           # Procurar nodes
> status           # Ver estado
```

**Terminal 2 - Node A:**
```bash
python node/node_runtime.py --name "Node A" --adapter hci1
> scan 5           # Procurar Sink
> connect 0        # Conectar ao Sink
> status           # Verificar conexão
> send_inbox "Olá do Node A"  # Enviar mensagem E2E
```

**Terminal 1 - Sink (ver mensagem):**
```bash
> inbox            # Ver mensagem recebida
```


## 🧪 9. Testes

```bash
# Verificar dependências
python scripts/check_dependencies.py

# Teste rápido de scanning BLE
python examples/quick_ble_test.py

# Teste completo de conexão BLE
python examples/test_ble_connection.py

# Teste de Node interativo
python examples/device_node.py
```


## ❌ 10. Limitações Conhecidas

| Funcionalidade | Estado | Notas |
|----------------|--------|-------|
| DTLS padrão RFC 6347 | ⚠️ DTLS-like | Implementação própria com mesmas garantias |
| BLE Advertising | ⚠️ Linux only | Requer BlueZ + dbus-next |
| BLE Mesh | ❌ N/A | Explicitamente proibido pelo enunciado |


## 📚 11. Dependências

Ver `requirements.txt`:

```
bleak>=0.21.0           # BLE scanning/connection
cryptography>=41.0.0    # X.509, ECDSA, ECDH, AES-GCM
dbus-next>=0.2.3        # BlueZ D-Bus (Linux)
```


## 📖 12. Referências

1. Bluetooth Core Specification v5.3
2. RFC 6347 - Datagram Transport Layer Security Version 1.2
3. RFC 5246 - The Transport Layer Security (TLS) Protocol Version 1.2
4. NIST SP 800-56A Rev. 3 - Recommendation for Pair-Wise Key-Establishment Schemes
5. Bleak Documentation - https://bleak.readthedocs.io/
6. Python cryptography library - https://cryptography.io/


---
*SIC Project - Segurança Informática e nas Comunicações 2024/2025*
