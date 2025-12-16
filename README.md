# 📜 README.md: SIC Project - Bluetooth-based, Secure Ad-hoc Network for IoT Devices

## 👤 1. Identificação do Grupo e Contribuição

| Número | Nome do Autor | Contribuição Percentual (%) |
| :--- | :--- | :--- |
| [115931] | [Joaquim Martins] | [Ex: 25%] |
| [115884] | [Lázaro Sá] | [Ex: 25%] |
| [112657] | [Ricardo Carmo] | [Ex: 25%] |
| [115359] | [Daniel Oliveira] | [Ex: 25%] |

---

## 🏗 2. Estrutura e Organização do Código

O projeto está organizado em módulos Python seguindo a divisão lógica e os requisitos de entrega:

### Estrutura de Diretórios

```
sic_project/
├── common/              # Código partilhado
│   ├── ble_manager.py   # ✨ Gerenciador BLE (scanning, conexão, desconexão)
│   ├── dtls_service.py  # Serviço DTLS Inbox (assinatura end-to-end)
│   ├── heartbeat.py     # Heartbeat com assinatura digital
│   └── network_utils.py # Utilitários de rede (Advertisement Data)
│
├── node/                # Lógica do Node IoT
│   └── iot_node.py      # Node IoT/Roteador (descoberta, roteamento, liveness)
│
├── sink/                # Lógica do Sink
│   ├── sink_host.py     # Sink Host (processamento de mensagens seguras)
│   └── sink_app.py      # Aplicação Sink (Heartbeat periódico)
│
├── support/             # Ferramentas de suporte
│   ├── ca_manager.py    # Autoridade Certificadora (geração de certificados)
│   └── certs/           # Certificados e chaves geradas
│
├── examples/            # Scripts de teste
│   ├── quick_ble_test.py        # Teste rápido de BLE
│   ├── test_ble_connection.py   # Suite completa de testes BLE
│   └── README.md                # Documentação dos exemplos
│
├── scripts/             # Scripts utilitários
│   └── check_dependencies.py    # Verificação de dependências
│
├── docs/                # Documentação
│   └── BLE_GUIDE.md     # Guia completo de implementação BLE
│
├── requirements.txt     # Dependências do projeto
├── Makefile            # Comandos facilitadores
├── QUICK_START.md      # Guia de início rápido
├── IMPLEMENTATION_SUMMARY.md  # Resumo de implementação
└── README.md           # Este arquivo
```

### Descrição dos Módulos

* **`common/`**: Código partilhado entre o Sink e os Nodes
  * `ble_manager.py`: Gerenciador BLE completo (scanning, conexão, desconexão)
  * `dtls_service.py`: Serviço DTLS Inbox
  * `heartbeat.py`: Heartbeat com assinatura digital
  * `network_utils.py`: Utilitários de rede

* **`node/`**: Lógica da aplicação do dispositivo IoT/Roteador
  * `iot_node.py`: Descoberta, Roteamento, Liveness e Envio de Serviços

* **`sink/`**: Lógica da aplicação do host central
  * `sink_host.py`: Processamento de Serviços Seguros (Inbox)
  * `sink_app.py`: Loop de Heartbeat periódico

* **`support/`**: Ferramentas de suporte
  * `ca_manager.py`: Autoridade Certificadora e geração de certificados

---

## ⚙️ 3. Funcionalidades Implementadas e Justificativa (20%)

### 3.1. Topologia em Árvore e Descoberta de Uplink 🌳

* **Implementação:** O Node determina o melhor Uplink (próximo salto) através de uma simulação de *scanning* do *Advertisement Payload* (codificado com o **NID** e o **Hop Count**).
* **Justificativa (Abordagem Lazy):** A função `choose_uplink()` segue a abordagem **lazy** (Secção 3): o Node seleciona o vizinho com o **menor Hop Count** até o Sink (ex: Hop 0 é preferido a Hop 1) e **mantém** essa conexão para evitar renegociações constantes.

### 3.2. Roteamento e Tabela de Encaminhamento (FT)

* **Implementação:** A classe `IoTNode` utiliza uma **Tabela de Encaminhamento (FT)**.
* **Justificativa (Modelo Switch):** Seguimos o modelo de *switch* (Secção 3.1):
    1.  **Aprendizagem:** O Node **memoriza** o vizinho (`source_link_nid`) por onde a mensagem de um Nó final (`source_nid`) chegou, garantindo o caminho de **retorno** (Downstream).
    2.  **Roteamento Upstream:** O tráfego para o **Sink** é prioritário e encaminhado diretamente pelo **`self.uplink_nid`** (regra estática).

### 3.3. Liveness e Desconexão em Cadeia ❤️

* **Implementação:** O Node utiliza a função `check_liveness()` para monitorizar a perda de Heartbeats.
* **Justificativa:**
    * **Detecção de Falha:** O Uplink é considerado "down" após a perda de **3 Heartbeats** consecutivos.
    * **Reação em Cadeia:** Ao detetar a falha, o Node **imediatamente** chama `disconnect_uplink()`, que **quebra a conexão com todos os Downlinks** (Secção 3), forçando-os a reentrar na rede.

---

## 🛡️ 4. Opções e Justificativas de Segurança (50%)

A segurança é garantida por primitivas de criptografia baseadas em Curvas Elípticas.

### 4.1. Identificação e CA (Secção 5.1, 5.2, 5.3)

* **Escolha:** Utilizamos **ECDSA** com a curva **P-521** (`ec.SECP521R1`). O **NID** é extraído do campo **`USER_ID`** do certificado **X.509** .
* **Justificativa:** A curva P-521 oferece segurança criptográfica forte com baixo *overhead* computacional e de memória, essencial para dispositivos IoT. A CA garante que apenas dispositivos autorizados (com certificados assinados) podem participar na rede.

### 4.2. Serviço End-to-End Seguro (DTLS Inbox) (Secção 5.7)

* **Escolha:** Implementamos a lógica do serviço Inbox sobre uma camada de **Assinatura Digital de Aplicação** (`seal_inbox_message`/`unseal_inbox_message`).
* **Justificativa:**
    * **Autenticidade/Integridade:** O Node **assina** o *payload* do Inbox com sua chave privada. O Sink utiliza a chave pública do Node (obtida do seu certificado) para **verificar a assinatura**, garantindo que a mensagem não foi adulterada em trânsito e que a origem é quem diz ser.

### 4.3. Segurança do Heartbeat (Secção 3.2)

* **Escolha:** O Sink assina cada Heartbeat com sua chave privada. O Node verifica a assinatura.
* **Justificativa:** Garante **Autenticidade** e **Integridade** do sinal de liveness, impedindo que um nó malicioso falsifique o Heartbeat para manter a rede ativa ou causar falhas.

---

## ✅ 5. Implementação BLE (Bluetooth Low Energy)

### 5.1. BLE Manager (`common/ble_manager.py`)

* **Implementação:** Gerenciador completo de conexões BLE usando a biblioteca `bleak`.
* **Funcionalidades:**
    * **Scanning:** Descoberta de dispositivos vizinhos através de Advertisement Data
    * **Conexão:** Estabelecimento de conexões GATT com Uplinks e Downlinks
    * **Desconexão:** Encerramento controlado de conexões BLE
    * **Envio/Recebimento:** Comunicação bidirecional via características GATT customizadas
    * **Advertisement:** Broadcast de NID e Hop Count (requer APIs nativas da plataforma)

### 5.2. Características GATT Customizadas

* **Serviço SIC:** UUID `d227d8e8-d4d1-4475-a835-189f7823f64c`
* **Característica de Dados:** UUID `d227d8e8-d4d1-4475-a835-189f7823f64d` (Read/Write)
* **Característica de Notificações:** UUID `d227d8e8-d4d1-4475-a835-189f7823f64e` (Notify)

### 5.3. Advertisement Data Format

* **Manufacturer ID:** 0xFFFF (teste)
* **Payload:** NID (16 bytes) + Hop Count (4 bytes, little-endian)

### 5.4. Integração nos Nodes

* **IoTNode:** 
    * `find_uplink_candidates()` - Scanning BLE real
    * `connect_to_uplink()` - Conexão BLE ao melhor candidato
    * `disconnect_uplink()` - Desconexão BLE e limpeza de estado
    * `send_message_ble()` - Envio de mensagens via GATT

* **SinkHost:**
    * `send_heartbeat_ble()` - Broadcast de Heartbeat para Downlinks
    * Aceitação de conexões de múltiplos Nodes

### 5.5. Limitações e Notas

* **Advertisement Mode:** `bleak` não suporta modo peripheral/advertising. Para implementação completa:
    * Linux: Usar BlueZ D-Bus API diretamente
    * Windows: Windows.Devices.Bluetooth.Advertisement API
    * macOS: CoreBluetooth (suporte limitado)
* **Hardware:** Requer adaptador BLE e permissões adequadas do sistema
* **Testes:** Script `examples/test_ble_connection.py` demonstra todas as funcionalidades

## ❌ 6. Funcionalidades Não Implementadas ou Parcialmente

* **Advertisement nativo:** Requer integração com APIs específicas de plataforma (BlueZ/Windows/macOS)
* **Múltiplos Sinks:** Não implementado. O sistema assume um único Sink.

---

## 🛠 Instruções de Execução

O sistema deve ser executado a partir do diretório raiz (`~/sic_project`) com o `venv` ativado.

### Instalação de Dependências

```bash
# Criar ambiente virtual (se necessário)
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# ou: venv\Scripts\activate  # Windows

# Instalar dependências
pip install -r requirements.txt
```

### Testes

1.  **Geração de Identidades:** (Cria chaves, certificados e NIDs)
    ```bash
    python3 support/ca_manager.py
    ```

2.  **Teste de Roteamento/Liveness:** (Demonstra Failover e FT)
    ```bash
    python3 node/iot_node.py
    ```

3.  **Teste de Serviço Seguro (DTLS Inbox):** (Demonstra Assinatura/Verificação End-to-End)
    ```bash
    python3 sink/sink_host.py
    ```

4.  **Teste BLE Completo:** (Demonstra Scanning, Conexão e Desconexão BLE)
    ```bash
    python3 examples/test_ble_connection.py
    ```
    
    **Nota:** Para testes BLE reais, é necessário:
    - Adaptador Bluetooth Low Energy ativo
    - Permissões de sistema apropriadas
    - Múltiplos dispositivos com o código executando

5.  **Execução do Sink com Heartbeat:** (Inicia o Sink e envia Heartbeats periódicos)
    ```bash
    python3 sink/sink_app.py
    ```
