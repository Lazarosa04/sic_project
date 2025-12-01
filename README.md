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

* **`common/`**: Código partilhado entre o Sink e os Nodes: Lógica de empacotamento de rede, **Heartbeat**, Funções de Assinatura/Verificação e **Serviço DTLS** (`heartbeat.py`, `dtls_service.py`, `network_utils.py`).
* **`node/`**: Lógica da aplicação do dispositivo IoT/Roteador (`iot_node.py`), incluindo Descoberta, Roteamento, Liveness e Envio de Serviços.
* **`sink/`**: Lógica da aplicação do host central (`sink_host.py`), para Assinatura de Heartbeat, Carregamento de Chaves e Processamento de Serviços Seguros (Inbox).
* **`support/`**: Ferramentas de suporte não utilizadas durante a operação da rede, como a **Autoridade Certificadora (CA)** e a geração de certificados de identidade (`ca_manager.py`).

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

## ❌ 5. Funcionalidades Não Implementadas ou Parcialmente

* **Implementação BLE real:** A camada de comunicação Bluetooth de Baixa Energia (BLE) com `bleak` não está implementada (substituída por funções assíncronas e simulações de I/O) devido à indisponibilidade inicial do hardware.
* **Múltiplos Sinks:** Não implementado. O sistema assume um único Sink.

---

## 🛠 Instruções de Execução (Testes Lógicos)

O sistema deve ser executado a partir do diretório raiz (`~/sic_project`) com o `venv` ativado.

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
