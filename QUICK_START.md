# 🚀 Guia de Início Rápido - BLE Projeto SIC

## 📋 Pré-requisitos

### Hardware
- ✅ Adaptador Bluetooth Low Energy (BLE 4.0+)
- ✅ 2 ou mais dispositivos com BLE para testes de rede

### Software
- ✅ Python 3.8 ou superior
- ✅ Bluetooth ativado no sistema operacional

---

## 🔧 Instalação

### Passo 1: Clonar/Navegar para o projeto
```bash
cd PATH_TO_PROJECT
```

### Passo 2: Criar ambiente virtual (recomendado)
```bash
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# ou: venv\Scripts\activate  # Windows
```

### Passo 3: Instalar dependências
```bash
pip install -r requirements.txt
```

### Passo 4: Verificar instalação do Bleak
```bash
python3 -c "import bleak; print('Bleak instalado:', bleak.__version__)"
#ou python3 -m pip show bleak
```

---

## 🔐 Configuração de Identidades

### Gerar Certificados e NIDs
```bash
python3 support/ca_manager.py
```

**Saída esperada:**
```
--- Gerenciador da Autoridade Certificadora (CA) do Projeto SIC ---
[CA] Chave Privada e Certificado da CA gerados...
[CERT] Sink Host gerado e assinado pela CA.
[CERT] NID: 44c7f5ca-bda5-458c-bfad-7cd2075cf862
[CERT] Node A gerado e assinado pela CA.
[CERT] NID: b328a1c9-1a73-45f8-84e0-77a8d5f47c0d
```

---

## 🧪 Testes BLE

### Teste 1: Verificação Rápida de Scanning

```bash
python3 examples/quick_ble_test.py
```

**O que faz:**
- Inicializa BLE Manager
- Executa scanning por 3 segundos
- Lista dispositivos BLE encontrados

**Resultado esperado:**
- ✅ Se houver dispositivos BLE: Lista com NIDs e Hop Counts
- ⚠️ Se não houver dispositivos: Mensagem informativa

### Teste 2: Suite Completa BLE

```bash
python3 examples/test_ble_connection.py
```

**Testes executados:**
1. Scanning BLE (8 segundos)
2. Conexão Node → Sink (simulado)
3. Desconexão BLE
4. Envio de mensagens seguras (DTLS Inbox)
5. Broadcast de Heartbeat

---

## 🌐 Execução da Rede

### Cenário 1: Teste Local (Simulação)

#### Terminal 1 - Sink
```bash
python3 sink/sink_app.py
```

**Saída esperada:**
```
[Sink Host] Inicializado. NID: 44c7f5ca-bda5-458c-bfad-7cd2075cf862
[Sink Host] Pronto para enviar Heartbeats a cada 5s.
[Sink Host][HB:1] Enviando Heartbeat assinado para 0 Downlinks.
```

#### Terminal 2 - Node A
```bash
python3 node/iot_node.py
```

**Saída esperada:**
```
[Node A] Inicializado. NID: b328a1c9-1a73-45f8-84e0-77a8d5f47c0d
[Node A] Hop Count: -1
[Node A] Iniciando Descoberta BLE de Uplink...
```

### Cenário 2: Teste com Hardware Real (2+ Dispositivos)

#### Dispositivo 1 (Raspberry Pi, Linux) - Sink
```bash
# 1. Verificar adaptador BLE
hciconfig

# 2. Ativar BLE (se necessário)
sudo hciconfig hci0 up

# 3. Dar permissões
sudo setcap cap_net_raw+eip $(which python3)

# 4. Executar Sink
python3 sink/sink_app.py
```

#### Dispositivo 2 (Laptop, Linux/Windows) - Node
```bash
# 1. Ativar Bluetooth nas configurações

# 2. Executar Node
python3 node/iot_node.py
```

**Fluxo esperado:**
1. Node escaneia e descobre Sink (Hop=0)
2. Node conecta ao Sink via BLE
3. Node atualiza Hop Count para 1
4. Sink envia Heartbeat
5. Node verifica assinatura do Heartbeat
6. Comunicação estabelecida

---

## 🐛 Troubleshooting

### Problema: "No BLE adapter found"

**Linux:**
```bash
# Verificar adaptador
hciconfig

# Instalar BlueZ (se ausente)
sudo apt-get update
sudo apt-get install bluez

# Reiniciar serviço Bluetooth
sudo systemctl restart bluetooth
```

**Windows:**
- Abrir Configurações → Dispositivos → Bluetooth
- Verificar se Bluetooth está "Ligado"
- Verificar Gerenciador de Dispositivos para drivers BLE

**macOS:**
- Abrir Preferências do Sistema → Bluetooth
- Verificar se Bluetooth está "Ligado"

### Problema: "Permission denied" (Linux)

```bash
# Opção 1: Dar permissões ao Python
sudo setcap cap_net_raw+eip $(which python3)

# Opção 2: Executar como root (não recomendado)
sudo python3 script.py

# Opção 3: Adicionar usuário ao grupo bluetooth
sudo usermod -a -G bluetooth $USER
# Depois fazer logout/login
```

### Problema: "Nenhum dispositivo descoberto"

**Verificações:**
1. ✅ Bluetooth está ativado?
2. ✅ Adaptador BLE está funcionando? (`hciconfig` no Linux)
3. ✅ Há outros dispositivos BLE transmitindo?
4. ✅ Os dispositivos estão próximos (< 10 metros)?
5. ✅ Não há interferência excessiva?

**Teste manual de scanning (Linux):**
```bash
sudo bluetoothctl
scan on
# Aguardar alguns segundos
# Deve listar dispositivos BLE próximos
```

### Problema: "Connection timeout"

**Possíveis causas:**
- Dispositivo muito distante
- Interferência de sinal
- Muitos dispositivos BLE na área
- Advertisement não está ativo no dispositivo alvo

**Solução:**
- Aproximar dispositivos
- Aumentar `timeout` no código: `await client.connect(timeout=20.0)`
- Reduzir interferências

---

## 📊 Verificação de Status

### Verificar Identidades Geradas
```bash
ls -la support/certs/
```

**Arquivos esperados:**
```
ca_certificate.pem
ca_private.pem
sink_host_certificate.pem
sink_host_private.pem
node_a_certificate.pem
node_a_private.pem
```

### Verificar Bibliotecas Instaladas
```bash
pip list | grep -E "bleak|cryptography"
```

**Saída esperada:**
```
bleak                 0.21.x
cryptography          41.x.x
```

### Verificar Bluetooth (Linux)
```bash
# Status do serviço
systemctl status bluetooth

# Informações do adaptador
hciconfig -a

# Versão BlueZ
bluetoothctl --version
```

---

## 🎯 Comandos Úteis

### Limpar Certificados e Regenerar
```bash
rm -rf support/certs/*
python3 support/ca_manager.py
```

### Testar Apenas Heartbeat
```bash
python3 common/heartbeat.py
```

### Testar Apenas DTLS
```bash
python3 sink/sink_host.py
```

### Testar Roteamento e Liveness
```bash
python3 node/iot_node.py
```

---

## 📈 Próximos Passos

Após validar o funcionamento básico:

1. **Adicionar mais Nodes**: Gerar certificados para Node B, Node C, etc.
   ```bash
   # Editar support/ca_manager.py para adicionar mais nodes
   python3 support/ca_manager.py
   ```

2. **Testar Topologia em Árvore**: 
   - Sink (Hop 0)
   - Node A conectado ao Sink (Hop 1)
   - Node B conectado ao Node A (Hop 2)

3. **Testar Failover**:
   - Desligar Sink
   - Observar nodes detectarem perda de Heartbeat
   - Observar reentrada na rede

4. **Integrar com Serviços**:
   - Desenvolver serviços customizados além do Inbox
   - Adicionar sensores reais nos nodes

---

## 📚 Documentação Adicional

- **Guia Completo BLE**: `docs/BLE_GUIDE.md`
- **Resumo de Implementação**: `IMPLEMENTATION_SUMMARY.md`
- **README Principal**: `README.md`

---

## 💡 Dicas de Desenvolvimento

### Debug Mode
Adicionar prints detalhados:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Aumentar Scan Duration
Para ambientes com muitos dispositivos:
```python
candidates = await node.find_uplink_candidates(scan_duration=10.0)
```

### Monitorar Tráfego BLE (Linux)
```bash
# Instalar Wireshark com suporte BLE
sudo apt-get install wireshark

# Capturar tráfego Bluetooth
sudo wireshark
# Selecionar interface: bluetooth0 ou similar
```

---

## ✅ Checklist de Validação

Antes de considerar o sistema funcional:

- [ ] Dependências instaladas (`pip install -r requirements.txt`)
- [ ] Certificados gerados (`support/ca_manager.py`)
- [ ] Adaptador BLE funcionando (`hciconfig` ou equivalente)
- [ ] Teste rápido passou (`quick_ble_test.py`)
- [ ] Suite de testes passou (`test_ble_connection.py`)
- [ ] Sink executa sem erros (`sink_app.py`)
- [ ] Node escaneia e descobre dispositivos (`iot_node.py`)
- [ ] Heartbeat é recebido e verificado
- [ ] Mensagens DTLS Inbox funcionam

---

## 🆘 Suporte

Se encontrar problemas:

1. Consultar `docs/BLE_GUIDE.md` para detalhes técnicos
2. Verificar logs de erro
3. Testar com `quick_ble_test.py` isoladamente
4. Verificar configurações de hardware/SO

---

**Última atualização**: 16 de Dezembro de 2025
**Versão**: 1.0
