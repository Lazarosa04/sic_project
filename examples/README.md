# 📂 Exemplos BLE - Projeto SIC

Este diretório contém scripts de exemplo e teste para as funcionalidades BLE do projeto.

---

## 📄 Arquivos

### `quick_ble_test.py`
**Teste rápido de scanning BLE (3 segundos)**

```bash
python3 examples/quick_ble_test.py
```

**O que faz:**
- Inicializa BLE Manager
- Executa scanning BLE por 3 segundos
- Lista dispositivos descobertos

**Ideal para:**
- Verificar se o adaptador BLE está funcionando
- Teste rápido antes de executar aplicações completas
- Diagnóstico de problemas de hardware

---

### `test_ble_connection.py`
**Suite completa de testes BLE**

```bash
python3 examples/test_ble_connection.py
```

**Testes incluídos:**
1. **Scanning BLE** (8 segundos) - Descoberta de dispositivos
2. **Conexão** - Node → Sink
3. **Desconexão** - Encerramento limpo
4. **Envio de Mensagens** - DTLS Inbox seguro
5. **Broadcast** - Heartbeat para Downlinks

**Ideal para:**
- Validação completa do sistema BLE
- Testes antes de deployment
- Demonstração de funcionalidades

---

## 🚀 Como Usar

### Preparação

1. **Instalar dependências:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Gerar certificados:**
   ```bash
   python3 support/ca_manager.py
   ```

3. **Verificar Bluetooth:**
   - Linux: `hciconfig`
   - Windows: Configurações → Bluetooth
   - macOS: Preferências do Sistema → Bluetooth

### Execução

#### Teste Rápido
```bash
# Do diretório raiz do projeto
python3 examples/quick_ble_test.py
```

#### Teste Completo
```bash
# Do diretório raiz do projeto
python3 examples/test_ble_connection.py
```

---

## 📊 Saídas Esperadas

### Quick BLE Test

**Com dispositivos BLE:**
```
✅ SUCESSO! 2 dispositivo(s) encontrado(s):
  • 44c7f5ca-bda5-458c-bfad-7cd2075cf862 (Hop: 0)
  • b328a1c9-1a73-45f8-84e0-77a8d5f47c0d (Hop: 1)
```

**Sem dispositivos BLE:**
```
⚠️ Nenhum dispositivo BLE encontrado.
[INFO] Isso é esperado se não houver dispositivos BLE ativos próximos.
```

### Test BLE Connection

```
==================================================
 TESTE 1: SCANNING BLE - DESCOBERTA DE DISPOSITIVOS
==================================================

[BLE] Iniciando scanning por 8s...
[BLE] Descoberto: 44c7f5ca... (Hop: 0, RSSI: -45)
[BLE] Scanning completo. 1 dispositivos encontrados.

[TEST] ✅ 1 dispositivos descobertos:
  • 44c7f5ca... (Hop Count: 0)

...
```

---

## 🐛 Troubleshooting

### Erro: "No module named 'bleak'"
```bash
pip install bleak
```

### Erro: "No BLE adapter found"
**Linux:**
```bash
hciconfig
sudo hciconfig hci0 up
```

**Windows/macOS:**
- Verificar se Bluetooth está ativado

### Nenhum dispositivo descoberto
- Verificar se há outros dispositivos BLE transmitindo
- Aumentar distância entre dispositivos (< 10 metros)
- Executar o Sink em outro dispositivo

---

## 💡 Dicas

### Executar em múltiplos dispositivos

**Dispositivo 1 (Sink):**
```bash
python3 sink/sink_app.py
```

**Dispositivo 2 (Node - teste):**
```bash
python3 examples/quick_ble_test.py
```

### Debug detalhado
Editar script e adicionar:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Aumentar tempo de scanning
Editar `quick_ble_test.py`:
```python
devices = await manager.scan_for_uplinks(duration=10.0)  # 10 segundos
```

---

## 📚 Documentação Adicional

- **Guia Completo BLE**: `../docs/BLE_GUIDE.md`
- **Quick Start**: `../QUICK_START.md`
- **README Principal**: `../README.md`

---

**Última atualização**: 16 de Dezembro de 2025
