# Quick Start V2

## Setup Inicial

```bash
# Criar venv
python3 -m venv .venv

# Ativar
source .venv/bin/activate.fish  # fish
# ou: source .venv/bin/activate  # bash/zsh

# Instalar dependências
pip install -r requirements.txt
```

## Gerar Certificados

```bash
# Criar CA e certificados para dispositivos
python support/generate_devices.py --devices "Device A" "Device B" "Device C"
```

Isso cria:
- `support/certs/ca_cert.pem` - CA raiz
- `support/certs/ca_key.pem` - CA private key
- `support/certs/device_a/` - cert + key para Device A
- `support/certs/device_b/` - cert + key para Device B
- `support/certs/device_c/` - cert + key para Device C

## Executar Sink

```bash
python sink/sink_app.py --adapter hci0
```

## Executar Device Nodes

Terminal 1:
```bash
python examples/device_node.py --name "Device A" --adapter hci1
```

Terminal 2:
```bash
python examples/device_node.py --name "Device B" --adapter hci2
```

Terminal 3:
```bash
python examples/device_node.py --name "Device C" --adapter hci3
```

## Conectar Devices

No prompt interativo de cada device:

```
scan 10          # Scan por 10 segundos
connect 0        # Conectar ao device índice 0
status           # Ver estado da conexão
debug on         # Ativar logs de debug (opcional)
```

## Topologia Exemplo

```
Sink (hci0)
  ├─ Device A (hci1) ← conectado ao Sink
  └─ Device B (hci2) ← conectado ao Sink
       └─ Device C (hci3) ← conectado ao Device B
```

## Comandos Úteis

```bash
# Verificar adaptadores BLE disponíveis
hciconfig

# Reset adapter se necessário
sudo hciconfig hci0 down
sudo hciconfig hci0 up

# Ver logs detalhados do BlueZ
sudo journalctl -u bluetooth -f
```

## Troubleshooting

**Erro "No such adapter":**
```bash
hciconfig  # Verificar nome correto do adapter
```

**Erro "Permission denied":**
```bash
# Adicionar user ao grupo bluetooth
sudo usermod -a -G bluetooth $USER
# Logout/login necessário
```

**Certificado não encontrado:**
```bash
# Re-gerar certificados
python support/generate_devices.py --devices "Device A" "Device B"
```

**Multiple Characteristics error:**
- Já corrigido no código (usa characteristic object em vez de UUID string)
