# Usar `ca_manager` e `generate_devices` (Guia)

Este documento descreve como gerar a Autoridade Certificadora (CA), criar certificados individuais para o `Sink` e múltiplos dispositivos, e usar o utilitário `generate_devices.py` incluído no repositório.

Local dos scripts
- `support/ca_manager.py` — utilitário para gerar a CA raiz e certificados individuais.
- `support/generate_devices.py` — utilitário para gerar vários dispositivos em lote.

Requisitos
- Python 3.10+ e dependências do projeto instaladas no venv (veja `requirements.txt`).

Preparar ambiente
1. Criar e ativar venv (exemplo usando fish shell):

```fish
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

2. (Opcional) garantir permissões para executar operações BLE sem sudo:

```fish
sudo setcap cap_net_raw+eip $(which python3)
```

Gerar CA e certificados de exemplo
1. Executar o gerador de CA/Device que já contém comportamento padrão:

```fish
./venv/bin/python3 support/ca_manager.py
```

Isso irá gerar (se não existirem):
- `support/certs/ca_private.pem` (chave privada da CA — protegida por password definida em `ca_manager.py`)
- `support/certs/ca_certificate.pem` (certificado público da CA)
- `support/certs/sink_host_private.pem` e `support/certs/sink_host_certificate.pem`
- `support/certs/node_a_private.pem` e `support/certs/node_a_certificate.pem`

Gerar certificados adicionais com `generate_devices.py`
O utilitário `generate_devices.py` facilita criar múltiplos dispositivos de forma repetível.

Exemplos:

- Gerar dispositivos nomeados explicitamente (pula os já existentes):

```fish
./venv/bin/python3 support/generate_devices.py --names "Node B,Node C,Node D"
```

- Gerar `count` dispositivos com um prefixo:

```fish
./venv/bin/python3 support/generate_devices.py --count 3 --prefix "Device"
# cria: Device 1, Device 2, Device 3
```

- Gerar 5 dispositivos começando em índice 10 e com OU personalizado:

```fish
./venv/bin/python3 support/generate_devices.py --count 5 --prefix "Sensor" --start 10 --ou "Sensor Unit"
```

Como o script funciona (breve)
- `generate_devices.py` chama `gerar_ca_raiz()` para garantir que a CA existe (gera se necessário).
- Para cada nome solicitado, chama `gerar_certificado_dispositivo()` em `ca_manager.py`.
- Se os ficheiros de certificado já existem em `support/certs/` para o nome amigável (nome normalizado), o script pula a geração para evitar sobrescrever.

Encontrar o NID (UUID) gerado
- Cada certificado tem um atributo `USER_ID` (OID `NameOID.USER_ID`) contendo o NID (UUID) do dispositivo.
- Para verificar rapidamente o NID de um certificado:

```fish
openssl x509 -in support/certs/node_b_certificate.pem -noout -subject
```

ou via Python:

```fish
./venv/bin/python3 - <<'PY'
from cryptography import x509
crt = x509.load_pem_x509_certificate(open('support/certs/node_b_certificate.pem','rb').read())
print(crt.subject)
PY
```

Boas práticas
- Não commitar `support/certs/ca_private.pem` ou chaves privadas no controle de versão.
- Fazer backups seguros da chave da CA (`ca_private.pem`), pois é necessária para gerar/validar certificados.
- Considere mudar a senha `CA_PASSWORD` em `support/ca_manager.py` antes de usar em ambientes com múltiplos utilizadores.

Problemas comuns
- "property is readonly" (dbus-next): Mensagem de erro do `dbus-next` que pode aparecer em ambientes BlueZ/D-Bus; normalmente não afeta a geração de certificados, mas indica interação com o D-Bus no ambiente (ignore para este tópico).
- Permissões BLE/D-Bus: Para rodar scripts que operam BLE localmente (advertising/GATT) você pode precisar de permissões (veja setcap/sudo acima).

Próximos passos sugeridos
- Se quiser, eu posso adicionar uma pequena CLI `scripts/new_device_cert.py` que aceita `--name` e gera diretamente (com prompts e confirmação), ou
- Adicionar uma flag `--force` no `generate_devices.py` para sobrescrever identidades existentes (apenas se você quiser regenerar).

---
Se quiser que eu gere agora um certificado para um device específico (ex.: "Device 2"), diga o nome e eu executo o comando aqui e retorno os paths e o NID.
