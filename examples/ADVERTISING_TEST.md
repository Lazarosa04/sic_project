**Como usar os exemplos BLE deste repositório**

Este documento explica, em português, como executar os exemplos de advertising e scanning BLE incluídos no repositório, bem como passos de diagnóstico úteis.

Pré-requisitos
- Linux com BlueZ instalado e serviço `bluetooth` a correr.
- Um ambiente Python (virtualenv). Por exemplo:
  ```fish
  python3 -m venv .venv
  . .venv/bin/activate.fish
  pip install -r requirements.txt
  ```
- Um adaptador BLE USB (ex.: `hci0`, `hci1`) ou um smartphone para scanning.

Principais ficheiros / scripts
- `examples/advertise_ble_example.py` — exemplo que regista um advertisement BlueZ (aceita `--adapter` e `--duration`).
- `examples/advertise_ble.py` — alternativa que pode usar `bless` (GATT server) ou instruções `bluetoothctl`.
- `examples/quick_ble_test.py` — scanner do projecto que procura por ManufacturerData com Company ID `0xFFFF` e formata (aceita `--adapter`, `--duration`, `--device-nid`).
- `examples/scan_debug.py` — scanner de diagnóstico que imprime todo o Manufacturer/Service data que chega (útil para ver o que realmente está no ar).
- `common/ble_advertiser_bluez.py` — utilitário que regista `org.bluez.LEAdvertisement1` com BlueZ.

Testes rápidos (recomendado: dois dispositivos)

1) Iniciar o advertiser (Device A)

No dispositivo que fará o advertising (p.ex. máquina com dongle `hci1`):
```fish
sudo .venv/bin/python3 examples/advertise_ble_example.py --adapter hci1 --duration 60
```

Saídas esperadas:
- `Preparing ManufacturerData: company=0xFFFF len=20 bytes payload=...`
- `Registering advertisement on BlueZ adapter /org/bluez/hci1`
- `Advertisement registered: NID=... Hop=...`

2) Fazer scanning (Device B ou telemóvel)

No outro dispositivo (ou num telemóvel com nRF Connect):
```fish
.venv/bin/python3 examples/scan_debug.py hci0 10
```

Procura por linhas que mostrem `Manufacturer Data` com `Company: 0xFFFF` ou o `local_name` `SIC-...`.

Testar com o scanner do projecto (filtrando e extraindo NID/hop):
```fish
sudo .venv/bin/python3 examples/quick_ble_test.py --adapter hci0 --duration 5 --device-nid 00000000-0000-0000-0000-000000000002
```

Notas importantes
- Muitos controladores não retornam os próprios pacotes de advertising quando se faz scanning a partir do mesmo adaptador. Por isso, se tentares correr advertiser e scanner no mesmo `hciX`, pode ser que o scanner não veja o próprio anúncio mesmo que o anúncio esteja a ser transmitido.
- Se não tiveres um segundo adaptador, usa um telemóvel com um app (p.ex. nRF Connect) para verificar o advertising.
- O script `scan_debug.py` ajuda a confirmar se a payload `0xFFFF` está mesmo no ar.

Comandos de diagnóstico úteis
- Ver adaptadores e estado:
  ```fish
  sudo hciconfig -a
  sudo btmgmt info
  sudo bluetoothctl list
  ```
- Ver tráfego HCI em bruto (mostrar anúncios transmitidos e recebidos):
  ```fish
  sudo btmon
  # ou filtrar procurando ManufacturerData 0xFFFF:
  sudo btmon |& grep --line-buffered -i "ff ff\|Company:\|65535"
  ```

Permissões (evitar usar `sudo`)
- Em muitos casos será mais simples usar `sudo` para correr os scripts que interagem com BlueZ. Se preferires não usar `sudo`, podes dar `cap_net_raw` ao binário Python do ambiente virtual (ou ao sistema python). Exemplos (use com cuidado):
  ```fish
  sudo setcap cap_net_raw+eip $(which python3)
  ```

Formato esperado do ManufacturerData (especificação do projecto)
- Company ID: `0xFFFF` (2 bytes)
- Payload: 20 bytes = 16 bytes UUID (NID) + 4 bytes HopCount (int32 little-endian)

Exemplo de payload (NID `00000000-0000-0000-0000-000000000001`, hop=1):
```
00000000000000000000000000000101000000
```

Problemas comuns
- `interface "org.bluez.LEAdvertisement1" does not have property "TxPower"`: aviso do D-Bus/dbus-next; benigno na maior parte dos casos e não impede o registo do advertisement.
- `No devices found` no `quick_ble_test.py`: verifique se o advertiser está activo noutro dispositivo, se o `--adapter` está correcto e se o `device-nid` passado ao scanner não faz com que ele ignore o anúncio.

Queres que eu adicione este ficheiro também ao `README.md` ou que crie uma versão em `docs/`? Se preferires, adapto o texto para outro formato (ex.: inglês) ou adiciono exemplos extra (polkit, systemd service, automatização).
