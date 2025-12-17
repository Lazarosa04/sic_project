#!/usr/bin/env python3
# examples/advertise_ble.py

"""
Script para fazer advertising BLE (anunciar sua presença).
Permite que outros dispositivos descubram este node via scanning.
"""

import asyncio
import uuid
import struct
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

from common.network_utils import SIC_SERVICE_UUID

# Tentar importar bless (pode não estar instalado)
try:
    from bless import BlessServer, BlessGATTCharacteristic, GATTCharacteristicProperties, GATTAttributePermissions
    BLESS_AVAILABLE = True
except ImportError:
    BLESS_AVAILABLE = False
    print("⚠️  Biblioteca 'bless' não instalada.")
    print("   Instale com: pip install bless")


# Constantes
SIC_MANUFACTURER_ID = 0xFFFF
SIC_DATA_CHARACTERISTIC_UUID = "d227d8e8-d4d1-4475-a835-189f7823f64d"


async def advertise_with_bless(device_nid: str, hop_count: int, duration: int = 30):
    """
    Faz advertising BLE usando a biblioteca bless.
    
    Args:
        device_nid: NID do dispositivo (UUID)
        hop_count: Hop count para anunciar
        duration: Duração do advertising em segundos
    """
    
    if not BLESS_AVAILABLE:
        print("❌ Não é possível fazer advertising sem a biblioteca 'bless'")
        return
    
    print(f"\n{'='*60}")
    print(f" ADVERTISING BLE - Bless ".center(60))
    print(f"{'='*60}\n")
    
    print(f"[ADV] NID: {device_nid[:8]}...")
    print(f"[ADV] Hop Count: {hop_count}")
    print(f"[ADV] Duração: {duration}s\n")
    
    # Construir manufacturer data
    nid_bytes = uuid.UUID(device_nid).bytes
    hop_bytes = struct.pack('<i', hop_count)
    manufacturer_data = nid_bytes + hop_bytes
    
    print(f"[ADV] Manufacturer Data ({len(manufacturer_data)} bytes):")
    print(f"      NID: {manufacturer_data[:16].hex()}")
    print(f"      Hop: {manufacturer_data[16:20].hex()}\n")
    
    # Criar servidor BLE
    server = BlessServer(name=f"SIC-Node-{device_nid[:4]}")
    
    # Adicionar serviço customizado
    await server.add_new_service(SIC_SERVICE_UUID)
    
    # Adicionar característica de dados
    char_flags = (
        GATTCharacteristicProperties.read |
        GATTCharacteristicProperties.write |
        GATTCharacteristicProperties.notify
    )
    
    await server.add_new_characteristic(
        SIC_SERVICE_UUID,
        SIC_DATA_CHARACTERISTIC_UUID,
        char_flags,
        b"SIC Data",
        GATTAttributePermissions.readable | GATTAttributePermissions.writeable
    )
    
    # Definir manufacturer data para advertising
    server.advertise_manufacturer_data(SIC_MANUFACTURER_ID, manufacturer_data)
    
    print(f"[ADV] ✅ Servidor GATT configurado")
    print(f"[ADV] Serviço: {SIC_SERVICE_UUID}")
    print(f"[ADV] Característica: {SIC_DATA_CHARACTERISTIC_UUID}\n")
    
    # Iniciar advertising
    print(f"[ADV] 📡 Iniciando advertising por {duration}s...")
    print(f"[ADV] Outros dispositivos podem escanear agora!\n")
    
    await server.start()
    
    print(f"[ADV] ✨ ADVERTISING ATIVO!")
    print(f"[ADV] Execute em outro terminal/dispositivo:")
    print(f"      python3 examples/quick_ble_test.py\n")
    
    # Manter advertising ativo
    await asyncio.sleep(duration)
    
    # Parar advertising
    print(f"\n[ADV] ⏸️  Parando advertising...")
    await server.stop()
    
    print(f"[ADV] ✅ Advertising encerrado.")


async def advertise_with_bluetoothctl(device_nid: str, hop_count: int):
    """
    Alternativa: Instruções para usar bluetoothctl nativo.
    """
    print(f"\n{'='*60}")
    print(f" ADVERTISING BLE - bluetoothctl (Manual) ".center(60))
    print(f"{'='*60}\n")
    
    print("⚠️  Para fazer advertising manualmente com bluetoothctl:\n")
    
    nid_bytes = uuid.UUID(device_nid).bytes
    hop_bytes = struct.pack('<i', hop_count)
    manufacturer_data = nid_bytes + hop_bytes
    
    # Converter para formato hex string
    hex_data = manufacturer_data.hex()
    
    print("1. Abrir bluetoothctl:")
    print("   $ sudo bluetoothctl\n")
    
    print("2. Entrar no menu de advertising:")
    print("   [bluetooth]# menu advertise\n")
    
    print("3. Definir manufacturer data:")
    print(f"   [bluetooth]# manufacturer 0xFFFF {hex_data}\n")
    
    print("4. Iniciar advertising:")
    print("   [bluetooth]# advertise on\n")
    
    print("5. Para parar:")
    print("   [bluetooth]# advertise off")
    print("   [bluetooth]# back\n")


async def main():
    """Função principal"""
    
    # Usar NID de exemplo (Sink)
    test_nid = "44c7f5ca-bda5-458c-bfad-7cd2075cf862"
    test_hop = 0
    
    print("\n" + "#"*60)
    print(" TESTE DE ADVERTISING BLE ".center(60))
    print("#"*60)
    
    print("\n[INFO] Este script faz advertising BLE para que outros")
    print("       dispositivos possam descobrir este node via scanning.\n")
    
    # Verificar disponibilidade de bless
    if BLESS_AVAILABLE:
        print("✅ Biblioteca 'bless' detectada")
        print("🚀 Iniciando advertising com bless...\n")
        
        try:
            await advertise_with_bless(test_nid, test_hop, duration=60)
        except Exception as e:
            print(f"\n❌ ERRO ao fazer advertising: {e}")
            print("\n💡 Tente a alternativa manual com bluetoothctl:")
            await advertise_with_bluetoothctl(test_nid, test_hop)
    else:
        print("❌ Biblioteca 'bless' não disponível")
        print("\n📋 Opções:\n")
        print("1. Instalar bless:")
        print("   pip install bless\n")
        print("2. Ou usar bluetoothctl manualmente:")
        await advertise_with_bluetoothctl(test_nid, test_hop)
    
    print("\n" + "#"*60 + "\n")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[INFO] Advertising interrompido pelo usuário.")
    except Exception as e:
        print(f"\n[ERRO] {e}")
        import traceback
        traceback.print_exc()
