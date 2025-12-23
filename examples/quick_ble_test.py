#!/usr/bin/env python3
# examples/quick_ble_test.py

"""
Teste rápido de funcionalidade BLE básica.
"""

import argparse
import os
import sys
import asyncio

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

from common.ble_manager import BLEConnectionManager


async def quick_scan(adapter: str, duration: float, device_nid: str):
    """Teste rápido de scanning BLE"""
    
    print("\n" + "="*60)
    print(" TESTE RÁPIDO DE SCANNING BLE ".center(60))
    print("="*60 + "\n")
    
    # Criar manager de teste
    test_nid = device_nid
    manager = BLEConnectionManager(device_nid=test_nid)

    print(f"[TESTE] BLE Manager criado para NID: {test_nid[:8]}...")
    print(f"[TESTE] Iniciando scanning por 3 segundos...")
    print(f"[INFO] Procurando dispositivos BLE nas proximidades...\n")
    
    try:
        # Scan curto
        devices = await manager.scan_for_uplinks(duration=duration, adapter=adapter)
        
        if devices:
            print(f"\n✅ SUCESSO! {len(devices)} dispositivo(s) encontrado(s):")
            for nid, hop in devices.items():
                print(f"  • {nid} (Hop: {hop})")
        else:
            print(f"\n⚠️ Nenhum dispositivo BLE encontrado.")
            print(f"[INFO] Isso é esperado se não houver dispositivos BLE ativos próximos.")
            print(f"[INFO] Para testar com dispositivos reais:")
            print(f"  1. Execute este script em 2+ dispositivos com BLE")
            print(f"  2. Execute ca_manager.py para gerar identidades")
            print(f"  3. Execute sink/sink_app.py em um dispositivo (Sink)")
            print(f"  4. Execute este script em outros dispositivos (Nodes)")
        
    except Exception as e:
        print(f"\n❌ ERRO: {e}")
        print(f"\n[DIAGNÓSTICO]")
        print(f"  • Bluetooth está ativado? Verifique configurações do sistema")
        print(f"  • Adaptador BLE disponível? Execute: hciconfig (Linux)")
        print(f"  • Permissões corretas? Pode ser necessário: sudo ou setcap")
        
        import platform
        if platform.system() == "Linux":
            print(f"\n[Linux] Comandos úteis:")
            print(f"  sudo apt-get install bluez")
            print(f"  hciconfig")
            print(f"  sudo hciconfig hci0 up")
            print(f"  sudo setcap cap_net_raw+eip $(which python3)")
        elif platform.system() == "Windows":
            print(f"\n[Windows] Verifique:")
            print(f"  • Bluetooth ativado em Configurações")
            print(f"  • Driver BLE instalado")
        elif platform.system() == "Darwin":
            print(f"\n[macOS] Verifique:")
            print(f"  • Bluetooth ativado em Preferências do Sistema")
    
    print("\n" + "="*60 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Quick BLE scan test (accepts --adapter and --device-nid)')
    parser.add_argument('--adapter', default=None, help='HCI adapter to use for scanning (e.g. hci0, hci1)')
    parser.add_argument('--duration', type=float, default=3.0, help='Scan duration in seconds')
    parser.add_argument('--device-nid', default='00000000-0000-0000-0000-000000000001', help='NID of this device (scanner) - used to ignore self adverts')
    args = parser.parse_args()

    try:
        asyncio.run(quick_scan(adapter=args.adapter, duration=args.duration, device_nid=args.device_nid))
    except KeyboardInterrupt:
        print("\n[INFO] Teste interrompido.")
