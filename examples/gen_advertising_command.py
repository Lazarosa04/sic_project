#!/usr/bin/env python3
# examples/gen_advertising_command.py

"""
Gera o comando bluetoothctl correto para advertising.
"""

import uuid
import struct
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))


def generate_advertising_command(device_nid: str, hop_count: int) -> str:
    """
    Gera o comando bluetoothctl para fazer advertising.
    
    Returns:
        String com o comando pronto para copiar/colar
    """
    
    # Converter NID para bytes
    nid_bytes = uuid.UUID(device_nid).bytes
    
    # Converter Hop Count para bytes (int32, little-endian)
    hop_bytes = struct.pack('<i', hop_count)
    
    # Juntar dados
    manufacturer_data = nid_bytes + hop_bytes
    
    # Converter para string hex com espaços (formato bluetoothctl)
    hex_parts = [f"{byte:02x}" for byte in manufacturer_data]
    hex_string = " ".join(hex_parts)
    
    # Gerar comando
    command = f"manufacturer 0xffff {hex_string}"
    
    return command, manufacturer_data


def main():
    """Função principal"""
    
    # Usar NID do Sink como exemplo
    device_nid = "44c7f5ca-bda5-458c-bfad-7cd2075cf862"
    hop_count = 0
    
    command, data = generate_advertising_command(device_nid, hop_count)
    
    print("\n" + "="*70)
    print(" COMANDO BLUETOOTHCTL PARA ADVERTISING ".center(70))
    print("="*70 + "\n")
    
    print(f"NID: {device_nid}")
    print(f"Hop Count: {hop_count}\n")
    
    print("Dados de Advertisement (hex):")
    print(f"  {data.hex()}\n")
    
    print("Comando (copie e cole no bluetoothctl):\n")
    print(f"  {command}\n")
    
    print("Sequência completa:\n")
    print("  [bluetooth]# menu advertise")
    print(f"  [bluetooth]# {command}")
    print("  [bluetooth]# advertise on")
    print("  [bluetooth]# back\n")
    
    print("="*70 + "\n")


if __name__ == "__main__":
    main()
