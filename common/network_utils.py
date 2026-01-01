import uuid
import struct
from typing import Optional

# A constante necessária para importação:
SIC_SERVICE_UUID = "d227d8e8-d4d1-4475-a835-189f7823f64c" 

# Simple application-level BLE fragmentation flags (1 byte prefix)
# 0x01: single frame; 0x02: start; 0x03: middle; 0x04: end
BLE_FRAG_SINGLE = 0x01
BLE_FRAG_START = 0x02
BLE_FRAG_MIDDLE = 0x03
BLE_FRAG_END = 0x04

def string_nid_to_bytes(nid_str: str) -> bytes:
    """Converte o NID string (UUID) para 16 bytes."""
    try:
        return uuid.UUID(nid_str).bytes
    except ValueError:
        return b'\x00' * 16 

def bytes_to_string_nid(nid_bytes: bytes) -> str:
    """Converte 16 bytes de volta para o NID string (UUID)."""
    if len(nid_bytes) != 16:
        return "NID Inválido"
    return str(uuid.UUID(bytes=nid_bytes))

def build_advertisement_data(current_nid: str, hop_count: int) -> bytes:
    """
    Constrói o Advertisement Data a ser transmitido (Payload) no formato Manufacturer Specific Data.
    Payload: [NID (16 bytes) | Hop Count (4 bytes, integer)]
    """
    
    # 1. NID (16 bytes)
    nid_bytes = string_nid_to_bytes(current_nid)
    
    # 2. Hop Count (inteiro de 4 bytes, little-endian '<i')
    hop_count_bytes = struct.pack('<i', hop_count) 
    
    # 3. Monta o Payload específico do projeto SIC (20 bytes)
    sic_data = nid_bytes + hop_count_bytes
    
    # 4. Formato AD Type 0xFF (Manufacturer Specific Data)
    company_id = struct.pack('<H', 0xFFFF) 
    
    manufacturer_data = struct.pack('<B', 0xFF) + struct.pack('<B', len(company_id) + len(sic_data)) + company_id + sic_data
    
    return manufacturer_data

# O teste de unidade removido para simplificação.
