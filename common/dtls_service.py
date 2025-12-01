# common/dtls_service.py

import json
import time
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.exceptions import InvalidSignature

# Função de ajuda para serializar dados (importante para assinatura)
def serialize_data_for_signing(data: Dict) -> bytes:
    """ Converte o dicionário de dados em uma string JSON ordenada e depois em bytes. """
    return json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')

def seal_inbox_message(sender_nid: str, payload: Dict[str, Any], private_key: ec.EllipticCurvePrivateKey) -> Dict:
    """
    Simula o empacotamento seguro de uma mensagem de Inbox (Secção 5.7).
    A mensagem é assinada com a chave privada do nó para garantir Autenticidade e Integridade.
    """
    
    # 1. Preparar o pacote de dados do serviço
    inbox_data = {
        "sender_nid": sender_nid,
        "timestamp": int(time.time()), 
        "payload": payload
    }
    
    data_to_sign = serialize_data_for_signing(inbox_data)
    
    # 2. Assinar os dados (ECDSA e SHA256)
    signature = private_key.sign(
        data_to_sign,
        ec.ECDSA(hashes.SHA256())
    )
    
    # 3. Empacotar a mensagem para transmissão
    secure_packet = {
        "is_dtls_service": True,
        "inbox_data": inbox_data,
        "signature": signature.hex() # Armazenado como string HEX
    }
    
    return secure_packet

def unseal_inbox_message(packet: Dict, public_key: ec.EllipticCurvePublicKey) -> Optional[Dict]:
    """
    Desempacota e verifica a autenticidade/integridade de uma mensagem de Inbox
    usando a chave pública do Nó (mútua autenticação).
    """
    
    if not packet.get("is_dtls_service"): return None
        
    inbox_data = packet.get("inbox_data")
    signature_hex = packet.get("signature")
    
    if not inbox_data or not signature_hex: return None
        
    try:
        signature = bytes.fromhex(signature_hex)
    except ValueError:
        print("[ERRO DTLS] Assinatura inválida (não é HEX).")
        return None
        
    data_to_verify = serialize_data_for_signing(inbox_data)

    # 1. Verificar a Assinatura
    try:
        public_key.verify(
            signature,
            data_to_verify,
            ec.ECDSA(hashes.SHA256())
        )
        
        # 2. Sucesso: Autenticidade e Integridade confirmadas
        print(f"[DTLS OK] Mensagem de Inbox de {inbox_data['sender_nid'][:8]}... verificada com sucesso.")
        return inbox_data["payload"]
        
    except InvalidSignature:
        print("[ERRO DTLS] Assinatura Inválida! Violação de Integridade/Autenticidade detectada.")
        return None
    except Exception as e:
        print(f"[ERRO DTLS] Erro durante a verificação: {e}")
        return None
