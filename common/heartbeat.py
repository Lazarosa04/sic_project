# common/heartbeat.py

import os 
import sys # <-- Adicionado para correção de caminho
import struct
import time
from typing import Dict, Optional, Tuple
from cryptography import x509 
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

# --- CORREÇÃO DE AMBIENTE: Forçar o Python a encontrar os módulos (support) ---
# Adiciona o diretório raiz (sic_project) ao caminho de pesquisa.
# Isto resolve o ModuleNotFoundError quando executado da raiz do projeto.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

# Importar as constantes de segurança do projeto (curva e hash)
from support.ca_manager import CURVE, HASH_ALGORITHM, OUTPUT_DIR

# O Heartbeat contém um contador que aumenta sucessivamente (Secção 3.2)
HEARTBEAT_STRUCT = struct.Struct('<IQ') # I: counter (4 bytes), Q: timestamp (8 bytes)
HEARTBEAT_PACING_SECONDS = 5 # Frequência de 5 segundos

def load_sink_keys() -> Tuple[Optional[ec.EllipticCurvePrivateKey], Optional[ec.EllipticCurvePublicKey]]:
    """Carrega a chave privada e o certificado público (chave pública) do Sink."""
    try:
        # Assumimos que o nome do ficheiro é 'sink_host'
        with open(os.path.join(OUTPUT_DIR, "sink_host_private.pem"), "rb") as f:
            private_key = load_pem_private_key(f.read(), password=None)
            
        with open(os.path.join(OUTPUT_DIR, "sink_host_certificate.pem"), "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
            public_key = cert.public_key()
            
        if isinstance(private_key, ec.EllipticCurvePrivateKey) and isinstance(public_key, ec.EllipticCurvePublicKey):
             return private_key, public_key
        return None, None
        
    except FileNotFoundError:
        print("[ERRO HBSec] Ficheiros do Sink ausentes. Execute o ca_manager.py.")
        return None, None


def load_ca_certificate():
    """Carrega o certificado público da CA (para verificar a assinatura do Sink)."""
    try:
        with open(os.path.join(OUTPUT_DIR, "ca_certificate.pem"), "rb") as f:
             return x509.load_pem_x509_certificate(f.read())
    except FileNotFoundError:
        print("[ERRO HBSec] Certificado da CA ausente.")
        return None

# --- Funções de Assinatura e Verificação ---

def sign_heartbeat(counter: int, sink_private_key: ec.EllipticCurvePrivateKey) -> Dict:
    """
    Cria e assina uma mensagem Heartbeat usando a chave privada do Sink (ECDSA).
    """
    
    timestamp = int(time.time())
    
    # 1. Montar os dados brutos (counter + timestamp)
    data_to_sign = HEARTBEAT_STRUCT.pack(counter, timestamp)
    
    # 2. Assinar os dados (ECDSA com SHA-512)
    signature_bytes = sink_private_key.sign(
        data_to_sign,
        ec.ECDSA(HASH_ALGORITHM)
    )
    
    return {
        "counter": counter,
        "timestamp": timestamp,
        "data": data_to_sign,
        "signature": signature_bytes.hex() # Envia como string hex
    }


def verify_heartbeat(heartbeat_msg: Dict, signer_public_key: ec.EllipticCurvePublicKey) -> bool:
    """
    Verifica a assinatura digital do Heartbeat (garantindo que veio do Sink).
    """
    try:
        signature_bytes = bytes.fromhex(heartbeat_msg["signature"])
        data_to_verify = heartbeat_msg["data"]
        
        # Tenta verificar a assinatura
        signer_public_key.verify(
            signature_bytes,
            data_to_verify,
            ec.ECDSA(HASH_ALGORITHM)
        )
        # Se a verificação for bem-sucedida, não lança exceção.
        return True
    
    except InvalidSignature:
        return False
    except Exception as e:
        # Erro de formato (ex: signature não é hex)
        print(f"[ERRO HBSec] Falha na verificação: {e}")
        return False

# --- Teste de Unidade ---
if __name__ == "__main__":
    
    print("--- Teste de Assinatura Heartbeat ---")
    
    # Carregar chaves do Sink (assumindo que ca_manager foi executado)
    sink_private_key, sink_public_key = load_sink_keys()
    
    if sink_private_key and sink_public_key:
        
        # 1. Sink assina o Heartbeat (counter=1)
        hb_msg = sign_heartbeat(1, sink_private_key)
        print(f"\n[SINK] Heartbeat Assinado (Counter: {hb_msg['counter']})")
        
        # 2. Node recebe e verifica
        is_valid = verify_heartbeat(hb_msg, sink_public_key)
        print(f"[NODE] Assinatura Heartbeat Válida? {is_valid}")
        
        # 3. Teste de Alteração (Integridade)
        print("\n[NODE] Tentando alterar a mensagem...")
        
        # Simula um atacante alterando o contador de 1 para 100
        malicious_data = HEARTBEAT_STRUCT.pack(100, hb_msg["timestamp"]) 
        hb_msg_modified = hb_msg.copy()
        hb_msg_modified["data"] = malicious_data
        
        is_valid_modified = verify_heartbeat(hb_msg_modified, sink_public_key)
        print(f"[NODE] Assinatura Válida após alteração? {is_valid_modified}")

        assert is_valid == True
        assert is_valid_modified == False
        print("\n[SUCESSO] Assinatura e verificação do Heartbeat funcionam corretamente.")
        
    else:
        print("[AVISO] Não foi possível executar o teste Heartbeat (Faltam chaves do Sink).")
