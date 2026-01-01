# support/ca_manager.py

import os
import uuid
import warnings
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import utils as ec_utils # Importado, mas não usado diretamente, mantido se necessário.
from cryptography.utils import CryptographyDeprecationWarning

# --- Constantes do Projeto ---
# A Curva Elíptica P-521 (SECP521R1), conforme exigido pelo projeto.
CURVE = ec.SECP521R1() 
HASH_ALGORITHM = hashes.SHA512()
# NOME_CA é o nome da Autoridade Certificadora
NOME_CA = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"PT"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Aveiro"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SIC IoT Root CA"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"SIC Project Root Certification Authority"),
])
# Validade do certificado
VALIDADE_CA = 3650 # 10 anos para a CA
VALIDADE_DEV = 365 # 1 ano para Sink e Nodes
CA_PASSWORD = b"strong-ca-password" # Password para proteger a chave privada da CA
# Pasta onde as chaves e certificados serão guardados
OUTPUT_DIR = "support/certs"


def gerar_nid():
    """Gera um NID de 128 bits (UUID v4) para uso no sistema."""
    # O projeto pede um identificador único de 128 bits. UUID é perfeito.
    return str(uuid.uuid4())


def carregar_chave_ca(password: bytes):
    """Carrega a chave privada da CA a partir do ficheiro PEM."""
    try:
        with open(os.path.join(OUTPUT_DIR, "ca_private.pem"), "rb") as key_file:
            chave_privada_ca = load_pem_private_key(
                key_file.read(),
                password=password, 
            )
        return chave_privada_ca
    except FileNotFoundError:
        print("[ERRO] Chave da CA não encontrada. Execute 'gerar_ca_raiz()' primeiro.")
        return None
    except ValueError:
        print("[ERRO] Password incorreta para a chave da CA.")
        return None


def gerar_ca_raiz():
    """
    Gera o par de chaves privada/pública e o certificado autoassinado da CA.
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    if os.path.exists(os.path.join(OUTPUT_DIR, "ca_private.pem")):
        print(f"[CA] Chave da CA já existe em {OUTPUT_DIR}/. Carregando...")
        return carregar_chave_ca(CA_PASSWORD), x509.load_pem_x509_certificate(
            open(os.path.join(OUTPUT_DIR, "ca_certificate.pem"), "rb").read()
        )
        
    # 1. Gerar Chave Privada da CA usando a curva P-521
    chave_privada_ca = ec.generate_private_key(CURVE)
    
    # 2. Criar o Certificado da CA (Self-Signed)
    certificado_ca = x509.CertificateBuilder().subject_name(NOME_CA).issuer_name(NOME_CA).public_key(chave_privada_ca.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.utcnow()).not_valid_after(datetime.utcnow() + timedelta(days=VALIDADE_CA)).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(chave_privada_ca, HASH_ALGORITHM)
    
    # 3. Guardar Chave e Certificado
    
    # Chave Privada (protegida por password, importante!)
    with open(os.path.join(OUTPUT_DIR, "ca_private.pem"), "wb") as f:
        f.write(chave_privada_ca.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(CA_PASSWORD) 
        ))

    # Certificado Público (CA)
    with open(os.path.join(OUTPUT_DIR, "ca_certificate.pem"), "wb") as f:
        f.write(certificado_ca.public_bytes(serialization.Encoding.PEM))
        
    print(f"[CA] Chave Privada e Certificado da CA gerados e guardados em {OUTPUT_DIR}/")
    print(f"[CA] Assunto: {certificado_ca.subject}")
    
    return chave_privada_ca, certificado_ca


def gerar_certificado_dispositivo(nome_amigavel: str, organizacao_unidade: str, chave_ca, certificado_ca, is_ca: bool = False):
    """
    Gera o par de chaves e o certificado para um Sink ou IoT Node,
    assina com a CA, e guarda os ficheiros.
    """
    
    # Gerar Chave Privada do Dispositivo (usando P-521)
    chave_privada_dispositivo = ec.generate_private_key(CURVE)
    
    # Criar o NID de 128 bits para o dispositivo
    nid = gerar_nid() 
    
    # 1. Montar o Subject Name (Nome do Assunto)
    subject_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PT"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Aveiro"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SIC IoT Network"),
        # Campo extra que identifica o tipo (Sink ou Node)
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizacao_unidade),
        # Nome Amigável (para facilitar a leitura)
        x509.NameAttribute(NameOID.COMMON_NAME, nome_amigavel),
        # Adiciona o NID real de 128 bits
        x509.NameAttribute(NameOID.USER_ID, nid), 
    ])
    
    # 2. Criar e Assinar o Certificado com a Chave da CA
    # NOTA: Usamos CertificateBuilder diretamente para criar o certificado
    # e assiná-lo com a chave privada da CA.
    certificado_dispositivo = x509.CertificateBuilder().subject_name(subject_name).issuer_name(certificado_ca.subject).public_key(chave_privada_dispositivo.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.utcnow()).not_valid_after(datetime.utcnow() + timedelta(days=VALIDADE_DEV)).add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True).sign(chave_ca, HASH_ALGORITHM)
    
    # 3. Guardar Chave e Certificado
    nome_ficheiro = nome_amigavel.lower().replace(" ", "_")
    
    # Chave Privada (Não protegida por password para facilidade no IoT/Sink)
    with open(os.path.join(OUTPUT_DIR, f"{nome_ficheiro}_private.pem"), "wb") as f:
        f.write(chave_privada_dispositivo.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Certificado Público
    with open(os.path.join(OUTPUT_DIR, f"{nome_ficheiro}_certificate.pem"), "wb") as f:
        f.write(certificado_dispositivo.public_bytes(serialization.Encoding.PEM))
        
    print(f"\n[CERT] {nome_amigavel} gerado e assinado pela CA.")
    print(f"[CERT] NID: {nid}")
    print(f"[CERT] OU={organizacao_unidade}")
    print(f"[CERT] Ficheiros guardados em {OUTPUT_DIR}/{nome_ficheiro}_...")
    
    return nid, chave_privada_dispositivo, certificado_dispositivo


# --- Função principal para executar a geração ---
def main():
    """
    Ponto de entrada para o gerenciador da CA.
    """
    # Suprimir os avisos de DeprecationWarnings e CryptographyDeprecationWarning para manter o output limpo:
    warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    
    print("--- Gerenciador da Autoridade Certificadora (CA) do Projeto SIC ---")
    
    # 1. Gerar ou Carregar a CA Raiz
    chave_ca, certificado_ca = gerar_ca_raiz()
    
    if chave_ca is None:
        return # Falha ao carregar/gerar a CA
    
    print("\n------------------------------------------------------------")
    print("2. Gerar o certificado para o SINK Host:")
    print("------------------------------------------------------------")
    
    # 2. Gerar o Certificado do Sink
    # O campo "Organizational Unit" (OU) identifica o Sink, conforme o projeto.
    gerar_certificado_dispositivo(
        nome_amigavel="Sink Host", 
        organizacao_unidade="Sink", 
        chave_ca=chave_ca, 
        certificado_ca=certificado_ca
    )
    
    print("\n------------------------------------------------------------")
    print("3. Gerar um certificado de exemplo para um IoT Node:")
    print("------------------------------------------------------------")

    # 3. Gerar um Certificado de Exemplo para um Node IoT
    gerar_certificado_dispositivo(
        nome_amigavel="Node A", 
        organizacao_unidade="IoT Node",
        chave_ca=chave_ca, 
        certificado_ca=certificado_ca
    )
    gerar_certificado_dispositivo(
        nome_amigavel="Node B", 
        organizacao_unidade="IoT Node",
        chave_ca=chave_ca, 
        certificado_ca=certificado_ca
    )
    
    print("\n[INFO] Configuração de Segurança de Identidades (CA, Sink, Node) concluída.")


if __name__ == "__main__":
    main()
