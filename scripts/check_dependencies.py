#!/usr/bin/env python3
# scripts/check_dependencies.py

"""
Script para verificar e instalar dependências do projeto SIC.
"""

import subprocess
import sys


def check_python_version():
    """Verifica se a versão do Python é adequada"""
    version = sys.version_info
    print(f"🐍 Python {version.major}.{version.minor}.{version.micro}")
    
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print("❌ ERRO: Python 3.8+ é necessário")
        return False
    
    print("✅ Versão do Python adequada")
    return True


def check_package(package_name):
    """Verifica se um pacote está instalado"""
    try:
        __import__(package_name)
        return True
    except ImportError:
        return False


def install_requirements():
    """Instala dependências do requirements.txt"""
    print("\n📦 Instalando dependências...")
    
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
        ])
        print("✅ Dependências instaladas com sucesso")
        return True
    except subprocess.CalledProcessError:
        print("❌ ERRO ao instalar dependências")
        return False


def check_dependencies():
    """Verifica todas as dependências necessárias"""
    print("="*60)
    print(" VERIFICAÇÃO DE DEPENDÊNCIAS - PROJETO SIC ".center(60))
    print("="*60 + "\n")
    
    # Verificar Python
    if not check_python_version():
        return False
    
    print("\n📋 Verificando pacotes necessários...\n")
    
    packages = {
        "cryptography": "Criptografia (ECDSA, X.509)",
        "bleak": "Bluetooth Low Energy (BLE)"
    }
    
    missing = []
    
    for package, description in packages.items():
        if check_package(package):
            try:
                module = __import__(package)
                version = getattr(module, "__version__", "desconhecida")
                print(f"✅ {package:20s} v{version:10s} - {description}")
            except Exception:
                print(f"✅ {package:20s} (instalado)    - {description}")
        else:
            print(f"❌ {package:20s} (AUSENTE)      - {description}")
            missing.append(package)
    
    if missing:
        print(f"\n⚠️  {len(missing)} pacote(s) ausente(s): {', '.join(missing)}")
        print("\n🔧 Instalando pacotes ausentes...\n")
        return install_requirements()
    else:
        print("\n✅ Todas as dependências estão instaladas!")
        return True


def check_certificates():
    """Verifica se os certificados foram gerados"""
    import os
    
    print("\n🔐 Verificando certificados...")
    
    cert_dir = "support/certs"
    required_files = [
        "ca_certificate.pem",
        "ca_private.pem",
        "sink_host_certificate.pem",
        "sink_host_private.pem"
    ]
    
    if not os.path.exists(cert_dir):
        print(f"❌ Diretório {cert_dir} não existe")
        print("   Execute: python3 support/ca_manager.py")
        return False
    
    missing_certs = []
    for cert_file in required_files:
        path = os.path.join(cert_dir, cert_file)
        if os.path.exists(path):
            print(f"✅ {cert_file}")
        else:
            print(f"❌ {cert_file} (ausente)")
            missing_certs.append(cert_file)
    
    if missing_certs:
        print(f"\n⚠️  {len(missing_certs)} certificado(s) ausente(s)")
        print("   Execute: python3 support/ca_manager.py")
        return False
    else:
        print("\n✅ Certificados gerados corretamente!")
        return True


def check_bluetooth():
    """Verifica se o Bluetooth está disponível"""
    import platform
    
    print("\n📡 Verificando Bluetooth...")
    
    system = platform.system()
    
    if system == "Linux":
        try:
            result = subprocess.run(
                ["hciconfig"],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0 and "hci0" in result.stdout:
                print("✅ Adaptador Bluetooth encontrado (hci0)")
                
                if "UP RUNNING" in result.stdout:
                    print("✅ Bluetooth está ativo")
                else:
                    print("⚠️  Bluetooth não está ativo")
                    print("   Execute: sudo hciconfig hci0 up")
                
                return True
            else:
                print("❌ Nenhum adaptador Bluetooth encontrado")
                return False
                
        except FileNotFoundError:
            print("⚠️  Comando 'hciconfig' não encontrado")
            print("   Instale: sudo apt-get install bluez")
            return False
    
    elif system == "Windows":
        print("⚠️  Verificação automática não disponível no Windows")
        print("   Verifique manualmente: Configurações → Dispositivos → Bluetooth")
        return True
    
    elif system == "Darwin":  # macOS
        print("⚠️  Verificação automática não disponível no macOS")
        print("   Verifique manualmente: Preferências do Sistema → Bluetooth")
        return True
    
    else:
        print(f"⚠️  Sistema operacional não reconhecido: {system}")
        return True


def main():
    """Função principal"""
    all_ok = True
    
    # Verificar dependências
    if not check_dependencies():
        all_ok = False
    
    # Verificar certificados
    if not check_certificates():
        all_ok = False
    
    # Verificar Bluetooth
    if not check_bluetooth():
        all_ok = False
    
    # Resumo final
    print("\n" + "="*60)
    if all_ok:
        print(" ✅ SISTEMA PRONTO PARA USO ".center(60))
        print("="*60)
        print("\n🚀 Próximos passos:")
        print("   1. python3 examples/quick_ble_test.py")
        print("   2. python3 examples/test_ble_connection.py")
        print("   3. python3 sink/sink_app.py")
    else:
        print(" ⚠️  SISTEMA NECESSITA CONFIGURAÇÃO ".center(60))
        print("="*60)
        print("\n🔧 Resolva os problemas acima antes de prosseguir")
        print("📚 Consulte: QUICK_START.md")
    
    print("\n")
    return all_ok


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
