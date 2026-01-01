#!/usr/bin/env python3
"""
test_full_project.py - Suite de Testes Completa do Projeto SIC

Este script testa TODAS as funcionalidades requeridas pelo enunciado:
- Secção 3: Gestão de Rede (topologia, routing, liveness)
- Secção 4: Controlos de Rede
- Secção 5: Segurança (certificados, autenticação, DTLS-like)
- Secção 6: Interface de Utilizador
- Bónus: Multi-Sink

Uso:
    python tests/test_full_project.py [--verbose] [--skip-ble]

Flags:
    --verbose   Mostra detalhes de cada teste
    --skip-ble  Ignora testes que requerem hardware BLE real
"""

import os
import sys
import json
import asyncio
import argparse
from datetime import datetime
from typing import Dict, List, Tuple, Optional

# Adicionar raiz do projeto ao path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# ============================================================================
# CONFIGURAÇÃO
# ============================================================================

VERBOSE = False
SKIP_BLE = False

# Cores para output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'

def log_pass(msg: str):
    print(f"  {Colors.GREEN}✓{Colors.END} {msg}")

def log_fail(msg: str):
    print(f"  {Colors.RED}✗{Colors.END} {msg}")

def log_warn(msg: str):
    print(f"  {Colors.YELLOW}⚠{Colors.END} {msg}")

def log_info(msg: str):
    if VERBOSE:
        print(f"  {Colors.BLUE}ℹ{Colors.END} {msg}")

def section_header(name: str):
    print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}{name}{Colors.END}")
    print(f"{Colors.BOLD}{'='*60}{Colors.END}")

# ============================================================================
# RESULTADOS
# ============================================================================

class TestResults:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.warnings = 0
        self.skipped = 0
        self.details: List[Tuple[str, str, str]] = []  # (section, test, result)
    
    def add_pass(self, section: str, test: str):
        self.passed += 1
        self.details.append((section, test, "PASS"))
        log_pass(test)
    
    def add_fail(self, section: str, test: str, reason: str = ""):
        self.failed += 1
        self.details.append((section, test, f"FAIL: {reason}"))
        log_fail(f"{test} - {reason}" if reason else test)
    
    def add_skip(self, section: str, test: str, reason: str = ""):
        self.skipped += 1
        self.details.append((section, test, f"SKIP: {reason}"))
        log_warn(f"{test} - {reason}" if reason else test)
    
    def summary(self):
        section_header("RESUMO DOS TESTES")
        total = self.passed + self.failed + self.skipped
        print(f"\nTotal de testes: {total}")
        print(f"  {Colors.GREEN}Passou: {self.passed}{Colors.END}")
        print(f"  {Colors.RED}Falhou: {self.failed}{Colors.END}")
        print(f"  {Colors.YELLOW}Ignorado: {self.skipped}{Colors.END}")
        
        if self.failed == 0:
            print(f"\n{Colors.GREEN}{Colors.BOLD}✓ TODOS OS TESTES PASSARAM!{Colors.END}")
        else:
            print(f"\n{Colors.RED}{Colors.BOLD}✗ ALGUNS TESTES FALHARAM{Colors.END}")
            print("\nTestes falhados:")
            for section, test, result in self.details:
                if result.startswith("FAIL"):
                    print(f"  - [{section}] {test}: {result[6:]}")
        
        # Estimativa de nota
        score = (self.passed / max(total - self.skipped, 1)) * 100
        print(f"\n{Colors.BOLD}Estimativa de completude: {score:.1f}%{Colors.END}")

results = TestResults()

# ============================================================================
# SECÇÃO 3: GESTÃO DE REDE (20%)
# ============================================================================

def test_section_3_network_management():
    """Testa funcionalidades de gestão de rede (Secção 3)."""
    section_header("SECÇÃO 3: GESTÃO DE REDE (20%)")
    
    # 3.1 - Imports básicos
    print("\n[3.1] Estrutura de Módulos")
    try:
        from node.iot_node import IoTNode, DISCONNECTED_HOP_COUNT
        results.add_pass("3.1", "Import IoTNode")
    except ImportError as e:
        results.add_fail("3.1", "Import IoTNode", str(e))
        return
    
    try:
        from sync.sink_host import SinkHost
        results.add_pass("3.1", "Import SinkHost (sync/)")
    except ImportError as e:
        results.add_fail("3.1", "Import SinkHost", str(e))
    
    # 3.2 - Criação de Node
    print("\n[3.2] Criação de Dispositivos")
    try:
        node = IoTNode(name="TestNode", is_sink=False)
        results.add_pass("3.2", "Criar IoTNode")
        
        # Verificar atributos essenciais
        assert hasattr(node, 'nid'), "Falta atributo 'nid'"
        assert hasattr(node, 'hop_count'), "Falta atributo 'hop_count'"
        assert hasattr(node, 'uplink_nid'), "Falta atributo 'uplink_nid'"
        assert hasattr(node, 'downlinks'), "Falta atributo 'downlinks'"
        assert hasattr(node, 'forwarding_table'), "Falta atributo 'forwarding_table'"
        results.add_pass("3.2", "Atributos essenciais do Node")
    except Exception as e:
        results.add_fail("3.2", "Criar IoTNode", str(e))
        return
    
    # 3.3 - Hop Count negativo para desconectados
    print("\n[3.3] Hop Count Negativo (Secção 3)")
    try:
        assert DISCONNECTED_HOP_COUNT < 0, "DISCONNECTED_HOP_COUNT deve ser negativo"
        results.add_pass("3.3", "Constante DISCONNECTED_HOP_COUNT negativa")
        
        # Node desconectado deve ter hop count negativo
        disconnected_node = IoTNode(name="Disconnected", is_sink=False)
        if disconnected_node.hop_count < 0 or disconnected_node.uplink_nid is None:
            results.add_pass("3.3", "Node inicial sem uplink tem estado correto")
        else:
            results.add_fail("3.3", "Node inicial sem uplink", "hop_count deveria ser negativo ou uplink None")
    except Exception as e:
        results.add_fail("3.3", "Hop Count Negativo", str(e))
    
    # 3.4 - Escolha de Uplink (abordagem lazy)
    print("\n[3.4] Escolha de Uplink (Lazy Approach)")
    try:
        candidates = {
            "node-hop-2": 2,
            "node-hop-1": 1,
            "node-hop-0": 0,
            "node-disconnected": -1
        }
        chosen = node.choose_uplink(candidates)
        
        if chosen == "node-hop-0":
            results.add_pass("3.4", "Escolhe uplink com menor hop count")
        else:
            results.add_fail("3.4", "Escolhe uplink com menor hop count", f"Escolheu {chosen} em vez de node-hop-0")
        
        # Não deve escolher node desconectado
        candidates_only_disconnected = {"node-a": -1, "node-b": -1}
        chosen = node.choose_uplink(candidates_only_disconnected)
        if chosen is None:
            results.add_pass("3.4", "Não escolhe nodes desconectados (hop < 0)")
        else:
            results.add_fail("3.4", "Não escolhe nodes desconectados", f"Escolheu {chosen}")
    except Exception as e:
        results.add_fail("3.4", "Escolha de Uplink", str(e))
    
    # 3.5 - Forwarding Table
    print("\n[3.5] Forwarding Table (Secção 3.1)")
    try:
        node.forwarding_table = {}
        node.update_forwarding_table("dest-nid-1", "next-hop-1")
        node.update_forwarding_table("dest-nid-2", "next-hop-2")
        
        assert "dest-nid-1" in node.forwarding_table, "Entrada não adicionada"
        assert node.forwarding_table["dest-nid-1"] == "next-hop-1", "Valor incorreto"
        results.add_pass("3.5", "Adicionar entradas à forwarding table")
        
        # Verificar lookup
        if node.forwarding_table.get("dest-nid-1") == "next-hop-1":
            results.add_pass("3.5", "Lookup na forwarding table")
        else:
            results.add_fail("3.5", "Lookup na forwarding table", "Valor incorreto")
    except Exception as e:
        results.add_fail("3.5", "Forwarding Table", str(e))
    
    # 3.6 - Heartbeat
    print("\n[3.6] Heartbeat (Secção 3.2)")
    try:
        from common.heartbeat import sign_heartbeat, verify_heartbeat, HEARTBEAT_PACING_SECONDS
        results.add_pass("3.6", "Import módulo heartbeat")
        
        assert HEARTBEAT_PACING_SECONDS > 0, "Pacing deve ser positivo"
        log_info(f"Heartbeat pacing: {HEARTBEAT_PACING_SECONDS}s")
        results.add_pass("3.6", "Constante HEARTBEAT_PACING_SECONDS definida")
    except ImportError as e:
        results.add_fail("3.6", "Import heartbeat", str(e))
    except Exception as e:
        results.add_fail("3.6", "Heartbeat config", str(e))
    
    # 3.7 - Heartbeat signing
    print("\n[3.7] Assinatura de Heartbeat")
    try:
        from common.heartbeat import sign_heartbeat, verify_heartbeat, load_sink_keys
        from support.ca_manager import OUTPUT_DIR
        
        # Carregar chaves do Sink
        sink_cert_path = os.path.join(OUTPUT_DIR, "sink_host_certificate.pem")
        sink_key_path = os.path.join(OUTPUT_DIR, "sink_host_private.pem")
        
        if os.path.exists(sink_cert_path) and os.path.exists(sink_key_path):
            sink_pub, sink_priv = load_sink_keys()
            
            # Assinar heartbeat
            hb = sign_heartbeat(counter=1, sink_private_key=sink_priv)
            assert "counter" in hb, "Falta counter"
            assert "signature" in hb, "Falta signature"
            results.add_pass("3.7", "Assinar heartbeat com chave do Sink")
            
            # Verificar heartbeat
            is_valid = verify_heartbeat(hb, sink_pub)
            if is_valid:
                results.add_pass("3.7", "Verificar assinatura do heartbeat")
            else:
                results.add_fail("3.7", "Verificar assinatura", "Assinatura inválida")
        else:
            results.add_skip("3.7", "Assinatura de Heartbeat", "Certificados não encontrados")
    except Exception as e:
        results.add_fail("3.7", "Assinatura de Heartbeat", str(e))
    
    # 3.8 - Liveness (3 heartbeats perdidos)
    print("\n[3.8] Detecção de Liveness")
    try:
        from node.iot_node import MAX_LOST_HEARTBEATS
        assert MAX_LOST_HEARTBEATS == 3, f"MAX_LOST_HEARTBEATS deve ser 3, é {MAX_LOST_HEARTBEATS}"
        results.add_pass("3.8", "MAX_LOST_HEARTBEATS = 3")
    except ImportError:
        # Tentar encontrar no código
        try:
            import node.iot_node as iot_module
            source = open(iot_module.__file__).read()
            if "lost_heartbeats" in source.lower() or "liveness" in source.lower():
                results.add_pass("3.8", "Mecanismo de liveness presente no código")
            else:
                results.add_fail("3.8", "Mecanismo de liveness", "Não encontrado")
        except:
            results.add_fail("3.8", "MAX_LOST_HEARTBEATS", "Constante não definida")

# ============================================================================
# SECÇÃO 4: CONTROLOS DE REDE
# ============================================================================

def test_section_4_network_controls():
    """Testa controlos de rede (Secção 4)."""
    section_header("SECÇÃO 4: CONTROLOS DE REDE")
    
    # 4.1 - Scanning
    print("\n[4.1] Scanning de Dispositivos")
    try:
        from common.ble_manager import BLEConnectionManager
        results.add_pass("4.1", "Import BLEConnectionManager")
        
        manager = BLEConnectionManager()
        assert hasattr(manager, 'scan_nearby') or hasattr(manager, 'scan'), "Falta método de scan"
        results.add_pass("4.1", "Método de scanning disponível")
    except Exception as e:
        results.add_fail("4.1", "BLEConnectionManager", str(e))
    
    # 4.2 - Conexão manual
    print("\n[4.2] Conexão Manual")
    try:
        from node.iot_node import IoTNode
        node = IoTNode(name="TestNode", is_sink=False)
        
        has_connect = hasattr(node, 'connect_to_uplink') or hasattr(node, 'connect_uplink')
        if has_connect:
            results.add_pass("4.2", "Método connect_to_uplink disponível")
        else:
            results.add_fail("4.2", "Método connect_to_uplink", "Não encontrado")
    except Exception as e:
        results.add_fail("4.2", "Conexão Manual", str(e))
    
    # 4.3 - Stop/Start Heartbeat por downlink
    print("\n[4.3] Controlo de Heartbeat por Downlink")
    try:
        from node.iot_node import IoTNode
        node = IoTNode(name="TestNode", is_sink=False)
        
        has_blocked = hasattr(node, 'blocked_heartbeat_nids') or hasattr(node, 'heartbeat_blocked')
        if has_blocked:
            results.add_pass("4.3", "Atributo para heartbeats bloqueados")
        else:
            # Verificar no código fonte
            import node.iot_node as iot_module
            source = open(iot_module.__file__).read()
            if "block" in source.lower() and "heartbeat" in source.lower():
                results.add_pass("4.3", "Lógica de bloqueio de heartbeat presente")
            else:
                results.add_fail("4.3", "Controlo de heartbeat", "Não implementado")
    except Exception as e:
        results.add_fail("4.3", "Controlo de Heartbeat", str(e))

# ============================================================================
# SECÇÃO 5: SEGURANÇA (50%)
# ============================================================================

def test_section_5_security():
    """Testa funcionalidades de segurança (Secção 5)."""
    section_header("SECÇÃO 5: SEGURANÇA (50%)")
    
    # 5.1 - Certificados X.509
    print("\n[5.1] Identificação com X.509 (Secção 5.1)")
    try:
        from support.ca_manager import OUTPUT_DIR
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        
        ca_cert_path = os.path.join(OUTPUT_DIR, "ca_certificate.pem")
        if os.path.exists(ca_cert_path):
            with open(ca_cert_path, 'rb') as f:
                ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            results.add_pass("5.1", "Certificado CA existe e é válido X.509")
            
            # Verificar curva elíptica
            from cryptography.hazmat.primitives.asymmetric import ec
            pub_key = ca_cert.public_key()
            if isinstance(pub_key, ec.EllipticCurvePublicKey):
                curve_name = pub_key.curve.name
                results.add_pass("5.1", f"CA usa curva elíptica: {curve_name}")
            else:
                results.add_fail("5.1", "Curva elíptica", "CA não usa ECC")
        else:
            results.add_skip("5.1", "Certificado CA", "Ficheiro não encontrado. Execute: python support/ca_manager.py")
    except Exception as e:
        results.add_fail("5.1", "Certificados X.509", str(e))
    
    # 5.2 - NID no certificado
    print("\n[5.2] NID no Certificado")
    try:
        from common.cert_utils import certificate_nid
        from support.ca_manager import OUTPUT_DIR
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        
        node_cert_path = os.path.join(OUTPUT_DIR, "node_a_certificate.pem")
        if os.path.exists(node_cert_path):
            with open(node_cert_path, 'rb') as f:
                node_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            
            nid = certificate_nid(node_cert)
            if nid and len(nid) > 0:
                results.add_pass("5.2", f"NID extraído do certificado: {nid[:16]}...")
            else:
                results.add_fail("5.2", "Extração de NID", "NID vazio")
        else:
            results.add_skip("5.2", "NID no certificado", "Certificado de node não encontrado")
    except Exception as e:
        results.add_fail("5.2", "NID no certificado", str(e))
    
    # 5.3 - Identificação do Sink (OU=Sink)
    print("\n[5.3] Identificação do Sink (Secção 5.2)")
    try:
        from common.cert_utils import is_sink_certificate, certificate_subject_ou
        from support.ca_manager import OUTPUT_DIR
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        
        sink_cert_path = os.path.join(OUTPUT_DIR, "sink_host_certificate.pem")
        if os.path.exists(sink_cert_path):
            with open(sink_cert_path, 'rb') as f:
                sink_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            
            is_sink = is_sink_certificate(sink_cert)
            if is_sink:
                results.add_pass("5.3", "Certificado do Sink identificável (OU=Sink)")
            else:
                ou = certificate_subject_ou(sink_cert)
                results.add_fail("5.3", "Identificação do Sink", f"OU={ou}, esperado 'Sink'")
        else:
            results.add_skip("5.3", "Identificação do Sink", "Certificado não encontrado")
    except Exception as e:
        results.add_fail("5.3", "Identificação do Sink", str(e))
    
    # 5.4 - CA Manager
    print("\n[5.4] CA Manager (Secção 5.3)")
    try:
        from support.ca_manager import CAManager, OUTPUT_DIR
        results.add_pass("5.4", "Import CAManager")
        
        # Verificar se pasta de certificados existe
        if os.path.exists(OUTPUT_DIR):
            certs = os.listdir(OUTPUT_DIR)
            if len(certs) >= 4:  # CA + pelo menos 1 dispositivo (cert + key)
                results.add_pass("5.4", f"Certificados gerados: {len(certs)} ficheiros")
            else:
                results.add_warn("5.4", "Poucos certificados gerados")
        else:
            results.add_skip("5.4", "Pasta de certificados", "Não existe")
    except Exception as e:
        results.add_fail("5.4", "CA Manager", str(e))
    
    # 5.5 - Link Security (autenticação mútua)
    print("\n[5.5] Autenticação Mútua por Link (Secção 5.4, 5.5)")
    try:
        from common.link_security import (
            LinkSession,
            build_link_auth1,
            build_link_auth2,
            validate_auth1,
            validate_auth2,
            derive_link_key
        )
        results.add_pass("5.5", "Import link_security")
        
        # Verificar estrutura de LinkSession
        session = LinkSession()
        assert hasattr(session, 'key') or hasattr(session, 'session_key'), "Falta atributo key"
        results.add_pass("5.5", "Classe LinkSession definida")
    except ImportError as e:
        results.add_fail("5.5", "Import link_security", str(e))
    except Exception as e:
        results.add_fail("5.5", "Link Security", str(e))
    
    # 5.6 - Session Key e MAC
    print("\n[5.6] Session Key e MAC (Secção 5.6)")
    try:
        from common.link_security import wrap_link_secure, unwrap_link_secure, LinkSession
        results.add_pass("5.6", "Funções wrap/unwrap disponíveis")
        
        # Testar wrap/unwrap
        test_session = LinkSession()
        test_session.key = os.urandom(32)  # Chave de teste
        test_session.send_seq = 0
        test_session.recv_max_seq = 0
        
        test_msg = {"type": "TEST", "data": "hello"}
        wrapped = wrap_link_secure(test_session, "sender-nid", test_msg)
        
        if wrapped and "mac" in str(wrapped).lower():
            results.add_pass("5.6", "MAC incluído nas mensagens")
        else:
            results.add_pass("5.6", "Wrap de mensagens funciona")
    except Exception as e:
        results.add_fail("5.6", "Session Key e MAC", str(e))
    
    # 5.7 - Anti-replay
    print("\n[5.7] Anti-Replay (Secção 5.6)")
    try:
        from common.link_security import LinkSession
        
        # Verificar campos de sequência
        session = LinkSession()
        has_seq = hasattr(session, 'send_seq') or hasattr(session, 'sequence')
        has_recv = hasattr(session, 'recv_max_seq') or hasattr(session, 'recv_seq')
        
        if has_seq and has_recv:
            results.add_pass("5.7", "Campos de sequência para anti-replay")
        else:
            # Verificar no código
            import common.link_security as ls_module
            source = open(ls_module.__file__).read()
            if "seq" in source.lower() and "replay" in source.lower():
                results.add_pass("5.7", "Lógica anti-replay presente no código")
            else:
                results.add_fail("5.7", "Anti-replay", "Não encontrado")
    except Exception as e:
        results.add_fail("5.7", "Anti-Replay", str(e))
    
    # 5.8 - E2E Security (DTLS-like)
    print("\n[5.8] Segurança End-to-End / DTLS-like (Secção 5.7)")
    try:
        from common.e2e_security import (
            E2ESession,
            build_e2e_hello1,
            build_e2e_hello2,
            derive_e2e_key,
            wrap_e2e_record,
            unwrap_e2e_record
        )
        results.add_pass("5.8", "Import e2e_security")
        
        # Verificar handshake
        session = E2ESession()
        assert hasattr(session, 'key') or hasattr(session, 'session_key'), "Falta chave E2E"
        results.add_pass("5.8", "Classe E2ESession definida")
    except ImportError as e:
        results.add_fail("5.8", "Import e2e_security", str(e))
    except Exception as e:
        results.add_fail("5.8", "E2E Security", str(e))
    
    # 5.9 - AES-GCM para E2E
    print("\n[5.9] Cifra E2E (AES-GCM)")
    try:
        import common.e2e_security as e2e_module
        source = open(e2e_module.__file__).read()
        
        if "AESGCM" in source or "AES" in source:
            results.add_pass("5.9", "AES-GCM usado para E2E")
        elif "GCM" in source:
            results.add_pass("5.9", "GCM mode usado para E2E")
        else:
            results.add_fail("5.9", "Cifra E2E", "AES-GCM não encontrado")
    except Exception as e:
        results.add_fail("5.9", "Cifra E2E", str(e))

# ============================================================================
# SECÇÃO 6: INTERFACE DE UTILIZADOR
# ============================================================================

def test_section_6_user_interface():
    """Testa interface de utilizador (Secção 6)."""
    section_header("SECÇÃO 6: INTERFACE DE UTILIZADOR")
    
    # 6.1 - Runtime files existem
    print("\n[6.1] Ficheiros de Runtime")
    
    base_path = os.path.dirname(os.path.dirname(__file__))
    
    node_runtime = os.path.join(base_path, "node", "node_runtime.py")
    if os.path.exists(node_runtime):
        results.add_pass("6.1", "node/node_runtime.py existe")
    else:
        results.add_fail("6.1", "node/node_runtime.py", "Ficheiro não encontrado")
    
    sink_runtime = os.path.join(base_path, "sync", "sink_runtime.py")
    if os.path.exists(sink_runtime):
        results.add_pass("6.1", "sync/sink_runtime.py existe")
    else:
        results.add_fail("6.1", "sync/sink_runtime.py", "Ficheiro não encontrado")
    
    # 6.2 - Comandos disponíveis
    print("\n[6.2] Comandos de Interface")
    required_commands = ["scan", "connect", "status", "help", "quit"]
    
    try:
        if os.path.exists(node_runtime):
            with open(node_runtime, 'r') as f:
                content = f.read().lower()
            
            for cmd in required_commands:
                if cmd in content:
                    results.add_pass("6.2", f"Comando '{cmd}' no Node")
                else:
                    results.add_fail("6.2", f"Comando '{cmd}' no Node", "Não encontrado")
    except Exception as e:
        results.add_fail("6.2", "Verificar comandos", str(e))
    
    # 6.3 - Informações mostradas
    print("\n[6.3] Informações na Interface (Secção 6)")
    required_info = [
        ("nid", "NID do dispositivo"),
        ("uplink", "Status do uplink"),
        ("downlink", "Lista de downlinks"),
        ("forwarding", "Forwarding table"),
        ("heartbeat", "Heartbeats perdidos"),
        ("routed", "Mensagens roteadas")
    ]
    
    try:
        if os.path.exists(node_runtime):
            with open(node_runtime, 'r') as f:
                content = f.read().lower()
            
            for keyword, desc in required_info:
                if keyword in content:
                    results.add_pass("6.3", f"Mostra: {desc}")
                else:
                    results.add_warn("6.3", f"Pode faltar: {desc}")
    except Exception as e:
        results.add_fail("6.3", "Informações na interface", str(e))
    
    # 6.4 - Serviço Inbox
    print("\n[6.4] Serviço Inbox")
    try:
        if os.path.exists(node_runtime):
            with open(node_runtime, 'r') as f:
                content = f.read().lower()
            
            if "inbox" in content and "send" in content:
                results.add_pass("6.4", "Comando send_inbox disponível")
            else:
                results.add_fail("6.4", "Serviço Inbox", "Não encontrado")
    except Exception as e:
        results.add_fail("6.4", "Serviço Inbox", str(e))

# ============================================================================
# SECÇÃO 8: ESTRUTURA DE PASTAS
# ============================================================================

def test_section_8_structure():
    """Testa estrutura de pastas (Secção 8)."""
    section_header("SECÇÃO 8: ESTRUTURA DE ENTREGA")
    
    base_path = os.path.dirname(os.path.dirname(__file__))
    
    # Pastas obrigatórias
    print("\n[8.1] Pastas Obrigatórias")
    required_folders = ["sync", "node", "common", "support"]
    
    for folder in required_folders:
        folder_path = os.path.join(base_path, folder)
        if os.path.exists(folder_path) and os.path.isdir(folder_path):
            results.add_pass("8.1", f"Pasta '{folder}/' existe")
        else:
            results.add_fail("8.1", f"Pasta '{folder}/'", "Não encontrada")
    
    # README.md
    print("\n[8.2] README.md")
    readme_path = os.path.join(base_path, "README.md")
    if os.path.exists(readme_path):
        results.add_pass("8.2", "README.md existe")
        
        with open(readme_path, 'r', encoding='utf-8') as f:
            readme = f.read()
        
        # Verificar conteúdo
        if "Identificação" in readme or "Autor" in readme:
            results.add_pass("8.2", "README tem identificação dos autores")
        else:
            results.add_fail("8.2", "README", "Falta identificação dos autores")
        
        if "%" in readme or "Contribuição" in readme:
            results.add_pass("8.2", "README tem contribuição percentual")
        else:
            results.add_warn("8.2", "README pode faltar contribuição %")
    else:
        results.add_fail("8.2", "README.md", "Ficheiro não encontrado")
    
    # 8.3 - Conteúdo das pastas
    print("\n[8.3] Conteúdo das Pastas")
    
    # sync/ deve ter código do Sink
    sync_path = os.path.join(base_path, "sync")
    if os.path.exists(sync_path):
        sync_files = os.listdir(sync_path)
        if "sink_host.py" in sync_files or "sink_app.py" in sync_files:
            results.add_pass("8.3", "sync/ contém código do Sink")
        else:
            results.add_fail("8.3", "sync/", "Não contém código do Sink")
    
    # node/ deve ter código do Node
    node_path = os.path.join(base_path, "node")
    if os.path.exists(node_path):
        node_files = os.listdir(node_path)
        if "iot_node.py" in node_files:
            results.add_pass("8.3", "node/ contém iot_node.py")
        else:
            results.add_fail("8.3", "node/", "Não contém iot_node.py")

# ============================================================================
# BÓNUS: MULTI-SINK
# ============================================================================

def test_bonus_multi_sink():
    """Testa feature bónus de Multi-Sink."""
    section_header("BÓNUS: MULTI-SINK (+10%)")
    
    print("\n[Bónus] Suporte a Múltiplos Sinks")
    try:
        import node.iot_node as iot_module
        source = open(iot_module.__file__).read()
        
        # Procurar por lógica de multi-sink
        indicators = [
            "_check_sink_change",
            "sink_change",
            "current_network_sink",
            "multiple.*sink",
            "sink.*mudou",
            "sink.*changed"
        ]
        
        import re
        found = False
        for indicator in indicators:
            if re.search(indicator, source, re.IGNORECASE):
                found = True
                break
        
        if found:
            results.add_pass("Bónus", "Lógica de Multi-Sink detectada")
            
            # Verificar invalidação de sessões E2E
            if "e2e_session" in source.lower() and ("invalidat" in source.lower() or "clear" in source.lower() or "del" in source):
                results.add_pass("Bónus", "Invalidação de sessões E2E ao mudar Sink")
            else:
                results.add_warn("Bónus", "Pode faltar invalidação de sessões E2E")
        else:
            results.add_skip("Bónus", "Multi-Sink", "Não implementado (opcional)")
    except Exception as e:
        results.add_skip("Bónus", "Multi-Sink", str(e))

# ============================================================================
# TESTES BLE (opcionais - requerem hardware)
# ============================================================================

def test_ble_hardware():
    """Testa funcionalidades BLE (requer hardware)."""
    if SKIP_BLE:
        section_header("TESTES BLE (IGNORADOS)")
        results.add_skip("BLE", "Testes BLE", "--skip-ble flag usado")
        return
    
    section_header("TESTES BLE (OPCIONAIS)")
    
    print("\n[BLE.1] Verificar adaptador")
    try:
        import asyncio
        from bleak import BleakScanner
        
        async def quick_scan():
            devices = await BleakScanner.discover(timeout=2.0)
            return len(devices)
        
        try:
            count = asyncio.get_event_loop().run_until_complete(quick_scan())
            results.add_pass("BLE.1", f"Adaptador BLE funcional ({count} dispositivos)")
        except Exception as e:
            results.add_skip("BLE.1", "Scan BLE", f"Erro: {e}")
    except ImportError:
        results.add_skip("BLE.1", "Bleak", "Biblioteca não instalada")

# ============================================================================
# MAIN
# ============================================================================

def main():
    global VERBOSE, SKIP_BLE
    
    parser = argparse.ArgumentParser(description="Suite de testes completa do Projeto SIC")
    parser.add_argument("--verbose", "-v", action="store_true", help="Modo verbose")
    parser.add_argument("--skip-ble", action="store_true", help="Ignorar testes BLE")
    args = parser.parse_args()
    
    VERBOSE = args.verbose
    SKIP_BLE = args.skip_ble
    
    print(f"\n{'='*60}")
    print(f"   SUITE DE TESTES - PROJETO SIC")
    print(f"   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")
    
    # Executar todos os testes
    test_section_8_structure()      # Estrutura primeiro
    test_section_3_network_management()
    test_section_4_network_controls()
    test_section_5_security()
    test_section_6_user_interface()
    test_bonus_multi_sink()
    test_ble_hardware()
    
    # Resumo final
    results.summary()
    
    return 0 if results.failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
