#!/usr/bin/env python3
# examples/test_ble_connection.py

"""
Script de teste para demonstrar conexão, scanning e desconexão BLE.
Este script mostra como usar o BLE Manager para descobrir e conectar dispositivos.
"""

import os
import sys
import asyncio

# Adicionar path para importar módulos do projeto
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

from node.iot_node import IoTNode
from sink.sink_host import SinkHost


async def test_ble_discovery():
    """
    Teste 1: Descoberta de dispositivos BLE (Scanning)
    """
    print("\n" + "="*70)
    print(" TESTE 1: SCANNING BLE - DESCOBERTA DE DISPOSITIVOS ".center(70, "="))
    print("="*70 + "\n")
    
    # Inicializar um Node
    node_a = IoTNode(name="Node A - Test", is_sink=False)
    
    if not node_a.nid or not node_a.ble_manager:
        print("[ERRO] Node não inicializado corretamente.")
        return
    
    print(f"[TEST] Node inicializado: {node_a.nid[:8]}...")
    print(f"[TEST] Iniciando scanning BLE por 8 segundos...")
    print(f"[INFO] Para testar com dispositivos reais, execute este script em hardware com BLE.\n")
    
    try:
        # Realizar scanning
        candidates = await node_a.find_uplink_candidates(scan_duration=8.0)
        
        if candidates:
            print(f"\n[TEST] ✅ {len(candidates)} dispositivos descobertos:")
            for nid, hop_count in candidates.items():
                print(f"  • {nid[:8]}... (Hop Count: {hop_count})")
        else:
            print(f"\n[TEST] ⚠️ Nenhum dispositivo BLE descoberto.")
            print(f"[INFO] Isso é normal se não houver hardware BLE ativo nas proximidades.")
        
    except Exception as e:
        print(f"\n[TEST] ❌ Erro durante scanning: {e}")
        print(f"[INFO] Certifique-se de que o adaptador BLE está ativo e o script tem permissões necessárias.")


async def test_ble_connection():
    """
    Teste 2: Conexão BLE entre Node e Sink (simulado)
    """
    print("\n" + "="*70)
    print(" TESTE 2: CONEXÃO BLE - NODE -> SINK ".center(70, "="))
    print("="*70 + "\n")
    
    # Inicializar Node e Sink
    node_a = IoTNode(name="Node A", is_sink=False)
    sink = SinkHost()
    
    if not node_a.nid or not sink.nid:
        print("[ERRO] Identidades não carregadas. Execute ca_manager.py primeiro.")
        return
    
    print(f"[TEST] Node A: {node_a.nid[:8]}...")
    print(f"[TEST] Sink:   {sink.nid[:8]}...\n")
    
    # Simular descoberta do Sink
    print(f"[TEST] Simulando descoberta do Sink...")
    
    # Manualmente adicionar Sink aos dispositivos descobertos (simulação)
    if node_a.ble_manager:
        # Em um cenário real, isso viria do scanning
        # Aqui simulamos para demonstração
        print(f"[TEST] Em produção, o Sink seria descoberto via scanning BLE.")
        print(f"[TEST] O Node A tentaria conectar ao Sink com menor Hop Count.\n")
        
        # Tentar conectar (falhará sem hardware real, mas mostra o fluxo)
        print(f"[TEST] Tentando conectar ao Sink via BLE...")
        print(f"[INFO] Conexão BLE real requer hardware. Pulando...\n")
        
        # Simular conexão bem-sucedida
        node_a.uplink_nid = sink.nid
        node_a.hop_count = 1
        
        print(f"[TEST] ✅ Conexão simulada estabelecida:")
        print(f"  • Uplink: {node_a.uplink_nid[:8]}...")
        print(f"  • Hop Count: {node_a.hop_count}")
    
    else:
        print(f"[TEST] ❌ BLE Manager não disponível.")


async def test_ble_disconnection():
    """
    Teste 3: Desconexão BLE
    """
    print("\n" + "="*70)
    print(" TESTE 3: DESCONEXÃO BLE ".center(70, "="))
    print("="*70 + "\n")
    
    # Inicializar Node
    node_a = IoTNode(name="Node A", is_sink=False)
    
    if not node_a.nid:
        print("[ERRO] Node não inicializado.")
        return
    
    # Simular conexão ativa
    node_a.uplink_nid = "44c7f5ca-bda5-458c-bfad-7cd2075cf862"  # Sink NID
    node_a.hop_count = 1
    
    print(f"[TEST] Node A conectado ao Uplink {node_a.uplink_nid[:8]}...")
    print(f"[TEST] Hop Count: {node_a.hop_count}")
    print(f"[TEST] Iniciando desconexão...\n")
    
    # Desconectar
    await node_a.disconnect_uplink()
    
    print(f"\n[TEST] ✅ Desconexão completa:")
    print(f"  • Uplink: {node_a.uplink_nid}")
    print(f"  • Hop Count: {node_a.hop_count}")
    print(f"  • Estado: {'DESCONECTADO' if node_a.hop_count == -1 else 'CONECTADO'}")


# Mensagens DTLS Inbox não são suportadas neste projeto.


async def test_heartbeat_broadcast():
    """
    Teste 5: Broadcast de Heartbeat via BLE
    """
    print("\n" + "="*70)
    print(" TESTE 5: BROADCAST DE HEARTBEAT VIA BLE ".center(70, "="))
    print("="*70 + "\n")
    
    # Inicializar Sink
    sink = SinkHost()
    
    if not sink.nid or not sink.private_key:
        print("[ERRO] Sink não inicializado corretamente.")
        return
    
    print(f"[TEST] Sink inicializado: {sink.nid[:8]}...")
    
    # Simular alguns Downlinks conectados
    if sink.ble_manager:
        print(f"[TEST] Downlinks conectados: {sink.ble_manager.get_downlink_count()}")
        print(f"[INFO] Em produção, o Sink aceitaria conexões de Nodes via BLE.\n")
    
    print(f"[TEST] Gerando e enviando Heartbeat...")
    
    try:
        count = await sink.send_heartbeat_ble(heartbeat_counter=1)
        print(f"[TEST] ✅ Heartbeat enviado para {count} Downlinks")
        print(f"[INFO] Com hardware real, cada Node conectado receberia o Heartbeat.")
    except Exception as e:
        print(f"[TEST] ⚠️ Esperado sem hardware: {e}")


async def main():
    """Executa todos os testes em sequência"""
    print("\n" + "#"*70)
    print(" SUITE DE TESTES BLE - CONEXÃO, SCANNING E DESCONEXÃO ".center(70))
    print("#"*70)
    
    print("\n[INFO] Estes testes demonstram a funcionalidade BLE do projeto SIC.")
    print("[INFO] Para testes completos com hardware real BLE, execute em dispositivos com suporte BLE.")
    print("[INFO] Certifique-se de que ca_manager.py foi executado para gerar certificados.\n")
    
    # Executar testes
    await test_ble_discovery()
    await asyncio.sleep(1)
    
    await test_ble_connection()
    await asyncio.sleep(1)
    
    await test_ble_disconnection()
    await asyncio.sleep(1)
    
    # Teste de envio de mensagens removido (projeto heartbeat-only)
    
    await test_heartbeat_broadcast()
    
    print("\n" + "#"*70)
    print(" TESTES CONCLUÍDOS ".center(70))
    print("#"*70 + "\n")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[INFO] Testes interrompidos pelo usuário.")
    except Exception as e:
        print(f"\n[ERRO] Erro durante testes: {e}")
        import traceback
        traceback.print_exc()
