# common/ble_manager.py

"""
BLE Manager - Gerenciamento de conexões Bluetooth Low Energy
Utiliza a biblioteca 'bleak' para scanning, conexão e comunicação.
"""

import asyncio
import struct
import uuid
from typing import Optional, Dict, Callable, List, Tuple
from bleak import BleakScanner, BleakClient
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

# UUIDs do serviço customizado SIC
SIC_SERVICE_UUID = "d227d8e8-d4d1-4475-a835-189f7823f64c"
SIC_DATA_CHARACTERISTIC_UUID = "d227d8e8-d4d1-4475-a835-189f7823f64d"  # RX/TX de dados
SIC_NOTIFY_CHARACTERISTIC_UUID = "d227d8e8-d4d1-4475-a835-189f7823f64e"  # Notificações

# Manufacturer ID customizado para o projeto (0xFFFF = teste)
SIC_MANUFACTURER_ID = 0xFFFF


class BLEConnectionManager:
    """
    Gerenciador de conexões BLE para IoT Nodes.
    Suporta scanning, conexão, envio/recebimento de mensagens e desconexão.
    """
    
    def __init__(self, device_nid: str, on_message_received: Optional[Callable] = None, adapter: Optional[str] = None,
                 on_uplink_lost: Optional[Callable[[str], None]] = None,
                 on_downlink_lost: Optional[Callable[[str], None]] = None):
        """
        Inicializa o gerenciador BLE.
        
        Args:
            device_nid: NID do dispositivo (UUID de 128 bits)
            on_message_received: Callback chamado quando mensagem é recebida
        """
        self.device_nid = device_nid
        self.on_message_received = on_message_received
        # Optional callbacks to inform higher-level node of link losses
        self.on_uplink_lost = on_uplink_lost
        self.on_downlink_lost = on_downlink_lost
        
        # Conexão ativa (Uplink para nodes, ou múltiplas para Sink)
        self.uplink_client: Optional[BleakClient] = None
        self.uplink_address: Optional[str] = None
        
        # Downlinks (para nodes que atuam como roteadores)
        self.downlink_clients: Dict[str, BleakClient] = {}  # NID -> Client
        
        # Scanning
        self.scanner: Optional[BleakScanner] = None
        self.discovered_devices: Dict[str, Tuple[BLEDevice, int]] = {}  # NID -> (Device, HopCount)
        # Preferred HCI adapter for scanning/connecting (e.g. 'hci0')
        self.adapter = adapter
        
        print(f"[BLE] Manager inicializado para {device_nid[:8]}...")
    
    # ==================== SCANNING ====================
    
    def _parse_advertisement_data(self, advertisement_data: AdvertisementData) -> Optional[Tuple[str, int]]:
        """
        Extrai NID (UUID) e Hop Count do Advertisement Data (Manufacturer Data).
        
        Formato esperado:
        - Company ID: 2 bytes (0xFFFF)
        - NID: 16 bytes (UUID)
        - Hop Count: 4 bytes (int32, little-endian)
        
        Returns:
            (nid, hop_count) ou None se inválido
        """
        if not advertisement_data.manufacturer_data:
            return None
        
        # Procurar pelos dados do fabricante SIC
        if SIC_MANUFACTURER_ID not in advertisement_data.manufacturer_data:
            return None
        
        data = advertisement_data.manufacturer_data[SIC_MANUFACTURER_ID]
        
        # Verificar tamanho mínimo (16 bytes NID + 4 bytes Hop Count)
        if len(data) < 20:
            return None
        
        try:
            # Extrair NID (primeiros 16 bytes)
            nid_bytes = data[:16]
            nid = str(uuid.UUID(bytes=nid_bytes))
            
            # Extrair Hop Count (próximos 4 bytes, little-endian)
            hop_count = struct.unpack('<i', data[16:20])[0]
            
            return (nid, hop_count)
            
        except (ValueError, struct.error) as e:
            print(f"[BLE] Erro ao parsear Advertisement Data: {e}")
            return None
    
    async def scan_for_uplinks(self, duration: float = 5.0, adapter: Optional[str] = None, show_all: bool = False) -> Dict[str, int]:
        """
        Realiza scanning BLE para descobrir dispositivos vizinhos.

        Args:
            duration: Duração do scan em segundos
            adapter: opcional, HCI adapter a usar (ex: 'hci0')
            show_all: se True, mostra TODOS os devices BLE (não só SIC)

        Returns:
            Dicionário {NID: HopCount} dos dispositivos descobertos
        """
        # Determine adapter: explicit arg > instance adapter > default
        use_adapter = adapter or self.adapter
        adapter_name = use_adapter if use_adapter else 'default'
        print(f"[BLE] Iniciando scanning por {duration}s (adapter={adapter_name})...")
        self.discovered_devices.clear()

        def detection_callback(device: BLEDevice, advertisement_data: AdvertisementData):
            """Callback chamado para cada dispositivo descoberto"""
            parsed = self._parse_advertisement_data(advertisement_data)

            if parsed:
                nid, hop_count = parsed

                # Ignorar a si próprio
                if nid == self.device_nid:
                    return

                # Armazenar ou atualizar dispositivo
                if nid not in self.discovered_devices or hop_count < self.discovered_devices[nid][1]:
                    self.discovered_devices[nid] = (device, hop_count)
                    print(f"[BLE][{adapter_name}] Descoberto: {nid[:8]}... (Hop: {hop_count}, RSSI: {advertisement_data.rssi})")
            elif show_all:
                # Debug mode: show ALL BLE devices even if not SIC format
                name = advertisement_data.local_name or device.name or "Unknown"
                print(f"[BLE][{adapter_name}] Device: {device.address} | Name: {name} | RSSI: {advertisement_data.rssi}")

        # Iniciar scanning com tolerância a erros de BlueZ/DBus.
        # Primeiro tenta com o adapter solicitado; em caso de erro, cai para o default.
        scanner: Optional[BleakScanner] = None
        started = False
        try:
            scanner = BleakScanner(detection_callback=detection_callback, adapter=use_adapter) if use_adapter else BleakScanner(detection_callback=detection_callback)
            await scanner.start()
            started = True
        except Exception as e:
            print(f"[BLE] Aviso: falha ao iniciar scanner (adapter={adapter_name}): {e}. Tentando fallback sem adapter...")
            try:
                scanner = BleakScanner(detection_callback=detection_callback)
                await scanner.start()
                started = True
                adapter_name = 'default'
            except Exception as e2:
                print(f"[BLE] ERRO: scanner fallback também falhou: {e2}")
                # Não foi possível iniciar scanner; retornar vazio
                return {}

        # Run scanning loop
        try:
            remaining = duration
            interval = 0.5
            while remaining > 0:
                await asyncio.sleep(min(interval, remaining))
                remaining -= interval
        finally:
            try:
                if scanner and started:
                    await scanner.stop()
            except Exception:
                pass

        print(f"[BLE] Scanning completo. {len(self.discovered_devices)} dispositivos encontrados.")

        # Retornar apenas NID -> HopCount
        return {nid: hop for nid, (dev, hop) in self.discovered_devices.items()}
    
    # ==================== CONEXÃO ====================
    
    async def connect_to_device(self, target_nid: str) -> bool:
        """
        Conecta-se a um dispositivo específico (usado para estabelecer Uplink).
        
        Args:
            target_nid: NID do dispositivo alvo
            
        Returns:
            True se conectado com sucesso
        """
        # If not in discovered list, attempt a short rescan first
        if target_nid not in self.discovered_devices:
            print(f"[BLE] Dispositivo {target_nid[:8]}... não encontrado no cache. Tentando rescan rápido...")
            try:
                await self.scan_for_uplinks(duration=3.0)
            except Exception as e:
                print(f"[BLE] Aviso: rescan falhou: {e}")

        if target_nid not in self.discovered_devices:
            print(f"[BLE] ERRO: Dispositivo {target_nid[:8]}... não foi descoberto após rescan. Execute scan primeiro.")
            return False

        device, hop_count = self.discovered_devices[target_nid]

        print(f"[BLE] Conectando ao {target_nid[:8]}... (endereço: {device.address})")

        # Try connecting a few times — sometimes addresses are transient/unresolved
        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            try:
                # Pass the BLEDevice object where supported to avoid address
                # resolution issues on some backends.
                try:
                    client = BleakClient(device, disconnected_callback=self._on_disconnect)
                except Exception:
                    # Fallback to address string if BLEDevice not accepted
                    client = BleakClient(device.address, disconnected_callback=self._on_disconnect)
                await client.connect(timeout=10.0)

                if not client.is_connected:
                    raise RuntimeError('client.is_connected is False')

                # Armazenar conexão como Uplink
                self.uplink_client = client
                self.uplink_address = device.address

                print(f"[BLE] ✅ Conectado a {target_nid[:8]}... (Uplink estabelecido)")
                # Small delay to avoid race where services aren't ready yet on
                # some backends. Then trigger explicit service discovery.
                try:
                    await asyncio.sleep(0.25)
                except Exception:
                    pass

                try:
                    # get_services triggers service discovery in bleak
                    await client.get_services()
                except Exception:
                    # Not critical; continue and rely on subscribe/write retries
                    pass

                # Subscrever notificações (this has internal retries)
                notify_ok = await self._subscribe_notifications(client)

                # After subscribing, send a small registration message so the
                # peripheral (server) can learn our NID and register us as a
                # downlink. Retry a few times in case the write characteristic
                # is not yet available immediately after connect.
                registration_sent = False
                try:
                    import json
                    reg = json.dumps({"type": "REGISTER", "source_nid": self.device_nid}).encode('utf-8')
                    write_attempts = 4
                    write_delay = 0.5

                    async def _find_write_char():
                        try:
                            try:
                                await client.get_services()
                            except Exception:
                                pass
                            services = getattr(client, 'services', None)
                            if services:
                                # Manual search first (avoid "Multiple Characteristics" errors)
                                try:
                                    for s in services:
                                        for c in s.characteristics:
                                            if str(getattr(c, 'uuid', '')).lower() == SIC_DATA_CHARACTERISTIC_UUID.lower():
                                                return c
                                except Exception:
                                    pass
                                # Fallback to get_characteristic if manual search failed
                                try:
                                    c = services.get_characteristic(SIC_DATA_CHARACTERISTIC_UUID)
                                    if c:
                                        return c
                                except Exception:
                                    pass
                        except Exception:
                            pass
                        return None

                    for w in range(1, write_attempts + 1):
                        try:
                            char = await _find_write_char()
                            if not char:
                                # Helpful debug output: list discovered services/characteristics
                                try:
                                    svcs = getattr(client, 'services', None)
                                    if svcs:
                                        print(f"[BLE DEBUG] Discovered services for {device.address}:")
                                        for s in svcs:
                                            try:
                                                print(f"  - Service: {s.uuid}")
                                                for c in s.characteristics:
                                                    print(f"      * Char: {c.uuid} flags={getattr(c, 'properties', getattr(c, 'flags', None))}")
                                            except Exception:
                                                pass
                                except Exception:
                                    pass
                                if w >= write_attempts:
                                    raise RuntimeError(f"Write characteristic {SIC_DATA_CHARACTERISTIC_UUID} not found")
                                print(f"[BLE] Aviso: write characteristic não encontrada ainda. Tentativa {w}/{write_attempts}. Retrying in {write_delay}s")
                                await asyncio.sleep(write_delay)
                                continue

                            # Use the characteristic object directly to avoid "Multiple Characteristics" error
                            try:
                                await client.write_gatt_char(char, reg, response=True)
                            except Exception as e:
                                # Fallback: try with UUID string if object approach fails
                                await client.write_gatt_char(SIC_DATA_CHARACTERISTIC_UUID, reg, response=True)
                            print(f"[BLE] Registration message sent to {device.address} (attempt {w})")
                            registration_sent = True
                            break
                        except Exception as we:
                            if w >= write_attempts:
                                raise
                            print(f"[BLE] Aviso: tentativa {w} falhou ao enviar registo: {we}. Retrying in {write_delay}s")
                            await asyncio.sleep(write_delay)
                except Exception as e:
                    print(f"[BLE] Aviso: falha ao enviar registo para {device.address}: {e}")
                # Consider connection successful only if notifications were enabled
                # and registration was sent (ensures SIC service is present).
                if notify_ok and registration_sent:
                    return True
                else:
                    print(f"[BLE] ERRO: Conexão estabelecida, mas serviço SIC indisponível (notify_ok={notify_ok}, registration_sent={registration_sent}).")
                    try:
                        await client.disconnect()
                    except Exception:
                        pass
                    self.uplink_client = None
                    self.uplink_address = None
                    # Continue to retry in outer loop
                    raise RuntimeError('SIC GATT service not available on target')

            except Exception as e:
                # Specific Bleak backends may report 'Device with address X was not found.'
                print(f"[BLE] ERRO ao conectar (tentativa {attempt}/{max_attempts}): {e}")

                # If last attempt, give up
                if attempt >= max_attempts:
                    print(f"[BLE] Falha ao conectar depois de {max_attempts} tentativas.")
                    return False

                # Wait briefly and try a fresh scan to refresh device info/address resolution
                await asyncio.sleep(1.0)
                try:
                    await self.scan_for_uplinks(duration=2.0)
                    if target_nid in self.discovered_devices:
                        device, hop_count = self.discovered_devices[target_nid]
                        print(f"[BLE] Rescan encontrou dispositivo {target_nid[:8]}... (endereço: {device.address}), retrying")
                    else:
                        print(f"[BLE] Rescan não encontrou {target_nid[:8]}..., nova tentativa em breve")
                except Exception as e2:
                    print(f"[BLE] Aviso: rescan durante retry falhou: {e2}")
    
    async def accept_downlink_connection(self, device_address: str, device_nid: str) -> bool:
        """
        Aceita uma conexão de um dispositivo Downlink (usado por roteadores/Sink).
        
        Args:
            device_address: Endereço BLE do dispositivo
            device_nid: NID do dispositivo
            
        Returns:
            True se conexão aceita com sucesso
        """
        print(f"[BLE] Aceitando conexão Downlink de {device_nid[:8]}...")
        
        try:
            client = BleakClient(device_address, disconnected_callback=self._on_disconnect)
            await client.connect(timeout=10.0)
            
            if not client.is_connected:
                return False
            
            # Armazenar como Downlink
            self.downlink_clients[device_nid] = client
            
            print(f"[BLE] ✅ Downlink aceito: {device_nid[:8]}... (Total: {len(self.downlink_clients)})")
            
            # Subscrever notificações
            await self._subscribe_notifications(client)
            
            return True
            
        except Exception as e:
            print(f"[BLE] ERRO ao aceitar Downlink: {e}")
            return False
    
    def _on_disconnect(self, client: BleakClient):
        """Callback chamado quando uma conexão é perdida"""
        address = client.address
        print(f"[BLE] ⚠️ Desconexão detectada: {address}")
        
        # Verificar se era o Uplink
        if self.uplink_client and self.uplink_client.address == address:
            print(f"[BLE] 🚨 UPLINK PERDIDO!")
            self.uplink_client = None
            self.uplink_address = None
            # Notify upper layer (IoTNode) that uplink was lost
            try:
                if self.on_uplink_lost:
                    self.on_uplink_lost(address)
            except Exception:
                pass
        
        # Verificar se era um Downlink
        for nid, downlink_client in list(self.downlink_clients.items()):
            if downlink_client.address == address:
                print(f"[BLE] Downlink {nid[:8]}... desconectado.")
                del self.downlink_clients[nid]
                # Notify upper layer (IoTNode) that a downlink was lost
                try:
                    if self.on_downlink_lost:
                        self.on_downlink_lost(nid)
                except Exception:
                    pass
                break
    
    async def _subscribe_notifications(self, client: BleakClient) -> bool:
        """Subscreve à característica de notificações para receber mensagens.
        Retorna True se as notificações foram ativadas com sucesso, caso contrário False.
        """

        async def _find_char(target_uuid: str):
            """Best-effort characteristic lookup tolerant to backend quirks.

            Some backends cache services late or expose duplicated services.
            This helper triggers discovery, then searches manually if
            get_characteristic returns None or raises on duplicates.
            """
            try:
                try:
                    await client.get_services()
                except Exception:
                    pass
                services = getattr(client, 'services', None)
                if services:
                    # Manual search first (avoid "Multiple Characteristics" errors)
                    try:
                        for s in services:
                            for c in s.characteristics:
                                if str(getattr(c, 'uuid', '')).lower() == target_uuid.lower():
                                    return c
                    except Exception:
                        pass
                    # Fallback to get_characteristic if manual search failed
                    try:
                        found = services.get_characteristic(target_uuid)
                        if found:
                            return found
                    except Exception:
                        pass
            except Exception:
                pass
            return None

        try:
            # Some peripherals may take a short time to register GATT
            # services after the connection is established. Retry a few
            # times to allow service discovery to complete.
            max_attempts = 8
            delay = 0.5
            for attempt in range(1, max_attempts + 1):
                try:
                    notify_char = await _find_char(SIC_NOTIFY_CHARACTERISTIC_UUID)
                    if not notify_char:
                        if attempt >= max_attempts:
                            # Before failing, dump discovered services/characteristics for diagnostics
                            try:
                                svcs = getattr(client, 'services', None)
                                if svcs:
                                    print(f"[BLE DEBUG] Discovered services for {client.address} (notify final attempt):")
                                    for s in svcs:
                                        try:
                                            print(f"  - Service: {s.uuid}")
                                            for c in s.characteristics:
                                                print(f"      * Char: {c.uuid} flags={getattr(c, 'properties', getattr(c, 'flags', None))}")
                                        except Exception:
                                            pass
                            except Exception:
                                pass
                            raise RuntimeError(f"Notify characteristic {SIC_NOTIFY_CHARACTERISTIC_UUID} not found")
                        print(f"[BLE] Aviso: notify characteristic não encontrada ainda. Tentativa {attempt}/{max_attempts}. Retrying in {delay}s")
                        await asyncio.sleep(delay)
                        continue

                    # Characteristic exists, request notifications using the object
                    # (Avoid "Multiple Characteristics" error by using object instead of UUID string)
                    try:
                        await client.start_notify(notify_char, self._notification_handler)
                    except Exception as e:
                        # Fallback: try with UUID string if object approach fails
                        await client.start_notify(
                            SIC_NOTIFY_CHARACTERISTIC_UUID,
                            self._notification_handler
                        )
                    print(f"[BLE] Notificações ativadas para {client.address} (attempt {attempt})")
                    return True
                except Exception as e:
                    if attempt >= max_attempts:
                        raise
                    else:
                        print(f"[BLE] Aviso: tentativa {attempt} falhou ao ativar notificações: {e}. Retrying in {delay}s")
                        await asyncio.sleep(delay)
        except Exception as e:
            print(f"[BLE] AVISO: Não foi possível ativar notificações: {e}")
            return False
        return False
    
    def _notification_handler(self, sender: int, data: bytes):
        """Handler chamado quando uma notificação BLE é recebida"""
        if self.on_message_received:
            try:
                # Converter bytes para mensagem (assumindo JSON serializado)
                import json
                message = json.loads(data.decode('utf-8'))
                self.on_message_received(message, sender)
            except Exception as e:
                print(f"[BLE] ERRO ao processar mensagem: {e}")
    
    # ==================== ENVIO DE MENSAGENS ====================
    
    async def send_to_uplink(self, data: bytes) -> bool:
        """
        Envia dados para o Uplink através da característica GATT.
        
        Args:
            data: Dados a enviar (bytes)
            
        Returns:
            True se enviado com sucesso
        """
        if not self.uplink_client or not self.uplink_client.is_connected:
            print(f"[BLE] ERRO: Sem conexão Uplink ativa.")
            return False
        
        try:
            await self.uplink_client.write_gatt_char(
                SIC_DATA_CHARACTERISTIC_UUID,
                data,
                response=True
            )
            print(f"[BLE] ✉️ Enviado {len(data)} bytes para Uplink")
            return True
            
        except Exception as e:
            print(f"[BLE] ERRO ao enviar para Uplink: {e}")
            return False
    
    async def send_to_downlink(self, target_nid: str, data: bytes) -> bool:
        """
        Envia dados para um Downlink específico.
        
        Args:
            target_nid: NID do dispositivo Downlink
            data: Dados a enviar (bytes)
            
        Returns:
            True se enviado com sucesso
        """
        if target_nid not in self.downlink_clients:
            print(f"[BLE] ERRO: Downlink {target_nid[:8]}... não conectado.")
            return False
        
        client = self.downlink_clients[target_nid]
        
        if not client.is_connected:
            print(f"[BLE] ERRO: Downlink {target_nid[:8]}... desconectado.")
            return False
        
        try:
            await client.write_gatt_char(
                SIC_DATA_CHARACTERISTIC_UUID,
                data,
                response=True
            )
            print(f"[BLE] ✉️ Enviado {len(data)} bytes para Downlink {target_nid[:8]}...")
            return True
            
        except Exception as e:
            print(f"[BLE] ERRO ao enviar para Downlink: {e}")
            return False
    
    async def broadcast_to_downlinks(self, data: bytes) -> int:
        """
        Envia dados para todos os Downlinks (usado para Heartbeat).
        
        Args:
            data: Dados a enviar (bytes)
            
        Returns:
            Número de Downlinks que receberam com sucesso
        """
        if not self.downlink_clients:
            print(f"[BLE] AVISO: Nenhum Downlink conectado para broadcast.")
            return 0
        
        success_count = 0
        
        for nid, client in self.downlink_clients.items():
            if await self.send_to_downlink(nid, data):
                success_count += 1
        
        print(f"[BLE] Broadcast completo: {success_count}/{len(self.downlink_clients)} Downlinks alcançados.")
        return success_count
    
    # ==================== DESCONEXÃO ====================
    
    async def disconnect_uplink(self):
        """Desconecta do Uplink atual"""
        if self.uplink_client:
            print(f"[BLE] Desconectando do Uplink ({self.uplink_address})...")
            try:
                await self.uplink_client.disconnect()
            except Exception as e:
                print(f"[BLE] ERRO ao desconectar: {e}")
            finally:
                self.uplink_client = None
                self.uplink_address = None
                print(f"[BLE] Uplink desconectado.")
    
    async def disconnect_downlink(self, target_nid: str):
        """Desconecta de um Downlink específico"""
        if target_nid not in self.downlink_clients:
            print(f"[BLE] AVISO: Downlink {target_nid[:8]}... não está conectado.")
            return
        
        client = self.downlink_clients[target_nid]
        print(f"[BLE] Desconectando Downlink {target_nid[:8]}...")
        
        try:
            await client.disconnect()
        except Exception as e:
            print(f"[BLE] ERRO ao desconectar Downlink: {e}")
        finally:
            del self.downlink_clients[target_nid]
            print(f"[BLE] Downlink {target_nid[:8]}... desconectado.")
    
    async def disconnect_all(self):
        """Desconecta de todos os dispositivos (Uplink e Downlinks)"""
        print(f"[BLE] Desconectando de todos os dispositivos...")
        
        # Desconectar Uplink
        await self.disconnect_uplink()
        
        # Desconectar todos os Downlinks
        downlink_nids = list(self.downlink_clients.keys())
        for nid in downlink_nids:
            await self.disconnect_downlink(nid)
        
        print(f"[BLE] Todas as conexões foram encerradas.")
    
    # ==================== UTILITÁRIOS ====================
    
    def is_connected_to_uplink(self) -> bool:
        """Verifica se há conexão ativa com Uplink"""
        return self.uplink_client is not None and self.uplink_client.is_connected
    
    def get_downlink_count(self) -> int:
        """Retorna o número de Downlinks conectados"""
        return len(self.downlink_clients)
    
    def get_connected_downlinks(self) -> List[str]:
        """Retorna lista de NIDs dos Downlinks conectados"""
        return list(self.downlink_clients.keys())


# ==================== ADVERTISING (Para Sink e Roteadores) ====================

class BLEAdvertiser:
    """
    Gerenciador de Advertisement BLE para permitir que outros dispositivos descubram este node.
    Nota: Bleak não suporta Advertisement diretamente. Esta classe é um placeholder
    para integração futura com bibliotecas específicas de plataforma.
    """
    
    def __init__(self, device_nid: str, hop_count: int):
        self.device_nid = device_nid
        self.hop_count = hop_count
        print(f"[BLE ADV] Advertiser inicializado (NID: {device_nid[:8]}..., Hop: {hop_count})")
    
    def build_manufacturer_data(self) -> bytes:
        """
        Constrói os dados de fabricante com NID e Hop Count.
        
        Returns:
            Bytes contendo NID (16) + Hop Count (4)
        """
        nid_bytes = uuid.UUID(self.device_nid).bytes
        hop_bytes = struct.pack('<i', self.hop_count)
        return nid_bytes + hop_bytes
    
    async def start_advertising(self):
        """
        Inicia o Advertisement BLE.
        
        NOTA: Bleak não suporta Advertisement mode. 
        Para implementação real, seria necessário usar:
        - Linux: BlueZ D-Bus API diretamente
        - Windows: Windows.Devices.Bluetooth.Advertisement
        - macOS: CoreBluetooth (não suporta peripheral mode facilmente)
        """
        print(f"[BLE ADV] ⚠️ Advertisement não suportado diretamente pelo Bleak.")
        print(f"[BLE ADV] Para implementação completa, use BlueZ D-Bus API (Linux) ou APIs nativas.")
        print(f"[BLE ADV] Dados que seriam transmitidos: NID={self.device_nid[:8]}..., Hop={self.hop_count}")
    
    async def stop_advertising(self):
        """Para o Advertisement BLE"""
        print(f"[BLE ADV] Advertisement parado.")
    
    def update_hop_count(self, new_hop_count: int):
        """Atualiza o Hop Count no Advertisement"""
        self.hop_count = new_hop_count
        print(f"[BLE ADV] Hop Count atualizado para {new_hop_count}")
