import requests
import json
import uuid
import random
import string
import logging
from datetime import datetime, timedelta
from config import SERVERS as CONFIG_SERVERS, XUI_USERNAME, XUI_PASSWORD
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Server down alert callback (set by bot.py)
_server_alert_callback = None

def set_server_alert_callback(callback):
    """Set callback for server down alerts. Callback: fn(server_name, error_msg)"""
    global _server_alert_callback
    _server_alert_callback = callback

def _get_server(server_id):
    """Get server config - checks bot's dynamic SERVERS first, then config"""
    try:
        from bot import SERVERS as BOT_SERVERS
        server = BOT_SERVERS.get(server_id)
        if server:
            return server
    except ImportError:
        pass
    return CONFIG_SERVERS.get(server_id)


class XUIApi:
    def __init__(self, server_id):
        self.server = _get_server(server_id)
        if not self.server:
            raise ValueError(f"Server {server_id} not found")
        self.base_url = self.server['url'] + self.server['panel_path']
        self.session = requests.Session()
        self.session.verify = False
        
        # Add retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        
        self.logged_in = False
        
    def login(self):
        """Login to 3x-ui panel"""
        try:
            login_url = f"{self.base_url}/login"
            payload = {
                "username": XUI_USERNAME,
                "password": XUI_PASSWORD
            }
            response = self.session.post(login_url, data=payload, timeout=30)
            result = response.json()
            
            if result.get('success'):
                self.logged_in = True
                logger.info(f"✅ Logged in to {self.server['name']}")
                return True
            else:
                logger.error(f"❌ Login failed for {self.server['name']}: {result.get('msg')}")
                return False
        except requests.exceptions.SSLError as e:
            error_msg = f"SSL Error: Server may be temporarily unavailable"
            logger.error(f"⚠️ {error_msg} - {self.server['name']}")
            if _server_alert_callback:
                _server_alert_callback(self.server['name'], error_msg)
            return False
        except requests.exceptions.ConnectionError as e:
            error_msg = f"Connection Error: Server may be offline"
            logger.error(f"⚠️ {error_msg} - {self.server['name']}")
            if _server_alert_callback:
                _server_alert_callback(self.server['name'], error_msg)
            return False
        except Exception as e:
            error_msg = f"Login error: {e}"
            logger.error(f"❌ {error_msg} - {self.server['name']}")
            if _server_alert_callback:
                _server_alert_callback(self.server['name'], error_msg)
            return False
    
    def get_inbounds(self):
        """Get all inbounds"""
        if not self.logged_in:
            self.login()
            
        try:
            url = f"{self.base_url}/panel/api/inbounds/list"
            response = self.session.get(url)
            result = response.json()
            
            if result.get('success'):
                return result.get('obj', [])
            return []
        except Exception as e:
            logger.error(f"❌ Error getting inbounds: {e}")
            return []
    
    def get_inbound_by_protocol(self, protocol='trojan'):
        """Find inbound by protocol"""
        inbounds = self.get_inbounds()
        for inbound in inbounds:
            if inbound.get('protocol') == protocol:
                return inbound
        return None
    
    def get_available_protocols(self):
        """Get list of available protocols from inbounds"""
        inbounds = self.get_inbounds()
        protocols = []
        for inbound in inbounds:
            protocol = inbound.get('protocol')
            if protocol and protocol not in protocols:
                protocols.append(protocol)
        return protocols
    
    def generate_sub_id(self):
        """Generate random subscription ID"""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
    
    def create_client(self, telegram_id, username, data_limit_gb=0, expiry_days=30, devices=1, protocol='trojan', expiry_timestamp=None, key_number=1):
        """Create a new client in 3x-ui panel
        
        Args:
            expiry_timestamp: Optional exact expiry timestamp in milliseconds. If provided, expiry_days is ignored.
            key_number: The key sequence number for this user (Key 1, Key 2, etc.)
        """
        if not self.logged_in:
            if not self.login():
                return None
        
        try:
            # Get inbound by protocol
            inbound = self.get_inbound_by_protocol(protocol)
            if not inbound:
                # Fallback to first available inbound
                inbounds = self.get_inbounds()
                if not inbounds:
                    logger.error("❌ No inbounds found")
                    return None
                inbound = inbounds[0]
                protocol = inbound.get('protocol', 'trojan')
            
            inbound_id = inbound['id']
            inbound_protocol = inbound.get('protocol', protocol)
            
            # Protocol short codes for client name
            protocol_codes = {
                'trojan': 'TR',
                'vless': 'VL',
                'vmess': 'VM',
                'shadowsocks': 'SS',
                'wireguard': 'WG'
            }
            proto_code = protocol_codes.get(inbound_protocol, 'VPN')
            
            # Format: username - {devices}D / Key {number} ({protocol})
            # Example: blackc0der404 - 2D / Key 1 (TR)
            device_label = f"{devices}D"
            if username:
                client_name = f"{username} - {device_label} / Key {key_number} ({proto_code})"
            else:
                client_name = f"User_{telegram_id} - {device_label} / Key {key_number} ({proto_code})"
            
            # Generate unique IDs
            client_uuid = str(uuid.uuid4())
            sub_id = self.generate_sub_id()
            
            # Calculate expiry timestamp (milliseconds)
            # Use provided expiry_timestamp if available, otherwise calculate from expiry_days
            if expiry_timestamp:
                expiry_time = expiry_timestamp
            else:
                expiry_time = int((datetime.now() + timedelta(days=expiry_days)).timestamp() * 1000)
            
            # Data limit in bytes (0 = unlimited)
            total_bytes = int(data_limit_gb * 1024 * 1024 * 1024) if data_limit_gb > 0 else 0
            
            # Build client settings based on protocol - 3x-ui format
            if inbound_protocol == 'trojan':
                client_settings = {
                    "password": client_uuid,
                    "email": client_name,
                    "limitIp": devices,
                    "totalGB": total_bytes,
                    "expiryTime": expiry_time,
                    "enable": True,
                    "tgId": str(telegram_id),
                    "subId": sub_id,
                    "reset": 0
                }
            elif inbound_protocol == 'vless':
                client_settings = {
                    "id": client_uuid,
                    "flow": "",
                    "email": client_name,
                    "limitIp": devices,
                    "totalGB": total_bytes,
                    "expiryTime": expiry_time,
                    "enable": True,
                    "tgId": str(telegram_id),
                    "subId": sub_id,
                    "reset": 0
                }
            elif inbound_protocol == 'vmess':
                client_settings = {
                    "id": client_uuid,
                    "email": client_name,
                    "limitIp": devices,
                    "totalGB": total_bytes,
                    "expiryTime": expiry_time,
                    "enable": True,
                    "tgId": str(telegram_id),
                    "subId": sub_id,
                    "reset": 0
                }
            elif inbound_protocol == 'shadowsocks':
                client_settings = {
                    "method": "",
                    "password": client_uuid,
                    "email": client_name,
                    "limitIp": devices,
                    "totalGB": total_bytes,
                    "expiryTime": expiry_time,
                    "enable": True,
                    "tgId": str(telegram_id),
                    "subId": sub_id,
                    "reset": 0
                }
            else:
                # Default for other protocols
                client_settings = {
                    "id": client_uuid,
                    "email": client_name,
                    "limitIp": devices,
                    "totalGB": total_bytes,
                    "expiryTime": expiry_time,
                    "enable": True,
                    "tgId": str(telegram_id),
                    "subId": sub_id,
                    "reset": 0
                }
            
            # Add client to inbound
            url = f"{self.base_url}/panel/api/inbounds/addClient"
            payload = {
                "id": inbound_id,
                "settings": json.dumps({"clients": [client_settings]})
            }
            
            logger.info(f"📡 Creating client: {client_name} with protocol: {inbound_protocol}")
            response = self.session.post(url, data=payload)
            result = response.json()
            
            if result.get('success'):
                logger.info(f"✅ Client created: {client_name}")
                
                # Generate subscription link
                sub_link = f"https://{self.server['domain']}:{self.server['sub_port']}/sub/{sub_id}"
                
                # Generate config link based on protocol
                port = inbound.get('port', 443)
                remark = inbound.get('remark', 'VPN')
                
                # Calculate actual days left from expiry_time
                if expiry_timestamp:
                    expiry_datetime = datetime.fromtimestamp(expiry_timestamp / 1000)
                else:
                    expiry_datetime = datetime.now() + timedelta(days=expiry_days)
                days_remaining = max(1, (expiry_datetime - datetime.now()).days)
                expiry_days_left = f"{days_remaining}D"
                
                # URL encode the remark
                import urllib.parse
                encoded_remark = urllib.parse.quote(f"{remark}-{client_name}-{expiry_days_left}")
                
                if inbound_protocol == 'trojan':
                    # Use custom trojan_port if configured, otherwise use inbound port
                    trojan_port = self.server.get('trojan_port', port)
                    config_link = f"trojan://{client_uuid}@{self.server['domain']}:{trojan_port}?security=none&type=tcp#{encoded_remark}"
                elif inbound_protocol == 'vless':
                    config_link = f"vless://{client_uuid}@{self.server['domain']}:{port}?type=tcp&security=none#{encoded_remark}"
                elif inbound_protocol == 'vmess':
                    import base64
                    vmess_config = {
                        "v": "2",
                        "ps": f"{remark}-{client_name}",
                        "add": self.server['domain'],
                        "port": str(port),
                        "id": client_uuid,
                        "aid": "0",
                        "net": "tcp",
                        "type": "none",
                        "tls": ""
                    }
                    config_link = "vmess://" + base64.b64encode(json.dumps(vmess_config).encode()).decode()
                elif inbound_protocol == 'shadowsocks':
                    # Get shadowsocks settings from inbound
                    ss_settings = json.loads(inbound.get('settings', '{}'))
                    method = ss_settings.get('method', 'aes-256-gcm')
                    password = client_settings.get('password', client_uuid)
                    import base64
                    ss_auth = base64.b64encode(f"{method}:{password}".encode()).decode()
                    config_link = f"ss://{ss_auth}@{self.server['domain']}:{port}#{encoded_remark}"
                else:
                    config_link = sub_link
                
                return {
                    'success': True,
                    'client_email': client_name,
                    'client_id': client_uuid,
                    'sub_link': sub_link,
                    'config_link': config_link,
                    'sub_id': sub_id,
                    'protocol': inbound_protocol,
                    'expiry_date': expiry_datetime,
                    'data_limit': data_limit_gb,
                    'devices': devices
                }
            else:
                logger.error(f"❌ Failed to create client: {result.get('msg')}")
                return None
                
        except Exception as e:
            logger.error(f"❌ Error creating client: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def delete_client(self, inbound_id, client_email):
        """Delete a client from inbound"""
        if not self.logged_in:
            self.login()
            
        try:
            url = f"{self.base_url}/panel/api/inbounds/{inbound_id}/delClient/{client_email}"
            response = self.session.post(url)
            result = response.json()
            return result.get('success', False)
        except Exception as e:
            logger.error(f"❌ Error deleting client: {e}")
            return False
    
    def get_client_stats(self, client_email):
        """Get client traffic stats"""
        if not self.logged_in:
            self.login()
            
        try:
            url = f"{self.base_url}/panel/api/inbounds/getClientTraffics/{client_email}"
            response = self.session.get(url)
            result = response.json()
            
            if result.get('success'):
                return result.get('obj')
            return None
        except Exception as e:
            logger.error(f"❌ Error getting client stats: {e}")
            return None
    
    def get_client_by_email(self, client_email):
        """Get client details by email"""
        inbounds = self.get_inbounds()
        for inbound in inbounds:
            settings = json.loads(inbound.get('settings', '{}'))
            clients = settings.get('clients', [])
            for client in clients:
                if client.get('email') == client_email:
                    return {
                        'client': client,
                        'inbound': inbound
                    }
        return None
    
    def reset_client_traffic(self, inbound_id, client_email):
        """Reset client traffic"""
        if not self.logged_in:
            self.login()
            
        try:
            url = f"{self.base_url}/panel/api/inbounds/{inbound_id}/resetClientTraffic/{client_email}"
            response = self.session.post(url)
            result = response.json()
            return result.get('success', False)
        except Exception as e:
            logger.error(f"❌ Error resetting traffic: {e}")
            return False

    def extend_client_expiry(self, client_email, extra_days):
        """Extend client's expiry time by extra_days on the 3x-ui panel"""
        if not self.logged_in:
            self.login()
        
        try:
            # Find the client and its inbound
            client_data = self.get_client_by_email(client_email)
            if not client_data:
                logger.error(f"❌ Client {client_email} not found for expiry extension")
                return False
            
            client = client_data['client']
            inbound = client_data['inbound']
            inbound_id = inbound['id']
            
            # Get current expiry
            current_expiry_ms = client.get('expiryTime', 0)
            if current_expiry_ms <= 0:
                # No expiry set (unlimited) — skip
                logger.warning(f"⚠️ Client {client_email} has no expiry (unlimited), skipping")
                return True
            
            # Add extra days in milliseconds
            extra_ms = extra_days * 24 * 60 * 60 * 1000
            new_expiry_ms = current_expiry_ms + extra_ms
            
            # Update client settings
            client['expiryTime'] = new_expiry_ms
            
            url = f"{self.base_url}/panel/api/inbounds/updateClient/{client.get('email')}"
            payload = {
                "id": inbound_id,
                "settings": json.dumps({"clients": [client]})
            }
            
            response = self.session.post(url, data=payload)
            result = response.json()
            
            if result.get('success'):
                new_dt = datetime.fromtimestamp(new_expiry_ms / 1000)
                logger.info(f"✅ Extended {client_email} by {extra_days} days → {new_dt.strftime('%Y-%m-%d %H:%M')}")
                return True
            else:
                logger.error(f"❌ Failed to extend client: {result.get('msg')}")
                return False
        except Exception as e:
            logger.error(f"❌ Error extending client expiry: {e}")
            return False


# Old helper functions - kept for backward compatibility
def get_all_panel_clients(server_id):
    """Get all clients from a server's panel"""
    api = XUIApi(server_id)
    if not api.login():
        return []
    
    all_clients = []
    inbounds = api.get_inbounds()
    for inbound in inbounds:
        settings = json.loads(inbound.get('settings', '{}'))
        clients = settings.get('clients', [])
        for client in clients:
            all_clients.append({
                'email': client.get('email'),
                'client': client,
                'inbound': inbound,
                'protocol': inbound.get('protocol')
            })
    return all_clients


# Old delete_vpn_client kept for backward compatibility with XUI only
def delete_vpn_client_xui(server_id, client_email):
    """Delete VPN client from XUI panel (old implementation)"""
    api = XUIApi(server_id)
    if not api.login():
        return False
    
    # Find the client first
    client_info = api.get_client_by_email(client_email)
    if not client_info:
        logger.warning(f"⚠️ Client {client_email} not found, may already be deleted")
        return True  # Consider it successful if not found
    
    inbound = client_info['inbound']
    inbound_id = inbound['id']
    client = client_info['client']
    inbound_protocol = inbound.get('protocol', 'trojan')
    
    # Get the correct client identifier based on protocol
    # For 3x-ui, use the UUID (id or password field)
    if inbound_protocol == 'trojan':
        client_uuid = client.get('password')
    elif inbound_protocol == 'shadowsocks':
        client_uuid = client.get('password') or client.get('email')
    else:
        client_uuid = client.get('id')
    
    if not client_uuid:
        client_uuid = client.get('email')
    
    logger.info(f"🗑️ Deleting client: {client_email} (UUID: {client_uuid}) from inbound {inbound_id}")
    
    try:
        # Delete client from inbound - use UUID
        url = f"{api.base_url}/panel/api/inbounds/{inbound_id}/delClient/{client_uuid}"
        response = api.session.post(url)
        
        # Check if response is valid JSON
        try:
            result = response.json()
        except:
            logger.warning(f"⚠️ Non-JSON response: {response.text[:200]}")
            # Try alternative deletion method with email
            url2 = f"{api.base_url}/panel/api/inbounds/{inbound_id}/delClient/{client.get('email')}"
            response2 = api.session.post(url2)
            try:
                result = response2.json()
            except:
                return False
        
        if result.get('success'):
            logger.info(f"✅ Deleted client {client_email} from panel")
            return True
        else:
            logger.error(f"❌ Failed to delete client: {result.get('msg')}")
            return False
    except Exception as e:
        logger.error(f"❌ Error deleting client: {e}")
        return False


if __name__ == "__main__":
    # Test connection
    api = XUIApi('sg1')
    if api.login():
        inbounds = api.get_inbounds()
        logger.debug(f"Found {len(inbounds)} inbounds")
        for ib in inbounds:
            logger.debug(f"  - {ib.get('remark')} ({ib.get('protocol')})")
        
        protocols = api.get_available_protocols()
        logger.debug(f"Available protocols: {protocols}")


# ===================== UNIFIED API =====================
# Unified interface for XUI panel management

def create_vpn_key(server_id, telegram_id, username, data_limit_gb=0, expiry_days=30, devices=1, protocol='trojan', key_number=1):
    """Create VPN key on XUI panel"""
    server = _get_server(server_id)
    if not server:
        logger.error(f"❌ Server {server_id} not found")
        return None
    
    logger.info(f"📡 Creating VPN key on {server['name']}")
    
    api = XUIApi(server_id)
    if not api.login():
        logger.error(f"❌ Failed to login to XUI panel")
        return None
    return api.create_client(telegram_id, username, data_limit_gb, expiry_days, devices, protocol, key_number=key_number)


def delete_vpn_client(server_id, client_id):
    """Delete VPN client from XUI panel"""
    server = _get_server(server_id)
    if not server:
        logger.error(f"❌ Server {server_id} not found")
        return False
    
    api = XUIApi(server_id)
    if not api.login():
        return False
    
    inbounds = api.get_inbounds()
    if not inbounds:
        return False
    
    for inbound in inbounds:
        settings = json.loads(inbound.get('settings', '{}'))
        clients = settings.get('clients', [])
        
        for client in clients:
            client_uuid = client.get('id') or client.get('password')
            if client_uuid == client_id or client.get('email') == client_id:
                inbound_id = inbound['id']
                client_email = client.get('email')
                
                try:
                    url = f"{api.base_url}/panel/api/inbounds/{inbound_id}/delClient/{client_uuid}"
                    response = api.session.post(url)
                    result = response.json()
                    
                    if result.get('success'):
                        logger.info(f"✅ Deleted client {client_email}")
                        return True
                except Exception as e:
                    logger.error(f"❌ Error deleting client: {e}")
    
    return False


def verify_client_exists(server_id, client_id):
    """Verify if client exists and return client info from XUI panel"""
    server = _get_server(server_id)
    if not server:
        return False
    
    api = XUIApi(server_id)
    if not api.login():
        return False
    
    inbounds = api.get_inbounds()
    if not inbounds:
        return False
    
    for inbound in inbounds:
        settings = json.loads(inbound.get('settings', '{}'))
        clients = settings.get('clients', [])
        
        for client in clients:
            client_uuid = client.get('id') or client.get('password')
            if client_uuid == client_id or client.get('email') == client_id:
                return {
                    'client': client,
                    'inbound': inbound
                }
    
    return False


# Protocol cache: {server_id: (protocols_list, timestamp)}
_protocol_cache = {}
_PROTOCOL_CACHE_TTL = 300  # 5 minutes

def get_available_protocols(server_id):
    """Get available protocols from XUI panel (cached for 5 min)"""
    import time as _cache_time
    
    # Check cache
    if server_id in _protocol_cache:
        cached_protocols, cached_at = _protocol_cache[server_id]
        if _cache_time.time() - cached_at < _PROTOCOL_CACHE_TTL:
            return cached_protocols
    
    server = _get_server(server_id)
    if not server:
        return []
    
    api = XUIApi(server_id)
    if not api.login():
        return []
    
    protocols = api.get_available_protocols()
    
    # Store in cache
    _protocol_cache[server_id] = (protocols, _cache_time.time())
    return protocols

