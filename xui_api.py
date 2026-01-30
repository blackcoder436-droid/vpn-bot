import requests
import json
import uuid
import random
import string
from datetime import datetime, timedelta
from config import SERVERS, XUI_USERNAME, XUI_PASSWORD
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class XUIApi:
    def __init__(self, server_id):
        self.server = SERVERS[server_id]
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
                print(f"✅ Logged in to {self.server['name']}")
                return True
            else:
                print(f"❌ Login failed: {result.get('msg')}")
                return False
        except requests.exceptions.SSLError as e:
            print(f"⚠️ SSL Error for {self.server['name']}: Server may be temporarily unavailable")
            return False
        except requests.exceptions.ConnectionError as e:
            print(f"⚠️ Connection Error for {self.server['name']}: Server may be offline")
            return False
        except Exception as e:
            print(f"❌ Login error for {self.server['name']}: {e}")
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
            print(f"❌ Error getting inbounds: {e}")
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
                    print("❌ No inbounds found")
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
            
            print(f"📡 Creating client: {client_name} with protocol: {inbound_protocol}")
            response = self.session.post(url, data=payload)
            result = response.json()
            
            if result.get('success'):
                print(f"✅ Client created: {client_name}")
                
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
                    config_link = f"trojan://{client_uuid}@{self.server['domain']}:{port}?security=none&type=tcp#{encoded_remark}"
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
                    'expiry_date': datetime.now() + timedelta(days=expiry_days),
                    'data_limit': data_limit_gb,
                    'devices': devices
                }
            else:
                print(f"❌ Failed to create client: {result.get('msg')}")
                return None
                
        except Exception as e:
            print(f"❌ Error creating client: {e}")
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
            print(f"❌ Error deleting client: {e}")
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
            print(f"❌ Error getting client stats: {e}")
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
            print(f"❌ Error resetting traffic: {e}")
            return False


def create_vpn_key(server_id, telegram_id, username, data_limit_gb=0, expiry_days=30, devices=1, protocol='trojan', expiry_timestamp=None, key_number=1):
    """Helper function to create VPN key"""
    api = XUIApi(server_id)
    return api.create_client(telegram_id, username, data_limit_gb, expiry_days, devices, protocol, expiry_timestamp, key_number)


def get_available_protocols(server_id):
    """Helper function to get available protocols"""
    api = XUIApi(server_id)
    return api.get_available_protocols()


def verify_client_exists(server_id, client_email):
    """Check if a client exists in the 3x-ui panel"""
    api = XUIApi(server_id)
    if not api.login():
        return None  # Can't verify
    
    client_info = api.get_client_by_email(client_email)
    if client_info:
        return client_info
    return None


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


def delete_vpn_client(server_id, client_email):
    """Helper function to delete VPN client from panel"""
    api = XUIApi(server_id)
    if not api.login():
        return False
    
    # Find the client first
    client_info = api.get_client_by_email(client_email)
    if not client_info:
        print(f"⚠️ Client {client_email} not found, may already be deleted")
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
    
    print(f"🗑️ Deleting client: {client_email} (UUID: {client_uuid}) from inbound {inbound_id}")
    
    try:
        # Delete client from inbound - use UUID
        url = f"{api.base_url}/panel/api/inbounds/{inbound_id}/delClient/{client_uuid}"
        response = api.session.post(url)
        
        # Check if response is valid JSON
        try:
            result = response.json()
        except:
            print(f"⚠️ Non-JSON response: {response.text[:200]}")
            # Try alternative deletion method with email
            url2 = f"{api.base_url}/panel/api/inbounds/{inbound_id}/delClient/{client.get('email')}"
            response2 = api.session.post(url2)
            try:
                result = response2.json()
            except:
                return False
        
        if result.get('success'):
            print(f"✅ Deleted client {client_email} from panel")
            return True
        else:
            print(f"❌ Failed to delete client: {result.get('msg')}")
            return False
    except Exception as e:
        print(f"❌ Error deleting client: {e}")
        return False


if __name__ == "__main__":
    # Test connection
    api = XUIApi('sg1')
    if api.login():
        inbounds = api.get_inbounds()
        print(f"Found {len(inbounds)} inbounds")
        for ib in inbounds:
            print(f"  - {ib.get('remark')} ({ib.get('protocol')})")
        
        protocols = api.get_available_protocols()
        print(f"Available protocols: {protocols}")
