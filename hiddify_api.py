import requests
import json
import uuid
from datetime import datetime, timedelta
from config import SERVERS
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class HiddifyApi:
    def __init__(self, server_id):
        self.server = SERVERS[server_id]
        self.base_url = self.server['url'].rstrip('/')
        self.api_key = self.server.get('api_key', '')
        self.proxy_path = self.server.get('proxy_path', '').strip('/')
        self.admin_uuid = self.server.get('admin_uuid', '')
        
        self.session = requests.Session()
        self.session.verify = False
        
        # Set API key in headers (API Key = Admin UUID in Hiddify)
        if self.api_key:
            self.session.headers.update({
                'Hiddify-API-Key': self.api_key,
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            })
        
        # Add retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        
        print(f"✅ Initialized Hiddify API for {self.server['name']}")
    
    def get_users(self):
        """Get all users from Hiddify panel"""
        try:
            url = f"{self.base_url}/{self.proxy_path}/api/v2/admin/user/"
            print(f"📡 Getting users from: {url}")
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 200:
                users = response.json()
                print(f"✅ Retrieved {len(users)} users from {self.server['name']}")
                return users
            else:
                print(f"❌ Failed to get users: {response.status_code} - {response.text}")
                return []
        except requests.exceptions.SSLError as e:
            print(f"⚠️ SSL Error for {self.server['name']}: Server may be temporarily unavailable")
            return []
        except requests.exceptions.ConnectionError as e:
            print(f"⚠️ Connection Error for {self.server['name']}: Server may be offline")
            return []
        except Exception as e:
            print(f"❌ Error getting users: {e}")
            return []
    
    def get_user_by_uuid(self, user_uuid):
        """Get user details by UUID"""
        try:
            url = f"{self.base_url}/{self.proxy_path}/api/v2/admin/user/{user_uuid}/"
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 200:
                user = response.json()
                return user
            else:
                print(f"❌ Failed to get user {user_uuid}: {response.status_code}")
                return None
        except Exception as e:
            print(f"❌ Error getting user: {e}")
            return None
    
    def create_user(self, telegram_id, username, data_limit_gb=0, expiry_days=30, devices=1, key_number=1):
        """Create a new user in Hiddify panel
        
        Args:
            telegram_id: User's Telegram ID
            username: User's Telegram username
            data_limit_gb: Data limit in GB (0 = unlimited, use 1000 for "unlimited")
            expiry_days: Number of days until expiry
            devices: Number of allowed devices (connection limit)
            key_number: The key sequence number for this user (Key 1, Key 2, etc.)
        """
        try:
            # Format user name: username - {devices}D / Key {number}
            # Example: blackc0der404 - 2D / Key 1
            device_label = f"{devices}D"
            if username:
                user_name = f"{username} - {device_label} / Key {key_number}"
            else:
                user_name = f"User_{telegram_id} - {device_label} / Key {key_number}"
            
            # Data limit (0 means unlimited in our system, but Hiddify uses large number)
            # Use 1000GB as "unlimited" if data_limit_gb is 0
            usage_limit = data_limit_gb if data_limit_gb > 0 else 1000
            
            # Build user data according to Hiddify API schema (minimal required fields)
            user_data = {
                "name": user_name,
                "usage_limit_GB": usage_limit,
                "package_days": expiry_days,
                "mode": "no_reset",
                "comment": f"Telegram ID: {telegram_id}",
                "enable": True
            }
            
            # Create user
            url = f"{self.base_url}/{self.proxy_path}/api/v2/admin/user/"
            print(f"📡 Creating user at: {url}")
            print(f"📦 User data: {user_data}")
            
            response = self.session.post(url, json=user_data, timeout=30)
            
            if response.status_code in [200, 201]:
                result = response.json()
                print(f"✅ User created: {user_name}")
                
                # Get the user UUID from response
                user_uuid = result.get('uuid')
                
                # Generate subscription link
                # Hiddify subscription format: https://domain/proxy_path/UUID/
                # For user panel: /proxy_path/uuid/ (user can access configs here)
                sub_link = f"{self.base_url}/{self.proxy_path}/{user_uuid}/"
                
                # Auto sub link format
                auto_sub = f"{self.base_url}/{self.proxy_path}/{user_uuid}/auto/"
                
                return {
                    'success': True,
                    'client_email': user_name,  # For compatibility with XUI
                    'client_id': user_uuid,  # For compatibility with XUI
                    'user_name': user_name,
                    'user_uuid': user_uuid,
                    'sub_link': sub_link,
                    'config_link': auto_sub,  # Auto config link
                    'sub_id': user_uuid,  # For compatibility
                    'expiry_date': datetime.now() + timedelta(days=expiry_days),
                    'data_limit': data_limit_gb,
                    'devices': devices,
                    'protocol': 'hiddify',  # Multi-protocol support
                    'panel_type': 'hiddify'
                }
            else:
                print(f"❌ Failed to create user: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            print(f"❌ Error creating user: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def update_user(self, user_uuid, **kwargs):
        """Update user information
        
        Available parameters:
        - name: User name
        - usage_limit_GB: Data limit in GB
        - package_days: Number of days for package
        - enable: Enable/disable user
        - comment: User comment
        - telegram_id: Telegram ID
        - max_ips: Connection limit
        """
        try:
            url = f"{self.base_url}/{self.proxy_path}/api/v2/admin/user/{user_uuid}/"
            
            # Build update data
            update_data = {}
            allowed_fields = [
                'name', 'usage_limit_GB', 'package_days', 'mode', 
                'enable', 'comment', 'telegram_id', 'max_ips'
            ]
            
            for key, value in kwargs.items():
                if key in allowed_fields:
                    update_data[key] = value
            
            if not update_data:
                print("⚠️ No valid fields to update")
                return False
            
            response = self.session.patch(url, json=update_data, timeout=30)
            
            if response.status_code == 200:
                print(f"✅ User {user_uuid} updated successfully")
                return True
            else:
                print(f"❌ Failed to update user: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            print(f"❌ Error updating user: {e}")
            return False
    
    def delete_user(self, user_uuid):
        """Delete a user from Hiddify panel"""
        try:
            url = f"{self.base_url}/{self.proxy_path}/api/v2/admin/user/{user_uuid}/"
            response = self.session.delete(url, timeout=30)
            
            if response.status_code in [200, 204]:
                print(f"✅ User {user_uuid} deleted successfully")
                return True
            else:
                print(f"❌ Failed to delete user: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Error deleting user: {e}")
            return False
    
    def enable_user(self, user_uuid):
        """Enable a user"""
        return self.update_user(user_uuid, enable=True)
    
    def disable_user(self, user_uuid):
        """Disable a user"""
        return self.update_user(user_uuid, enable=False)
    
    def reset_user_usage(self, user_uuid):
        """Reset user's data usage"""
        return self.update_user(
            user_uuid, 
            current_usage_GB=0,
            last_reset_time=datetime.now().strftime("%Y-%m-%d")
        )
    
    def get_user_usage(self, user_uuid):
        """Get user's current usage statistics"""
        user = self.get_user_by_uuid(user_uuid)
        if user:
            return {
                'current_usage_GB': user.get('current_usage_GB', 0),
                'usage_limit_GB': user.get('usage_limit_GB', 0),
                'last_online': user.get('last_online'),
                'expiry_time': user.get('expiry_time'),
                'enable': user.get('enable', False)
            }
        return None
    
    def extend_user(self, user_uuid, additional_days):
        """Extend user's expiry date"""
        user = self.get_user_by_uuid(user_uuid)
        if user:
            current_package_days = user.get('package_days', 0)
            new_package_days = current_package_days + additional_days
            return self.update_user(user_uuid, package_days=new_package_days)
        return False
    
    def get_server_status(self):
        """Get server status information"""
        try:
            url = f"{self.base_url}/{self.proxy_path}/api/v2/admin/system/status/"
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            print(f"❌ Error getting server status: {e}")
            return None
    
    def verify_user_exists(self, user_uuid):
        """Verify if a user exists"""
        user = self.get_user_by_uuid(user_uuid)
        return user is not None
    
    def get_available_protocols(self):
        """Get list of available protocols (Hiddify supports multiple protocols)"""
        # Hiddify supports multiple protocols simultaneously
        return ['vless', 'vmess', 'trojan', 'shadowsocks', 'reality', 'hysteria', 'tuic', 'wireguard']


# Helper function to create VPN key with Hiddify
def create_vpn_key_hiddify(server_id, telegram_id, username, data_limit, expiry_days, devices, key_number=1):
    """Create VPN key using Hiddify panel"""
    try:
        api = HiddifyApi(server_id)
        result = api.create_user(
            telegram_id=telegram_id,
            username=username,
            data_limit_gb=data_limit,
            expiry_days=expiry_days,
            devices=devices,
            key_number=key_number
        )
        return result
    except Exception as e:
        print(f"❌ Error creating Hiddify VPN key: {e}")
        return None


def delete_vpn_user_hiddify(server_id, user_uuid):
    """Delete VPN user from Hiddify panel"""
    try:
        api = HiddifyApi(server_id)
        return api.delete_user(user_uuid)
    except Exception as e:
        print(f"❌ Error deleting Hiddify user: {e}")
        return False


def verify_user_exists_hiddify(server_id, user_uuid):
    """Verify if user exists in Hiddify panel"""
    try:
        api = HiddifyApi(server_id)
        return api.verify_user_exists(user_uuid)
    except Exception as e:
        print(f"❌ Error verifying Hiddify user: {e}")
        return False


def get_available_protocols_hiddify(server_id):
    """Get available protocols from Hiddify panel"""
    try:
        api = HiddifyApi(server_id)
        return api.get_available_protocols()
    except Exception as e:
        print(f"❌ Error getting Hiddify protocols: {e}")
        return []
