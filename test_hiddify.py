#!/usr/bin/env python3
"""
Hiddify API Test Script
Test the Hiddify panel integration
"""

import sys
from hiddify_api import HiddifyApi
from config import SERVERS

def test_hiddify_connection(server_id='hiddify1'):
    """Test connection to Hiddify panel"""
    print(f"\n{'='*60}")
    print(f"Testing Hiddify Panel Connection: {server_id}")
    print(f"{'='*60}\n")
    
    # Check if server exists
    if server_id not in SERVERS:
        print(f"❌ Server '{server_id}' not found in config!")
        print(f"Available servers: {list(SERVERS.keys())}")
        return False
    
    server = SERVERS[server_id]
    panel_type = server.get('panel_type', 'xui')
    
    if panel_type != 'hiddify':
        print(f"❌ Server '{server_id}' is not a Hiddify panel (type: {panel_type})")
        return False
    
    print(f"Server Name: {server['name']}")
    print(f"URL: {server['url']}")
    print(f"Proxy Path: {server.get('proxy_path', 'N/A')}")
    print(f"Panel Type: {panel_type}\n")
    
    # Initialize API
    try:
        api = HiddifyApi(server_id)
        print("✅ API initialized successfully\n")
    except Exception as e:
        print(f"❌ Failed to initialize API: {e}")
        return False
    
    # Test 1: Get server status
    print("📊 Test 1: Getting server status...")
    try:
        status = api.get_server_status()
        if status:
            print(f"✅ Server is online and accessible")
            print(f"Status data: {status}\n")
        else:
            print("⚠️ Could not retrieve server status (may not have permission)\n")
    except Exception as e:
        print(f"⚠️ Server status check failed: {e}\n")
    
    # Test 2: Get users
    print("👥 Test 2: Getting users list...")
    try:
        users = api.get_users()
        print(f"✅ Retrieved {len(users)} users")
        if users:
            print(f"Sample user: {users[0].get('name', 'N/A')}")
        print()
    except Exception as e:
        print(f"❌ Failed to get users: {e}\n")
        return False
    
    # Test 3: Get available protocols
    print("🔐 Test 3: Getting available protocols...")
    try:
        protocols = api.get_available_protocols()
        print(f"✅ Available protocols: {', '.join(protocols)}\n")
    except Exception as e:
        print(f"❌ Failed to get protocols: {e}\n")
    
    # Test 4: Create test user
    print("➕ Test 4: Creating test user...")
    test_username = "test_bot_user"
    try:
        result = api.create_user(
            telegram_id=123456789,
            username=test_username,
            data_limit_gb=5,
            expiry_days=1,
            devices=1,
            key_number=1
        )
        
        if result and result.get('success'):
            print(f"✅ Test user created successfully!")
            print(f"   UUID: {result.get('user_uuid')}")
            print(f"   Name: {result.get('user_name')}")
            print(f"   Subscription: {result.get('sub_link')}")
            
            # Test 5: Delete test user
            print("\n🗑️ Test 5: Deleting test user...")
            user_uuid = result.get('user_uuid')
            if api.delete_user(user_uuid):
                print(f"✅ Test user deleted successfully")
            else:
                print(f"⚠️ Failed to delete test user (UUID: {user_uuid})")
        else:
            print(f"❌ Failed to create test user")
            if result:
                print(f"   Error: {result}")
            return False
    except Exception as e:
        print(f"❌ Test user creation failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    print(f"\n{'='*60}")
    print("✅ All tests completed successfully!")
    print(f"{'='*60}\n")
    return True


def test_unified_api():
    """Test unified API that works with both XUI and Hiddify"""
    print(f"\n{'='*60}")
    print("Testing Unified API")
    print(f"{'='*60}\n")
    
    from xui_api import create_vpn_key, get_available_protocols
    
    # Test with each server
    for server_id, server in SERVERS.items():
        panel_type = server.get('panel_type', 'xui')
        print(f"\n📡 Testing {server['name']} ({panel_type.upper()})...")
        
        try:
            protocols = get_available_protocols(server_id)
            print(f"   ✅ Protocols: {', '.join(protocols) if protocols else 'None'}")
        except Exception as e:
            print(f"   ⚠️ Could not get protocols: {e}")
    
    print(f"\n{'='*60}")
    print("✅ Unified API test completed")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    print("\n🧪 Hiddify Integration Test Suite\n")
    
    # Find Hiddify servers
    hiddify_servers = [sid for sid, srv in SERVERS.items() if srv.get('panel_type') == 'hiddify']
    
    if not hiddify_servers:
        print("⚠️ No Hiddify servers found in configuration!")
        print("Please add a Hiddify server to config.py and set HIDDIFY_API_KEY in .env")
        sys.exit(1)
    
    print(f"Found {len(hiddify_servers)} Hiddify server(s): {', '.join(hiddify_servers)}\n")
    
    # Test each Hiddify server
    for server_id in hiddify_servers:
        success = test_hiddify_connection(server_id)
        if not success:
            print(f"\n⚠️ Tests failed for {server_id}")
    
    # Test unified API
    test_unified_api()
    
    print("\n✨ Test suite finished!\n")
