import sqlite3
from datetime import datetime, timedelta
from config import DATABASE_PATH

def init_db():
    """Initialize the database with required tables"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            telegram_id INTEGER UNIQUE,
            username TEXT,
            first_name TEXT,
            last_name TEXT,
            phone TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_banned INTEGER DEFAULT 0
        )
    ''')
    
    # Orders table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            telegram_id INTEGER,
            server_id TEXT,
            plan_id TEXT,
            amount INTEGER,
            protocol TEXT DEFAULT 'trojan',
            status TEXT DEFAULT 'pending',
            payment_screenshot TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            approved_at TIMESTAMP,
            approved_by INTEGER,
            FOREIGN KEY (telegram_id) REFERENCES users(telegram_id)
        )
    ''')
    
    # VPN Keys table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vpn_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            telegram_id INTEGER,
            order_id INTEGER,
            server_id TEXT,
            client_email TEXT,
            client_id TEXT,
            sub_link TEXT,
            config_link TEXT,
            data_limit INTEGER,
            expiry_date TIMESTAMP,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (telegram_id) REFERENCES users(telegram_id),
            FOREIGN KEY (order_id) REFERENCES orders(id)
        )
    ''')
    
    # Free test tracking
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS free_tests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            telegram_id INTEGER UNIQUE,
            used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (telegram_id) REFERENCES users(telegram_id)
        )
    ''')
    
    # Payments table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER,
            telegram_id INTEGER,
            amount INTEGER,
            payment_method TEXT,
            transaction_id TEXT,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (order_id) REFERENCES orders(id)
        )
    ''')
    
    # Security logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            telegram_id INTEGER,
            event_type TEXT,
            details TEXT,
            ip_address TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Referral system tables
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS referrals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            referrer_id INTEGER NOT NULL,
            referred_id INTEGER UNIQUE NOT NULL,
            referred_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_paid INTEGER DEFAULT 0,
            paid_at TIMESTAMP,
            order_id INTEGER,
            FOREIGN KEY (referrer_id) REFERENCES users(telegram_id),
            FOREIGN KEY (referred_id) REFERENCES users(telegram_id)
        )
    ''')
    
    # Referral rewards tracking
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS referral_rewards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            telegram_id INTEGER NOT NULL,
            reward_type TEXT NOT NULL,
            reward_value TEXT,
            referral_count INTEGER,
            claimed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (telegram_id) REFERENCES users(telegram_id)
        )
    ''')
    
    # Add referral bonus data to users (5 Days per referral)
    try:
        cursor.execute('ALTER TABLE users ADD COLUMN referral_bonus_days INTEGER DEFAULT 0')
    except:
        pass  # Column already exists
    
    # Add referral code to users
    try:
        cursor.execute('ALTER TABLE users ADD COLUMN referral_code TEXT')
    except:
        pass  # Column already exists
    
    # Feature flags table (persistent settings)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS feature_flags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            flag_name TEXT UNIQUE NOT NULL,
            is_enabled INTEGER DEFAULT 1,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_by INTEGER
        )
    ''')
    
    # Initialize default feature flags
    default_flags = [
        ('referral_system', 1),
        ('free_test_key', 1),
        ('protocol_change', 1),
        ('auto_approve', 1)
    ]
    for flag_name, is_enabled in default_flags:
        cursor.execute('''
            INSERT OR IGNORE INTO feature_flags (flag_name, is_enabled) VALUES (?, ?)
        ''', (flag_name, is_enabled))
    
    # User bans table (temporary ban support)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_bans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            telegram_id INTEGER NOT NULL,
            reason TEXT,
            banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            banned_until TIMESTAMP,
            banned_by INTEGER,
            is_active INTEGER DEFAULT 1,
            unbanned_at TIMESTAMP,
            unbanned_by INTEGER,
            FOREIGN KEY (telegram_id) REFERENCES users(telegram_id)
        )
    ''')
    
    # Dynamic servers table (admin can add/remove servers)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            panel_path TEXT NOT NULL,
            domain TEXT NOT NULL,
            panel_type TEXT NOT NULL DEFAULT 'xui',
            sub_port INTEGER DEFAULT 2096,
            api_key TEXT,
            admin_uuid TEXT,
            proxy_path TEXT,
            user_sub_path TEXT,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_by INTEGER,
            updated_at TIMESTAMP
        )
    ''')

    # Protocol settings table (admin can enable/disable protocols)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS protocol_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            protocol_name TEXT UNIQUE NOT NULL,
            display_name TEXT NOT NULL,
            is_enabled INTEGER DEFAULT 1,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_by INTEGER
        )
    ''')
    
    # Initialize default protocols
    default_protocols = [
        ('trojan', '🔐 Trojan (Recommended)', 1),
        ('vless', '⚡ VLESS', 1),
        ('vmess', '🌐 VMess', 1),
        ('shadowsocks', '🔒 Shadowsocks', 1),
        ('wireguard', '🛡️ WireGuard', 1)
    ]
    for proto_name, display_name, is_enabled in default_protocols:
        cursor.execute('''
            INSERT OR IGNORE INTO protocol_settings (protocol_name, display_name, is_enabled) VALUES (?, ?, ?)
        ''', (proto_name, display_name, is_enabled))

    conn.commit()
    conn.close()
    print("✅ Database initialized successfully!")

def get_user(telegram_id):
    """Get user by telegram ID"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE telegram_id = ?', (telegram_id,))
    user = cursor.fetchone()
    conn.close()
    return user

def create_user(telegram_id, username, first_name, last_name=None):
    """Create a new user"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT OR IGNORE INTO users (telegram_id, username, first_name, last_name)
            VALUES (?, ?, ?, ?)
        ''', (telegram_id, username, first_name, last_name))
        conn.commit()
    except Exception as e:
        print(f"Error creating user: {e}")
    finally:
        conn.close()

def has_used_free_test(telegram_id):
    """Check if user has already used free test"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM free_tests WHERE telegram_id = ?', (telegram_id,))
    result = cursor.fetchone()
    conn.close()
    return result is not None

def mark_free_test_used(telegram_id):
    """Mark free test as used for user"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO free_tests (telegram_id) VALUES (?)', (telegram_id,))
        conn.commit()
    except Exception as e:
        print(f"Error marking free test: {e}")
    finally:
        conn.close()

def create_order(telegram_id, server_id, plan_id, amount, protocol='trojan'):
    """Create a new order"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO orders (telegram_id, server_id, plan_id, amount, protocol)
            VALUES (?, ?, ?, ?, ?)
        ''', (telegram_id, server_id, plan_id, amount, protocol))
        conn.commit()
        order_id = cursor.lastrowid
        conn.close()
        return order_id
    except Exception as e:
        print(f"Error creating order: {e}")
        conn.close()
        return None

def update_order_screenshot(order_id, screenshot_file_id):
    """Update order with payment screenshot"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE orders SET payment_screenshot = ? WHERE id = ?
    ''', (screenshot_file_id, order_id))
    conn.commit()
    conn.close()

def approve_order(order_id, admin_id):
    """Approve an order"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE orders SET status = 'approved', approved_at = ?, approved_by = ?
        WHERE id = ?
    ''', (datetime.now(), admin_id, order_id))
    conn.commit()
    conn.close()

def reject_order(order_id, admin_id):
    """Reject an order"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE orders SET status = 'rejected', approved_at = ?, approved_by = ?
        WHERE id = ?
    ''', (datetime.now(), admin_id, order_id))
    conn.commit()
    conn.close()

def get_order(order_id):
    """Get order by ID"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM orders WHERE id = ?', (order_id,))
    order = cursor.fetchone()
    conn.close()
    return order

def get_user_orders(telegram_id, limit=10):
    """Get recent orders for a user"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, server_id, plan_id, amount, status, created_at, payment_screenshot
        FROM orders 
        WHERE telegram_id = ?
        ORDER BY created_at DESC
        LIMIT ?
    ''', (telegram_id, limit))
    rows = cursor.fetchall()
    conn.close()
    
    orders = []
    for row in rows:
        orders.append({
            'id': row[0],
            'server_id': row[1],
            'plan_id': row[2],
            'amount': row[3],
            'status': row[4],
            'created_at': row[5] if isinstance(row[5], (int, float)) else 0,
            'screenshot_hash': row[6][:20] if row[6] else None  # Use partial file_id as hash
        })
    return orders

def save_vpn_key(telegram_id, order_id, server_id, client_email, client_id, sub_link, config_link, data_limit, expiry_date):
    """Save VPN key to database"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO vpn_keys (telegram_id, order_id, server_id, client_email, client_id, sub_link, config_link, data_limit, expiry_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (telegram_id, order_id, server_id, client_email, client_id, sub_link, config_link, data_limit, expiry_date))
        conn.commit()
        key_id = cursor.lastrowid
        conn.close()
        return key_id
    except Exception as e:
        print(f"Error saving VPN key: {e}")
        conn.close()
        return None

def get_user_keys(telegram_id):
    """Get all VPN keys for a user"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM vpn_keys WHERE telegram_id = ? AND is_active = 1
        ORDER BY created_at ASC
    ''', (telegram_id,))
    keys = cursor.fetchall()
    conn.close()
    return keys

def get_vpn_key_by_id(key_id):
    """Get VPN key by ID"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM vpn_keys WHERE id = ?', (key_id,))
    key = cursor.fetchone()
    conn.close()
    return key

def update_vpn_key(key_id, sub_link, config_link, client_email, client_id):
    """Update VPN key with new protocol info"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            UPDATE vpn_keys 
            SET sub_link = ?, config_link = ?, client_email = ?, client_id = ?
            WHERE id = ?
        ''', (sub_link, config_link, client_email, client_id, key_id))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error updating VPN key: {e}")
        conn.close()
        return False

def deactivate_vpn_key(key_id):
    """Deactivate a VPN key (mark as not active)"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            UPDATE vpn_keys 
            SET is_active = 0
            WHERE id = ?
        ''', (key_id,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error deactivating VPN key: {e}")
        conn.close()
        return False

def get_expiring_keys(days=3):
    """Get keys expiring within specified days"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    expiry_threshold = datetime.now() + timedelta(days=days)
    cursor.execute('''
        SELECT * FROM vpn_keys 
        WHERE is_active = 1 AND expiry_date <= ? AND expiry_date > ?
    ''', (expiry_threshold, datetime.now()))
    keys = cursor.fetchall()
    conn.close()
    return keys

def get_user_active_keys(telegram_id):
    """Get user's active keys with server info"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, server_id, client_id, expiry_date FROM vpn_keys 
        WHERE telegram_id = ? AND is_active = 1
        ORDER BY expiry_date DESC
    ''', (telegram_id,))
    keys = cursor.fetchall()
    conn.close()
    return keys

def extend_key_expiry(key_id, days):
    """Extend VPN key expiry by specified days"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    try:
        # Get current expiry
        cursor.execute('SELECT expiry_date FROM vpn_keys WHERE id = ?', (key_id,))
        result = cursor.fetchone()
        if not result:
            conn.close()
            return None
        
        current_expiry = result[0]
        if isinstance(current_expiry, str):
            current_expiry = datetime.strptime(current_expiry, '%Y-%m-%d %H:%M:%S')
        
        # Calculate new expiry
        new_expiry = current_expiry + timedelta(days=days)
        
        # Update in database
        cursor.execute('''
            UPDATE vpn_keys SET expiry_date = ? WHERE id = ?
        ''', (new_expiry, key_id))
        conn.commit()
        conn.close()
        return new_expiry
    except Exception as e:
        print(f"Error extending key expiry: {e}")
        conn.close()
        return None

def get_all_orders(status=None):
    """Get all orders, optionally filtered by status"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    if status:
        cursor.execute('SELECT * FROM orders WHERE status = ? ORDER BY created_at DESC', (status,))
    else:
        cursor.execute('SELECT * FROM orders ORDER BY created_at DESC')
    orders = cursor.fetchall()
    conn.close()
    return orders

def get_sales_stats():
    """Get sales statistics"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Total sales
    cursor.execute('SELECT SUM(amount) FROM orders WHERE status = "approved"')
    total_sales = cursor.fetchone()[0] or 0
    
    # Today's sales
    today = datetime.now().date()
    cursor.execute('''
        SELECT SUM(amount) FROM orders 
        WHERE status = "approved" AND DATE(approved_at) = ?
    ''', (today,))
    today_sales = cursor.fetchone()[0] or 0
    
    # Total users
    cursor.execute('SELECT COUNT(*) FROM users')
    total_users = cursor.fetchone()[0] or 0
    
    # Total active keys
    cursor.execute('SELECT COUNT(*) FROM vpn_keys WHERE is_active = 1')
    active_keys = cursor.fetchone()[0] or 0
    
    # Pending orders
    cursor.execute('SELECT COUNT(*) FROM orders WHERE status = "pending"')
    pending_orders = cursor.fetchone()[0] or 0
    
    conn.close()
    
    return {
        'total_sales': total_sales,
        'today_sales': today_sales,
        'total_users': total_users,
        'active_keys': active_keys,
        'pending_orders': pending_orders
    }

# ===================== SECURITY FUNCTIONS =====================

def ban_user(telegram_id, reason=""):
    """Ban a user"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute('UPDATE users SET is_banned = 1 WHERE telegram_id = ?', (telegram_id,))
        # Log the ban
        cursor.execute('''
            INSERT INTO security_logs (telegram_id, event_type, details)
            VALUES (?, 'USER_BANNED', ?)
        ''', (telegram_id, reason))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error banning user: {e}")
        return False
    finally:
        conn.close()

def unban_user(telegram_id):
    """Unban a user"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute('UPDATE users SET is_banned = 0 WHERE telegram_id = ?', (telegram_id,))
        cursor.execute('''
            INSERT INTO security_logs (telegram_id, event_type, details)
            VALUES (?, 'USER_UNBANNED', '')
        ''', (telegram_id,))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error unbanning user: {e}")
        return False
    finally:
        conn.close()

def is_user_banned_db(telegram_id):
    """Check if user is banned in database"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT is_banned FROM users WHERE telegram_id = ?', (telegram_id,))
    result = cursor.fetchone()
    conn.close()
    return result and result[0] == 1

def log_security_event(telegram_id, event_type, details=""):
    """Log security event to database"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO security_logs (telegram_id, event_type, details)
            VALUES (?, ?, ?)
        ''', (telegram_id, event_type, details))
        conn.commit()
    except Exception as e:
        print(f"Error logging security event: {e}")
    finally:
        conn.close()

def get_security_logs(limit=100):
    """Get recent security logs"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM security_logs 
        ORDER BY created_at DESC 
        LIMIT ?
    ''', (limit,))
    logs = cursor.fetchall()
    conn.close()
    return logs

def get_all_users():
    """Get all users"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users ORDER BY created_at DESC')
    users = cursor.fetchall()
    conn.close()
    return users

# ===================== REFERRAL SYSTEM =====================

def generate_referral_code(telegram_id):
    """Generate unique referral code for user"""
    import hashlib
    # Create a unique code based on telegram_id
    hash_input = f"{telegram_id}_vpnbot_ref"
    code = hashlib.md5(hash_input.encode()).hexdigest()[:8].upper()
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET referral_code = ? WHERE telegram_id = ?', (code, telegram_id))
    conn.commit()
    conn.close()
    return code

def get_referral_code(telegram_id):
    """Get user's referral code"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT referral_code FROM users WHERE telegram_id = ?', (telegram_id,))
    result = cursor.fetchone()
    conn.close()
    
    if result and result[0]:
        return result[0]
    else:
        # Generate new code if doesn't exist
        return generate_referral_code(telegram_id)

def get_user_by_referral_code(code):
    """Get user by their referral code"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT telegram_id FROM users WHERE referral_code = ?', (code.upper(),))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

def add_referral(referrer_id, referred_id):
    """Add a new referral relationship"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Check if user is already referred by someone
    cursor.execute('SELECT id FROM referrals WHERE referred_id = ?', (referred_id,))
    if cursor.fetchone():
        conn.close()
        return False, "already_referred"
    
    # Check self-referral
    if referrer_id == referred_id:
        conn.close()
        return False, "self_referral"
    
    try:
        cursor.execute('''
            INSERT INTO referrals (referrer_id, referred_id)
            VALUES (?, ?)
        ''', (referrer_id, referred_id))
        conn.commit()
        conn.close()
        return True, "success"
    except Exception as e:
        conn.close()
        return False, str(e)

def mark_referral_paid(referred_id, order_id):
    """Mark referral as paid when referred user makes a purchase"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Get the referral record
    cursor.execute('''
        SELECT id, referrer_id, is_paid FROM referrals 
        WHERE referred_id = ? AND is_paid = 0
    ''', (referred_id,))
    referral = cursor.fetchone()
    
    if not referral:
        conn.close()
        return None  # No unpaid referral found
    
    referral_id, referrer_id, is_paid = referral
    
    # Mark as paid
    cursor.execute('''
        UPDATE referrals SET is_paid = 1, paid_at = ?, order_id = ?
        WHERE id = ?
    ''', (datetime.now(), order_id, referral_id))
    
    # Add 5 Days bonus to referrer
    cursor.execute('''
        UPDATE users SET referral_bonus_days = COALESCE(referral_bonus_days, 0) + 5
        WHERE telegram_id = ?
    ''', (referrer_id,))
    
    conn.commit()
    conn.close()
    
    return referrer_id

def get_referral_stats(telegram_id):
    """Get referral statistics for a user"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Total referred users (signed up through link)
    cursor.execute('''
        SELECT COUNT(*) FROM referrals WHERE referrer_id = ?
    ''', (telegram_id,))
    result = cursor.fetchone()
    total_referred = result[0] if result else 0
    
    # Paid referrals (referred users who made a purchase)
    cursor.execute('''
        SELECT COUNT(*) FROM referrals WHERE referrer_id = ? AND is_paid = 1
    ''', (telegram_id,))
    result = cursor.fetchone()
    paid_referrals = result[0] if result else 0
    
    # Get bonus Days
    cursor.execute('''
        SELECT COALESCE(referral_bonus_days, 0) FROM users WHERE telegram_id = ?
    ''', (telegram_id,))
    result = cursor.fetchone()
    bonus_days = result[0] if result else 0
    
    # Get claimed free months
    cursor.execute('''
        SELECT COUNT(*) FROM referral_rewards 
        WHERE telegram_id = ? AND reward_type = 'free_month'
    ''', (telegram_id,))
    result = cursor.fetchone()
    claimed_free_months = result[0] if result else 0
    
    conn.close()
    
    return {
        'total_referred': total_referred,
        'paid_referrals': paid_referrals,
        'bonus_days': bonus_days,
        'claimed_free_months': claimed_free_months,
        'can_claim_free_month': paid_referrals >= 3 and paid_referrals // 3 > claimed_free_months
    }

def claim_free_month_reward(telegram_id):
    """Claim free month reward for 3 paid referrals"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Check eligibility
    stats = get_referral_stats(telegram_id)
    if not stats['can_claim_free_month']:
        conn.close()
        return False, "not_eligible"
    
    try:
        cursor.execute('''
            INSERT INTO referral_rewards (telegram_id, reward_type, reward_value, referral_count)
            VALUES (?, 'free_month', '1 month free key', ?)
        ''', (telegram_id, stats['paid_referrals']))
        conn.commit()
        conn.close()
        return True, "success"
    except Exception as e:
        conn.close()
        return False, str(e)

def get_referrer_id(referred_id):
    """Get the referrer ID for a user"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT referrer_id FROM referrals WHERE referred_id = ?', (referred_id,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

def use_bonus_days(telegram_id, days_amount):
    """Use bonus Days from referral rewards"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute('SELECT referral_bonus_days FROM users WHERE telegram_id = ?', (telegram_id,))
    current_bonus = cursor.fetchone()[0] or 0
    
    if current_bonus < days_amount:
        conn.close()
        return False
    
    cursor.execute('''
        UPDATE users SET referral_bonus_days = referral_bonus_days - ?
        WHERE telegram_id = ?
    ''', (days_amount, telegram_id))
    conn.commit()
    conn.close()
    return True

def get_referred_users_details(referrer_id):
    """Get detailed list of referred users with their order info"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Get all referrals with user info and order details
    cursor.execute('''
        SELECT 
            r.referred_id,
            r.referred_at,
            r.is_paid,
            r.paid_at,
            r.order_id,
            u.username,
            u.first_name,
            o.plan_id,
            o.amount,
            o.status
        FROM referrals r
        LEFT JOIN users u ON r.referred_id = u.telegram_id
        LEFT JOIN orders o ON r.order_id = o.id
        WHERE r.referrer_id = ?
        ORDER BY r.referred_at DESC
    ''', (referrer_id,))
    
    results = cursor.fetchall()
    conn.close()
    
    referred_users = []
    for row in results:
        referred_users.append({
            'user_id': row[0],
            'referred_at': row[1],
            'is_paid': row[2],
            'paid_at': row[3],
            'order_id': row[4],
            'username': row[5],
            'first_name': row[6],
            'plan_id': row[7],
            'amount': row[8],
            'order_status': row[9]
        })
    
    return referred_users

# ==================== FEATURE FLAGS ====================

def get_feature_flag(flag_name):
    """Get feature flag status from database"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT is_enabled FROM feature_flags WHERE flag_name = ?', (flag_name,))
    result = cursor.fetchone()
    conn.close()
    return bool(result[0]) if result else True  # Default to True if not found

def set_feature_flag(flag_name, is_enabled, updated_by=None):
    """Set feature flag status in database"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO feature_flags (flag_name, is_enabled, updated_at, updated_by)
            VALUES (?, ?, CURRENT_TIMESTAMP, ?)
            ON CONFLICT(flag_name) DO UPDATE SET 
                is_enabled = excluded.is_enabled,
                updated_at = CURRENT_TIMESTAMP,
                updated_by = excluded.updated_by
        ''', (flag_name, 1 if is_enabled else 0, updated_by))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error setting feature flag: {e}")
        return False
    finally:
        conn.close()

def get_all_feature_flags():
    """Get all feature flags from database"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT flag_name, is_enabled FROM feature_flags')
    results = cursor.fetchall()
    conn.close()
    return {row[0]: bool(row[1]) for row in results}

# ==================== PROTOCOL SETTINGS ====================

def get_protocol_enabled(protocol_name):
    """Check if a protocol is enabled"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT is_enabled FROM protocol_settings WHERE protocol_name = ?', (protocol_name,))
    result = cursor.fetchone()
    conn.close()
    return bool(result[0]) if result else True  # Default to True if not found

def set_protocol_enabled(protocol_name, is_enabled, updated_by=None):
    """Set protocol enabled/disabled status"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO protocol_settings (protocol_name, display_name, is_enabled, updated_at, updated_by)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP, ?)
            ON CONFLICT(protocol_name) DO UPDATE SET 
                is_enabled = excluded.is_enabled,
                updated_at = CURRENT_TIMESTAMP,
                updated_by = excluded.updated_by
        ''', (protocol_name, protocol_name.upper(), 1 if is_enabled else 0, updated_by))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error setting protocol status: {e}")
        return False
    finally:
        conn.close()

def get_all_protocol_settings():
    """Get all protocol settings from database"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT protocol_name, display_name, is_enabled FROM protocol_settings')
    results = cursor.fetchall()
    conn.close()
    return {row[0]: {'display_name': row[1], 'is_enabled': bool(row[2])} for row in results}

def get_enabled_protocols():
    """Get list of enabled protocol names"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT protocol_name FROM protocol_settings WHERE is_enabled = 1')
    results = cursor.fetchall()
    conn.close()
    return [row[0] for row in results]

# ==================== USER BAN SYSTEM ====================

def ban_user(telegram_id, reason=None, duration_hours=None, banned_by=None):
    """
    Ban a user (temporary or permanent)
    duration_hours: None = permanent, number = temporary ban in hours
    """
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    banned_until = None
    if duration_hours:
        banned_until = datetime.now() + timedelta(hours=duration_hours)
    
    try:
        # Deactivate any existing active bans for this user
        cursor.execute('''
            UPDATE user_bans SET is_active = 0 WHERE telegram_id = ? AND is_active = 1
        ''', (telegram_id,))
        
        # Create new ban
        cursor.execute('''
            INSERT INTO user_bans (telegram_id, reason, banned_until, banned_by)
            VALUES (?, ?, ?, ?)
        ''', (telegram_id, reason, banned_until, banned_by))
        
        # Also update users table
        cursor.execute('UPDATE users SET is_banned = 1 WHERE telegram_id = ?', (telegram_id,))
        
        conn.commit()
        return True
    except Exception as e:
        print(f"Error banning user: {e}")
        return False
    finally:
        conn.close()

def unban_user(telegram_id, unbanned_by=None):
    """Unban a user"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            UPDATE user_bans 
            SET is_active = 0, unbanned_at = CURRENT_TIMESTAMP, unbanned_by = ?
            WHERE telegram_id = ? AND is_active = 1
        ''', (unbanned_by, telegram_id))
        
        cursor.execute('UPDATE users SET is_banned = 0 WHERE telegram_id = ?', (telegram_id,))
        
        conn.commit()
        return True
    except Exception as e:
        print(f"Error unbanning user: {e}")
        return False
    finally:
        conn.close()

def is_user_banned(telegram_id):
    """
    Check if user is currently banned
    Returns: dict with ban info or None if not banned
    """
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT reason, banned_at, banned_until, banned_by
        FROM user_bans 
        WHERE telegram_id = ? AND is_active = 1
        ORDER BY banned_at DESC LIMIT 1
    ''', (telegram_id,))
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        return None
    
    reason, banned_at, banned_until, banned_by = result
    
    # Check if temporary ban has expired
    if banned_until:
        if datetime.now() > datetime.fromisoformat(banned_until):
            # Ban expired, auto-unban
            unban_user(telegram_id)
            return None
    
    return {
        'reason': reason,
        'banned_at': banned_at,
        'banned_until': banned_until,
        'banned_by': banned_by,
        'is_permanent': banned_until is None
    }

def get_banned_users():
    """Get list of all currently banned users"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT b.telegram_id, b.reason, b.banned_at, b.banned_until, b.banned_by,
               u.username, u.first_name
        FROM user_bans b
        LEFT JOIN users u ON b.telegram_id = u.telegram_id
        WHERE b.is_active = 1
        ORDER BY b.banned_at DESC
    ''')
    results = cursor.fetchall()
    conn.close()
    
    banned_users = []
    for row in results:
        # Check if temporary ban expired
        if row[3]:  # banned_until exists
            if datetime.now() > datetime.fromisoformat(row[3]):
                unban_user(row[0])  # Auto-unban
                continue
        
        banned_users.append({
            'telegram_id': row[0],
            'reason': row[1],
            'banned_at': row[2],
            'banned_until': row[3],
            'banned_by': row[4],
            'username': row[5],
            'first_name': row[6],
            'is_permanent': row[3] is None
        })
    
    return banned_users

def get_user_ban_history(telegram_id):
    """Get ban history for a user"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT reason, banned_at, banned_until, banned_by, is_active, unbanned_at
        FROM user_bans 
        WHERE telegram_id = ?
        ORDER BY banned_at DESC
    ''', (telegram_id,))
    results = cursor.fetchall()
    conn.close()
    
    return [{
        'reason': row[0],
        'banned_at': row[1],
        'banned_until': row[2],
        'banned_by': row[3],
        'is_active': bool(row[4]),
        'unbanned_at': row[5]
    } for row in results]

# ==================== STATISTICS ====================

def get_statistics(period='all'):
    """
    Get comprehensive statistics
    period: 'today', 'week', 'month', 'all'
    """
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Date filter
    date_filter = ""
    if period == 'today':
        date_filter = "AND date(created_at) = date('now')"
    elif period == 'week':
        date_filter = "AND created_at >= datetime('now', '-7 days')"
    elif period == 'month':
        date_filter = "AND created_at >= datetime('now', '-30 days')"
    
    stats = {}
    
    # Total users
    cursor.execute(f"SELECT COUNT(*) FROM users WHERE 1=1 {date_filter.replace('created_at', 'created_at')}")
    stats['total_users'] = cursor.fetchone()[0]
    
    # Total orders
    cursor.execute(f"SELECT COUNT(*) FROM orders WHERE 1=1 {date_filter}")
    stats['total_orders'] = cursor.fetchone()[0]
    
    # Completed orders
    cursor.execute(f"SELECT COUNT(*) FROM orders WHERE status = 'approved' {date_filter}")
    stats['completed_orders'] = cursor.fetchone()[0]
    
    # Pending orders
    cursor.execute(f"SELECT COUNT(*) FROM orders WHERE status = 'pending' {date_filter}")
    stats['pending_orders'] = cursor.fetchone()[0]
    
    # Rejected orders
    cursor.execute(f"SELECT COUNT(*) FROM orders WHERE status = 'rejected' {date_filter}")
    stats['rejected_orders'] = cursor.fetchone()[0]
    
    # Total revenue (from approved orders)
    cursor.execute(f"SELECT COALESCE(SUM(amount), 0) FROM orders WHERE status = 'approved' {date_filter}")
    stats['total_revenue'] = cursor.fetchone()[0]
    
    # Active VPN keys
    cursor.execute("SELECT COUNT(*) FROM vpn_keys WHERE is_active = 1")
    stats['active_keys'] = cursor.fetchone()[0]
    
    # Free tests used
    cursor.execute(f"SELECT COUNT(*) FROM free_tests WHERE 1=1 {date_filter.replace('created_at', 'used_at')}")
    stats['free_tests_used'] = cursor.fetchone()[0]
    
    # Referrals count
    cursor.execute(f"SELECT COUNT(*) FROM referrals WHERE 1=1 {date_filter.replace('created_at', 'referred_at')}")
    stats['total_referrals'] = cursor.fetchone()[0]
    
    # Paid referrals
    cursor.execute(f"SELECT COUNT(*) FROM referrals WHERE is_paid = 1 {date_filter.replace('created_at', 'referred_at')}")
    stats['paid_referrals'] = cursor.fetchone()[0]
    
    # Banned users count
    cursor.execute("SELECT COUNT(*) FROM user_bans WHERE is_active = 1")
    stats['banned_users'] = cursor.fetchone()[0]
    
    conn.close()
    return stats

def get_revenue_by_period():
    """Get revenue breakdown by day for last 7 days"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT date(approved_at) as day, SUM(amount) as revenue, COUNT(*) as orders
        FROM orders 
        WHERE status = 'approved' AND approved_at >= datetime('now', '-7 days')
        GROUP BY date(approved_at)
        ORDER BY day DESC
    ''')
    results = cursor.fetchall()
    conn.close()
    
    return [{'date': row[0], 'revenue': row[1], 'orders': row[2]} for row in results]

def get_top_users(limit=10):
    """Get top users by order amount"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT u.telegram_id, u.username, u.first_name, 
               COUNT(o.id) as order_count, 
               COALESCE(SUM(o.amount), 0) as total_spent
        FROM users u
        LEFT JOIN orders o ON u.telegram_id = o.telegram_id AND o.status = 'approved'
        GROUP BY u.telegram_id
        HAVING total_spent > 0
        ORDER BY total_spent DESC
        LIMIT ?
    ''', (limit,))
    results = cursor.fetchall()
    conn.close()
    
    return [{
        'telegram_id': row[0],
        'username': row[1],
        'first_name': row[2],
        'order_count': row[3],
        'total_spent': row[4]
    } for row in results]

# ==================== SERVER MANAGEMENT ====================

def add_server(server_id, name, url, panel_path, domain, panel_type='xui', 
               sub_port=2096, api_key=None, admin_uuid=None, proxy_path=None, 
               user_sub_path=None, created_by=None):
    """Add a new server to database"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO servers (server_id, name, url, panel_path, domain, panel_type,
                               sub_port, api_key, admin_uuid, proxy_path, user_sub_path, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (server_id, name, url, panel_path, domain, panel_type, 
              sub_port, api_key, admin_uuid, proxy_path, user_sub_path, created_by))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False  # Server ID already exists
    except Exception as e:
        print(f"Error adding server: {e}")
        return False
    finally:
        conn.close()

def update_server(server_id, **kwargs):
    """Update server settings"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Build update query dynamically
    valid_fields = ['name', 'url', 'panel_path', 'domain', 'panel_type', 
                    'sub_port', 'api_key', 'admin_uuid', 'proxy_path', 
                    'user_sub_path', 'is_active']
    
    updates = []
    values = []
    for field, value in kwargs.items():
        if field in valid_fields:
            updates.append(f"{field} = ?")
            values.append(value)
    
    if not updates:
        return False
    
    updates.append("updated_at = CURRENT_TIMESTAMP")
    values.append(server_id)
    
    try:
        cursor.execute(f'''
            UPDATE servers SET {', '.join(updates)} WHERE server_id = ?
        ''', values)
        conn.commit()
        return cursor.rowcount > 0
    except Exception as e:
        print(f"Error updating server: {e}")
        return False
    finally:
        conn.close()

def delete_server(server_id):
    """Delete a server from database"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute('DELETE FROM servers WHERE server_id = ?', (server_id,))
        conn.commit()
        return cursor.rowcount > 0
    except Exception as e:
        print(f"Error deleting server: {e}")
        return False
    finally:
        conn.close()

def get_server(server_id):
    """Get a specific server by ID"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM servers WHERE server_id = ?', (server_id,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return None
    
    return {
        'id': row[0],
        'server_id': row[1],
        'name': row[2],
        'url': row[3],
        'panel_path': row[4],
        'domain': row[5],
        'panel_type': row[6],
        'sub_port': row[7],
        'api_key': row[8],
        'admin_uuid': row[9],
        'proxy_path': row[10],
        'user_sub_path': row[11],
        'is_active': bool(row[12]),
        'created_at': row[13],
        'created_by': row[14],
        'updated_at': row[15]
    }

def get_all_db_servers(active_only=True):
    """Get all servers from database"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    if active_only:
        cursor.execute('SELECT * FROM servers WHERE is_active = 1 ORDER BY created_at')
    else:
        cursor.execute('SELECT * FROM servers ORDER BY created_at')
    
    rows = cursor.fetchall()
    conn.close()
    
    servers = {}
    for row in rows:
        server_id = row[1]
        server_data = {
            'name': row[2],
            'url': row[3],
            'panel_path': row[4],
            'domain': row[5],
            'panel_type': row[6],
            'sub_port': row[7],
            'is_active': bool(row[12]),
            'from_database': True
        }
        
        # Add Hiddify-specific fields if present
        if row[6] == 'hiddify':
            server_data['api_key'] = row[8]
            server_data['admin_uuid'] = row[9]
            server_data['proxy_path'] = row[10]
            server_data['user_sub_path'] = row[11]
        
        servers[server_id] = server_data
    
    return servers

def toggle_server_active(server_id, is_active):
    """Toggle server active status"""
    return update_server(server_id, is_active=1 if is_active else 0)

if __name__ == "__main__":
    init_db()
