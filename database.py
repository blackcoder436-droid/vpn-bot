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
        SELECT id, server_id, plan_id, amount, status, created_at, screenshot_file_id
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

if __name__ == "__main__":
    init_db()
