import sqlite3
import logging
from contextlib import contextmanager
from datetime import datetime, timedelta
from config import DATABASE_PATH

logger = logging.getLogger(__name__)


@contextmanager
def get_db():
    """Context manager for database connections - ensures proper cleanup"""
    conn = sqlite3.connect(DATABASE_PATH, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")  # Better concurrent access
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

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
    
    # Add free_tests tracking columns
    for col_stmt in [
        'ALTER TABLE free_tests ADD COLUMN server_id TEXT',
        'ALTER TABLE free_tests ADD COLUMN protocol TEXT',
        'ALTER TABLE free_tests ADD COLUMN username TEXT',
    ]:
        try:
            cursor.execute(col_stmt)
        except:
            pass  # Column already exists
    
    # Add screenshot_unique_id to orders for duplicate detection
    try:
        cursor.execute('ALTER TABLE orders ADD COLUMN screenshot_unique_id TEXT')
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

    # Create indexes for frequently queried columns
    index_statements = [
        'CREATE INDEX IF NOT EXISTS idx_orders_telegram_id ON orders(telegram_id)',
        'CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status)',
        'CREATE INDEX IF NOT EXISTS idx_vpn_keys_telegram_id ON vpn_keys(telegram_id)',
        'CREATE INDEX IF NOT EXISTS idx_vpn_keys_active ON vpn_keys(is_active)',
        'CREATE INDEX IF NOT EXISTS idx_referrals_referrer ON referrals(referrer_id)',
        'CREATE INDEX IF NOT EXISTS idx_referrals_referred ON referrals(referred_id)',
        'CREATE INDEX IF NOT EXISTS idx_user_bans_telegram_id ON user_bans(telegram_id)',
        'CREATE INDEX IF NOT EXISTS idx_security_logs_telegram_id ON security_logs(telegram_id)',
        'CREATE INDEX IF NOT EXISTS idx_users_referral_code ON users(referral_code)',
    ]
    for stmt in index_statements:
        try:
            cursor.execute(stmt)
        except Exception:
            pass

    conn.commit()
    conn.close()
    logger.info("✅ Database initialized successfully!")

def get_user(telegram_id):
    """Get user by telegram ID"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE telegram_id = ?', (telegram_id,))
        user = cursor.fetchone()
        return user

def create_user(telegram_id, username, first_name, last_name=None):
    """Create a new user or update existing user's name/username"""
    with get_db() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO users (telegram_id, username, first_name, last_name)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(telegram_id) DO UPDATE SET
                    username = excluded.username,
                    first_name = excluded.first_name,
                    last_name = excluded.last_name
            ''', (telegram_id, username, first_name, last_name))
        except Exception as e:
            logger.error(f"Error creating user: {e}")

def has_used_free_test(telegram_id):
    """Check if user has already used free test"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM free_tests WHERE telegram_id = ?', (telegram_id,))
        result = cursor.fetchone()
        return result is not None

def mark_free_test_used(telegram_id, server_id=None, protocol=None, username=None):
    """Mark free test as used for user with server/protocol tracking"""
    with get_db() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                'INSERT INTO free_tests (telegram_id, server_id, protocol, username) VALUES (?, ?, ?, ?)',
                (telegram_id, server_id, protocol, username)
            )
        except Exception as e:
            logger.error(f"Error marking free test: {e}")

def get_free_test_stats():
    """Get all free test key data with conversion tracking"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT ft.telegram_id, ft.used_at, ft.server_id, ft.protocol, ft.username,
                   u.username as tg_username, u.first_name
            FROM free_tests ft
            LEFT JOIN users u ON ft.telegram_id = u.telegram_id
            ORDER BY ft.used_at DESC
        ''')
        rows = cursor.fetchall()
        return rows

def get_free_key_conversions():
    """Get free key users who later purchased a paid key"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT ft.telegram_id, ft.used_at, ft.server_id, ft.protocol,
                   u.username, u.first_name,
                   COUNT(DISTINCT o.id) as paid_orders,
                   SUM(o.amount) as total_spent,
                   MIN(o.created_at) as first_purchase
            FROM free_tests ft
            LEFT JOIN users u ON ft.telegram_id = u.telegram_id
            LEFT JOIN orders o ON ft.telegram_id = o.telegram_id 
                               AND o.status = 'approved' 
                               AND o.plan_id != 'free_test'
            GROUP BY ft.telegram_id
            ORDER BY paid_orders DESC, ft.used_at DESC
        ''')
        rows = cursor.fetchall()
        return rows

def get_free_key_server_stats():
    """Get free key usage aggregated by server and protocol"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT server_id, protocol, COUNT(*) as count
            FROM free_tests
            WHERE server_id IS NOT NULL
            GROUP BY server_id, protocol
            ORDER BY count DESC
        ''')
        rows = cursor.fetchall()
        return rows

def create_order(telegram_id, server_id, plan_id, amount, protocol='trojan'):
    """Create a new order"""
    with get_db() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO orders (telegram_id, server_id, plan_id, amount, protocol)
                VALUES (?, ?, ?, ?, ?)
            ''', (telegram_id, server_id, plan_id, amount, protocol))
            order_id = cursor.lastrowid
            return order_id
        except Exception as e:
            logger.error(f"Error creating order: {e}")
            return None

def update_order_screenshot(order_id, screenshot_file_id):
    """Update order with payment screenshot"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE orders SET payment_screenshot = ? WHERE id = ?
        ''', (screenshot_file_id, order_id))

def is_duplicate_screenshot(file_unique_id, current_order_id=None):
    """Check if a screenshot file_unique_id was already used in an approved/pending order.
    Returns the order_id if duplicate found, None otherwise."""
    with get_db() as conn:
        cursor = conn.cursor()
        if current_order_id:
            cursor.execute('''
                SELECT id FROM orders 
                WHERE screenshot_unique_id = ? AND id != ? AND status IN ('approved', 'pending')
                LIMIT 1
            ''', (file_unique_id, current_order_id))
        else:
            cursor.execute('''
                SELECT id FROM orders 
                WHERE screenshot_unique_id = ? AND status IN ('approved', 'pending')
                LIMIT 1
            ''', (file_unique_id,))
        result = cursor.fetchone()
        return result[0] if result else None

def save_screenshot_unique_id(order_id, file_unique_id):
    """Store the unique file ID for duplicate detection"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE orders SET screenshot_unique_id = ? WHERE id = ?
        ''', (file_unique_id, order_id))

def approve_order(order_id, admin_id):
    """Approve an order"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE orders SET status = 'approved', approved_at = ?, approved_by = ?
            WHERE id = ?
        ''', (datetime.now(), admin_id, order_id))

def approve_order_atomic(order_id, admin_id):
    """Atomically approve an order only if pending. Returns True if approved, False if already processed."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE orders SET status = 'approved', approved_at = ?, approved_by = ?
            WHERE id = ? AND status = 'pending'
        ''', (datetime.now(), admin_id, order_id))
        affected = cursor.rowcount
        return affected > 0

def reject_order(order_id, admin_id):
    """Reject an order"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE orders SET status = 'rejected', approved_at = ?, approved_by = ?
            WHERE id = ?
        ''', (datetime.now(), admin_id, order_id))

def get_order(order_id):
    """Get order by ID"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM orders WHERE id = ?', (order_id,))
        order = cursor.fetchone()
        return order

def get_user_orders(telegram_id, limit=10):
    """Get recent orders for a user"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, server_id, plan_id, amount, status, created_at, payment_screenshot
            FROM orders 
            WHERE telegram_id = ?
            ORDER BY created_at DESC
            LIMIT ?
        ''', (telegram_id, limit))
        rows = cursor.fetchall()

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
    with get_db() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO vpn_keys (telegram_id, order_id, server_id, client_email, client_id, sub_link, config_link, data_limit, expiry_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (telegram_id, order_id, server_id, client_email, client_id, sub_link, config_link, data_limit, expiry_date))
            key_id = cursor.lastrowid
            return key_id
        except Exception as e:
            logger.error(f"Error saving VPN key: {e}")
            return None

def get_user_keys(telegram_id):
    """Get all VPN keys for a user"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM vpn_keys WHERE telegram_id = ? AND is_active = 1
            ORDER BY created_at ASC
        ''', (telegram_id,))
        keys = cursor.fetchall()
        return keys

def get_vpn_key_by_id(key_id):
    """Get VPN key by ID"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM vpn_keys WHERE id = ?', (key_id,))
        key = cursor.fetchone()
        return key

def update_vpn_key(key_id, sub_link, config_link, client_email, client_id):
    """Update VPN key with new protocol info"""
    with get_db() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute('''
                UPDATE vpn_keys 
                SET sub_link = ?, config_link = ?, client_email = ?, client_id = ?
                WHERE id = ?
            ''', (sub_link, config_link, client_email, client_id, key_id))
            return True
        except Exception as e:
            logger.error(f"Error updating VPN key: {e}")
            return False

def deactivate_vpn_key(key_id):
    """Deactivate a VPN key (mark as not active)"""
    with get_db() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute('''
                UPDATE vpn_keys 
                SET is_active = 0
                WHERE id = ?
            ''', (key_id,))
            return True
        except Exception as e:
            logger.error(f"Error deactivating VPN key: {e}")
            return False

def get_expiring_keys(days=3):
    """Get keys expiring within specified days"""
    with get_db() as conn:
        cursor = conn.cursor()
        expiry_threshold = datetime.now() + timedelta(days=days)
        cursor.execute('''
            SELECT * FROM vpn_keys 
            WHERE is_active = 1 AND expiry_date <= ? AND expiry_date > ?
        ''', (expiry_threshold, datetime.now()))
        keys = cursor.fetchall()
        return keys

def get_user_active_keys(telegram_id):
    """Get user's active keys with server info"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, server_id, client_id, expiry_date FROM vpn_keys 
            WHERE telegram_id = ? AND is_active = 1
            ORDER BY expiry_date DESC
        ''', (telegram_id,))
        keys = cursor.fetchall()
        return keys

def extend_key_expiry(key_id, days):
    """Extend VPN key expiry by specified days"""
    with get_db() as conn:
        cursor = conn.cursor()
        try:
            # Get current expiry
            cursor.execute('SELECT expiry_date FROM vpn_keys WHERE id = ?', (key_id,))
            result = cursor.fetchone()
            if not result:
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
            return new_expiry
        except Exception as e:
            logger.error(f"Error extending key expiry: {e}")
            return None

def get_all_orders(status=None):
    """Get all orders, optionally filtered by status"""
    with get_db() as conn:
        cursor = conn.cursor()
        if status:
            cursor.execute('SELECT * FROM orders WHERE status = ? ORDER BY created_at DESC', (status,))
        else:
            cursor.execute('SELECT * FROM orders ORDER BY created_at DESC')
        orders = cursor.fetchall()
        return orders

def cancel_stale_orders(hours=24):
    """Cancel pending orders older than specified hours. Returns count of cancelled orders."""
    with get_db() as conn:
        cursor = conn.cursor()
        cutoff = datetime.now() - timedelta(hours=hours)
        cursor.execute('''
            UPDATE orders SET status = 'cancelled'
            WHERE status = 'pending' AND created_at < ?
        ''', (cutoff,))
        cancelled = cursor.rowcount
        if cancelled > 0:
            logger.info(f"🗑️ Cancelled {cancelled} stale pending orders (older than {hours}h)")
        return cancelled

def get_sales_stats():
    """Get sales statistics"""
    with get_db() as conn:
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


        return {
            'total_sales': total_sales,
            'today_sales': today_sales,
            'total_users': total_users,
            'active_keys': active_keys,
            'pending_orders': pending_orders
        }

# ===================== SECURITY FUNCTIONS =====================

def is_user_banned_db(telegram_id):
    """Check if user is banned in database"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT is_banned FROM users WHERE telegram_id = ?', (telegram_id,))
        result = cursor.fetchone()
        return result and result[0] == 1

def log_security_event(telegram_id, event_type, details=""):
    """Log security event to database"""
    with get_db() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO security_logs (telegram_id, event_type, details)
                VALUES (?, ?, ?)
            ''', (telegram_id, event_type, details))
        except Exception as e:
            logger.error(f"Error logging security event: {e}")

def get_security_logs(limit=100):
    """Get recent security logs"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM security_logs 
            ORDER BY created_at DESC 
            LIMIT ?
        ''', (limit,))
        logs = cursor.fetchall()
        return logs

def get_all_users():
    """Get all users"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users ORDER BY created_at DESC')
        users = cursor.fetchall()
        return users

# ===================== REFERRAL SYSTEM =====================

def generate_referral_code(telegram_id):
    """Generate unique referral code for user"""
    import hashlib
    # Create a unique code based on telegram_id
    hash_input = f"{telegram_id}_vpnbot_ref"
    code = hashlib.md5(hash_input.encode()).hexdigest()[:8].upper()
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET referral_code = ? WHERE telegram_id = ?', (code, telegram_id))
        return code

def get_referral_code(telegram_id):
    """Get user's referral code"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT referral_code FROM users WHERE telegram_id = ?', (telegram_id,))
        result = cursor.fetchone()

        if result and result[0]:
            return result[0]
        else:
            # Generate new code if doesn't exist
            return generate_referral_code(telegram_id)

def get_user_by_referral_code(code):
    """Get user by their referral code"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT telegram_id FROM users WHERE referral_code = ?', (code.upper(),))
        result = cursor.fetchone()
        return result[0] if result else None

def add_referral(referrer_id, referred_id):
    """Add a new referral relationship"""
    with get_db() as conn:
        cursor = conn.cursor()

        # Check if user is already referred by someone
        cursor.execute('SELECT id FROM referrals WHERE referred_id = ?', (referred_id,))
        if cursor.fetchone():
            return False, "already_referred"

        # Check self-referral
        if referrer_id == referred_id:
            return False, "self_referral"

        try:
            cursor.execute('''
                INSERT INTO referrals (referrer_id, referred_id)
                VALUES (?, ?)
            ''', (referrer_id, referred_id))
            return True, "success"
        except Exception as e:
            return False, str(e)

def mark_referral_paid(referred_id, order_id):
    """Mark referral as paid when referred user makes a purchase"""
    with get_db() as conn:
        cursor = conn.cursor()

        # Get the referral record
        cursor.execute('''
            SELECT id, referrer_id, is_paid FROM referrals 
            WHERE referred_id = ? AND is_paid = 0
        ''', (referred_id,))
        referral = cursor.fetchone()

        if not referral:
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


        return referrer_id

def get_referral_stats(telegram_id):
    """Get referral statistics for a user"""
    with get_db() as conn:
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


        return {
            'total_referred': total_referred,
            'paid_referrals': paid_referrals,
            'bonus_days': bonus_days,
            'claimed_free_months': claimed_free_months,
            'can_claim_free_month': paid_referrals >= 3 and paid_referrals // 3 > claimed_free_months
        }

def claim_free_month_reward(telegram_id):
    """Claim free month reward for 3 paid referrals"""
    with get_db() as conn:
        cursor = conn.cursor()

        # Check eligibility
        stats = get_referral_stats(telegram_id)
        if not stats['can_claim_free_month']:
            return False, "not_eligible"

        try:
            cursor.execute('''
                INSERT INTO referral_rewards (telegram_id, reward_type, reward_value, referral_count)
                VALUES (?, 'free_month', '1 month free key', ?)
            ''', (telegram_id, stats['paid_referrals']))
            return True, "success"
        except Exception as e:
            return False, str(e)

def get_referrer_id(referred_id):
    """Get the referrer ID for a user"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT referrer_id FROM referrals WHERE referred_id = ?', (referred_id,))
        result = cursor.fetchone()
        return result[0] if result else None

def use_bonus_days(telegram_id, days_amount):
    """Use bonus Days from referral rewards"""
    with get_db() as conn:
        cursor = conn.cursor()

        cursor.execute('SELECT referral_bonus_days FROM users WHERE telegram_id = ?', (telegram_id,))
        current_bonus = cursor.fetchone()[0] or 0

        if current_bonus < days_amount:
            return False

        cursor.execute('''
            UPDATE users SET referral_bonus_days = referral_bonus_days - ?
            WHERE telegram_id = ?
        ''', (days_amount, telegram_id))
        return True

def get_referred_users_details(referrer_id):
    """Get detailed list of referred users with their order info"""
    with get_db() as conn:
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
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT is_enabled FROM feature_flags WHERE flag_name = ?', (flag_name,))
        result = cursor.fetchone()
        return bool(result[0]) if result else True  # Default to True if not found

def set_feature_flag(flag_name, is_enabled, updated_by=None):
    """Set feature flag status in database"""
    with get_db() as conn:
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
            return True
        except Exception as e:
            logger.error(f"Error setting feature flag: {e}")
            return False

def get_all_feature_flags():
    """Get all feature flags from database"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT flag_name, is_enabled FROM feature_flags')
        results = cursor.fetchall()
        return {row[0]: bool(row[1]) for row in results}

# ==================== PROTOCOL SETTINGS ====================

def get_protocol_enabled(protocol_name):
    """Check if a protocol is enabled"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT is_enabled FROM protocol_settings WHERE protocol_name = ?', (protocol_name,))
        result = cursor.fetchone()
        return bool(result[0]) if result else True  # Default to True if not found

def set_protocol_enabled(protocol_name, is_enabled, updated_by=None):
    """Set protocol enabled/disabled status"""
    with get_db() as conn:
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
            return True
        except Exception as e:
            logger.error(f"Error setting protocol status: {e}")
            return False

def get_all_protocol_settings():
    """Get all protocol settings from database"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT protocol_name, display_name, is_enabled FROM protocol_settings')
        results = cursor.fetchall()
        return {row[0]: {'display_name': row[1], 'is_enabled': bool(row[2])} for row in results}

def get_enabled_protocols():
    """Get list of enabled protocol names"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT protocol_name FROM protocol_settings WHERE is_enabled = 1')
        results = cursor.fetchall()
        return [row[0] for row in results]

# ==================== USER BAN SYSTEM ====================

def ban_user(telegram_id, reason=None, duration_hours=None, banned_by=None):
    """
    Ban a user (temporary or permanent)
    duration_hours: None = permanent, number = temporary ban in hours
    """
    with get_db() as conn:
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

            return True
        except Exception as e:
            logger.error(f"Error banning user: {e}")
            return False

def unban_user(telegram_id, unbanned_by=None):
    """Unban a user"""
    with get_db() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute('''
                UPDATE user_bans 
                SET is_active = 0, unbanned_at = CURRENT_TIMESTAMP, unbanned_by = ?
                WHERE telegram_id = ? AND is_active = 1
            ''', (unbanned_by, telegram_id))

            cursor.execute('UPDATE users SET is_banned = 0 WHERE telegram_id = ?', (telegram_id,))

            return True
        except Exception as e:
            logger.error(f"Error unbanning user: {e}")
            return False

def is_user_banned(telegram_id):
    """
    Check if user is currently banned
    Returns: dict with ban info or None if not banned
    """
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT reason, banned_at, banned_until, banned_by
            FROM user_bans 
            WHERE telegram_id = ? AND is_active = 1
            ORDER BY banned_at DESC LIMIT 1
        ''', (telegram_id,))
        result = cursor.fetchone()

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
    with get_db() as conn:
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
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT reason, banned_at, banned_until, banned_by, is_active, unbanned_at
            FROM user_bans 
            WHERE telegram_id = ?
            ORDER BY banned_at DESC
        ''', (telegram_id,))
        results = cursor.fetchall()

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
    with get_db() as conn:
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

        return stats

def get_revenue_by_period():
    """Get revenue breakdown by day for last 7 days"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT date(approved_at) as day, SUM(amount) as revenue, COUNT(*) as orders
            FROM orders 
            WHERE status = 'approved' AND approved_at >= datetime('now', '-7 days')
            GROUP BY date(approved_at)
            ORDER BY day DESC
        ''')
        results = cursor.fetchall()

        return [{'date': row[0], 'revenue': row[1], 'orders': row[2]} for row in results]

def get_top_users(limit=10):
    """Get top users by order amount"""
    with get_db() as conn:
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
    with get_db() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO servers (server_id, name, url, panel_path, domain, panel_type,
                                   sub_port, api_key, admin_uuid, proxy_path, user_sub_path, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (server_id, name, url, panel_path, domain, panel_type, 
                  sub_port, api_key, admin_uuid, proxy_path, user_sub_path, created_by))
            return True
        except sqlite3.IntegrityError:
            return False  # Server ID already exists
        except Exception as e:
            logger.error(f"Error adding server: {e}")
            return False

def update_server(server_id, **kwargs):
    """Update server settings"""
    with get_db() as conn:
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
            return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Error updating server: {e}")
            return False

def delete_server(server_id):
    """Delete a server from database"""
    with get_db() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute('DELETE FROM servers WHERE server_id = ?', (server_id,))
            return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Error deleting server: {e}")
            return False

def get_server(server_id):
    """Get a specific server by ID"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM servers WHERE server_id = ?', (server_id,))
        row = cursor.fetchone()

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
    with get_db() as conn:
        cursor = conn.cursor()

        if active_only:
            cursor.execute('SELECT * FROM servers WHERE is_active = 1 ORDER BY created_at')
        else:
            cursor.execute('SELECT * FROM servers ORDER BY created_at')

        rows = cursor.fetchall()

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

            servers[server_id] = server_data

        return servers

def toggle_server_active(server_id, is_active):
    """Toggle server active status"""
    return update_server(server_id, is_active=1 if is_active else 0)

if __name__ == "__main__":
    init_db()
