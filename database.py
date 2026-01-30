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

def get_all_users():
    """Get all users"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users ORDER BY created_at DESC')
    users = cursor.fetchall()
    conn.close()
    return users

if __name__ == "__main__":
    init_db()
