"""
Burmese Digital Store - VPN Website Server
Flask web server with Telegram bot integration
"""

import os
import sys
import sqlite3
from datetime import datetime
from flask import Flask, render_template, jsonify, request

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from config import DATABASE_PATH, SERVERS, PLANS, PAYMENT_INFO
except ImportError:
    # Fallback defaults if config not available
    DATABASE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'vpn_bot.db')
    SERVERS = {}
    PLANS = {}
    PAYMENT_INFO = {}

app = Flask(__name__)


# ============ Helper Functions ============

def get_db():
    """Get database connection"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception:
        return None


def get_stats():
    """Get basic statistics for the website"""
    stats = {
        'total_users': 0,
        'total_orders': 0,
        'active_keys': 0,
        'servers_online': len(SERVERS) if SERVERS else 5,
    }
    
    conn = get_db()
    if conn:
        try:
            cursor = conn.cursor()
            
            # Total users
            cursor.execute("SELECT COUNT(*) FROM users")
            stats['total_users'] = cursor.fetchone()[0]
            
            # Total completed orders
            cursor.execute("SELECT COUNT(*) FROM orders WHERE status = 'approved'")
            stats['total_orders'] = cursor.fetchone()[0]
            
            # Active keys
            cursor.execute("SELECT COUNT(*) FROM vpn_keys WHERE status = 'active'")
            stats['active_keys'] = cursor.fetchone()[0]
            
            conn.close()
        except Exception:
            if conn:
                conn.close()
    
    return stats


def get_server_status():
    """Get server status information"""
    servers = []
    server_flags = {
        'sg1': '🇸🇬', 'sg2': '🇸🇬', 'sg3': '🇸🇬',
        'us1': '🇺🇸',
        'hiddify1': '🌐'
    }
    server_names = {
        'sg1': 'Singapore 1', 'sg2': 'Singapore 2', 'sg3': 'Singapore 3',
        'us1': 'United States',
        'hiddify1': 'Hiddify Multi'
    }
    
    if SERVERS:
        for sid, sdata in SERVERS.items():
            servers.append({
                'id': sid,
                'name': server_names.get(sid, sdata.get('name', sid)),
                'flag': server_flags.get(sid, '🌐'),
                'status': 'online',  # Could add actual health checks
                'type': sdata.get('panel_type', 'xui')
            })
    else:
        # Fallback server list
        for sid in ['sg1', 'sg2', 'sg3', 'us1', 'hiddify1']:
            servers.append({
                'id': sid,
                'name': server_names[sid],
                'flag': server_flags[sid],
                'status': 'online',
                'type': 'xui'
            })
    
    return servers


# ============ Routes ============

@app.route('/')
def index():
    """Main landing page"""
    return render_template('index.html')


@app.route('/api/stats')
def api_stats():
    """API endpoint for website statistics"""
    stats = get_stats()
    return jsonify({
        'success': True,
        'data': stats
    })


@app.route('/api/servers')
def api_servers():
    """API endpoint for server status"""
    servers = get_server_status()
    return jsonify({
        'success': True,
        'data': servers
    })


@app.route('/api/plans')
def api_plans():
    """API endpoint for pricing plans"""
    plans_data = {}
    if PLANS:
        for plan_id, plan in PLANS.items():
            plans_data[plan_id] = {
                'devices': plan.get('devices', 1),
                'months': plan.get('months', 1),
                'price': plan.get('price', 0),
                'description': plan.get('description', '')
            }
    
    return jsonify({
        'success': True,
        'data': plans_data
    })


@app.route('/api/health')
def api_health():
    """Health check endpoint"""
    return jsonify({
        'status': 'ok',
        'timestamp': datetime.now().isoformat(),
        'service': 'Burmese Digital Store'
    })


# ============ Error Handlers ============

@app.errorhandler(404)
def not_found(error):
    """404 error handler"""
    if request.path.startswith('/api/'):
        return jsonify({'success': False, 'error': 'Not found'}), 404
    return render_template('index.html'), 404


@app.errorhandler(500)
def server_error(error):
    """500 error handler"""
    if request.path.startswith('/api/'):
        return jsonify({'success': False, 'error': 'Internal server error'}), 500
    return render_template('index.html'), 500


# ============ Main ============

if __name__ == '__main__':
    port = int(os.environ.get('WEB_PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    
    print(f"""
╔══════════════════════════════════════════╗
║    Burmese Digital Store - Web Server    ║
╠══════════════════════════════════════════╣
║  🌐 URL: http://0.0.0.0:{port:<16} ║
║  🔧 Debug: {str(debug):<29} ║
║  📂 Template: templates/               ║
║  📁 Static: static/                    ║
╚══════════════════════════════════════════╝
    """)
    
    app.run(
        host='0.0.0.0',
        port=port,
        debug=debug
    )
