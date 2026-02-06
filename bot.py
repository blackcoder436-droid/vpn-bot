import telebot
from telebot import types
import logging
import re
import json
import threading
import shutil
import os
from datetime import datetime, timedelta
import pytz  # For timezone support
from config import BOT_TOKEN, ADMIN_CHAT_ID, PAYMENT_CHANNEL_ID, SERVERS as CONFIG_SERVERS, PLANS, PAYMENT_INFO, MESSAGES, DATABASE_PATH
from database import (
    init_db, create_user, get_user, has_used_free_test, mark_free_test_used,
    create_order, update_order_screenshot, approve_order, reject_order,
    get_order, get_user_orders, save_vpn_key, get_user_keys, get_vpn_key_by_id, update_vpn_key,
    get_sales_stats, get_all_orders, get_expiring_keys, get_all_users,
    deactivate_vpn_key, log_security_event,
    # Referral system
    get_referral_code, get_user_by_referral_code, add_referral, 
    mark_referral_paid, get_referral_stats, claim_free_month_reward, get_referrer_id,
    get_user_active_keys, extend_key_expiry, get_referred_users_details,
    # Feature flags
    get_feature_flag, set_feature_flag, get_all_feature_flags,
    # User ban system
    ban_user, unban_user, is_user_banned as is_user_banned_db, 
    get_banned_users, get_user_ban_history,
    # Statistics
    get_statistics, get_revenue_by_period, get_top_users,
    # Server management
    add_server, update_server, delete_server, get_server, get_all_db_servers, toggle_server_active
)
from xui_api import create_vpn_key, get_available_protocols, delete_vpn_client, verify_client_exists
from security import (
    rate_limiter, InputValidator, is_valid_callback, SecurityLogger,
    abuse_detector, VALID_CALLBACK_PREFIXES
)

# OCR Payment Verification
try:
    from ocr_payment import process_payment_screenshot
    OCR_ENABLED = True
    print("✅ OCR Payment Verification enabled")
except ImportError as e:
    OCR_ENABLED = False
    print(f"⚠️ OCR Payment Verification disabled: {e}")

# Channel that users must join for Free Test Key
REQUIRED_CHANNEL_ID = "@BurmeseDigitalStore"  # Channel username (with @)
REQUIRED_CHANNEL_LINK = "https://t.me/BurmeseDigitalStore"

# Auto-approve settings
AUTO_APPROVE_ENABLED = True  # Enable/disable auto-approve
AUTO_APPROVE_TIMEOUT = 60  # 1 minute - faster approval for users
pending_auto_approvals = {}  # {order_id: {'timer': timer, 'data': {...}}}

# Protocol display names
PROTOCOL_NAMES = {
    'trojan': '🔐 Trojan (Recommended)',
    'vless': '⚡ VLESS',
    'vmess': '🌐 VMess',
    'shadowsocks': '🔒 Shadowsocks',
    'wireguard': '🛡️ WireGuard'
}

# Enable logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Create bot instance
bot = telebot.TeleBot(BOT_TOKEN, parse_mode='Markdown')

# User session storage
user_sessions = {}

# Server status (runtime - disabled servers)
disabled_servers = set()

# Banned users set (runtime cache)
banned_users = set()

# Dynamic SERVERS dict (merged from config + database)
SERVERS = {}

def load_servers():
    """Load servers from config.py and merge with database servers"""
    global SERVERS
    
    # Start with config servers
    SERVERS = dict(CONFIG_SERVERS)
    
    # Merge database servers (database servers can override config)
    try:
        db_servers = get_all_db_servers(active_only=False)
        for server_id, server_data in db_servers.items():
            if server_id not in SERVERS:
                # New server from database
                SERVERS[server_id] = server_data
            else:
                # Update existing with database settings if needed
                SERVERS[server_id]['from_database'] = True
                
        logger.info(f"📡 Servers loaded: {len(CONFIG_SERVERS)} from config + {len(db_servers)} from database = {len(SERVERS)} total")
    except Exception as e:
        logger.error(f"Error loading database servers: {e}")
        # Keep using config servers only

def get_active_servers():
    """Get all active servers (not disabled)"""
    return {
        sid: sdata for sid, sdata in SERVERS.items() 
        if sid not in disabled_servers and sdata.get('is_active', True) != False
    }

# Feature flags - Load from database on startup
def load_feature_flags():
    """Load feature flags from database"""
    global feature_flags
    try:
        feature_flags = get_all_feature_flags()
        # Ensure all expected flags exist
        expected_flags = ['referral_system', 'free_test_key', 'protocol_change', 'auto_approve']
        for flag in expected_flags:
            if flag not in feature_flags:
                feature_flags[flag] = True
        logger.info(f"📋 Feature flags loaded: {feature_flags}")
    except Exception as e:
        logger.error(f"Error loading feature flags: {e}")
        # Use defaults if database fails
        feature_flags = {
            'referral_system': True,
            'free_test_key': True,
            'protocol_change': True,
            'auto_approve': True,
        }

# Initial feature flags (will be loaded from DB)
feature_flags = {
    'referral_system': True,
    'free_test_key': True,
    'protocol_change': True,
    'auto_approve': True,
}

# ===================== SECURITY HELPERS =====================

def check_rate_limit(user_id: int, action_type: str = 'message') -> tuple:
    """Check rate limit and return (is_allowed, error_message)"""
    return rate_limiter.check_rate_limit(user_id, action_type)

def is_user_banned(user_id: int) -> bool:
    """Check if user is banned (runtime, database, rate limiter, or abuse detector)"""
    return (user_id in banned_users or 
            rate_limiter.is_banned(user_id) or 
            is_user_banned_db(user_id) or
            abuse_detector.is_user_blocked(user_id))

def security_check(user_id: int, text: str = None, action_type: str = 'message') -> tuple[bool, str]:
    """
    Comprehensive security check for all user actions
    Returns: (is_allowed, error_message)
    """
    # Check if user is banned
    if is_user_banned(user_id):
        return False, "⛔ Your access has been temporarily restricted."
    
    # Check rate limit
    is_allowed, error_msg = check_rate_limit(user_id, action_type)
    if not is_allowed:
        return False, error_msg
    
    # Check input safety if text provided
    if text:
        is_safe, threat_type = InputValidator.is_safe_text(text)
        if not is_safe:
            # Record the malicious attempt
            should_block, _ = abuse_detector.check_injection_attempt(user_id, threat_type)
            if should_block:
                return False, "⛔ Your access has been blocked due to suspicious activity."
            return False, "⚠️ Invalid input detected."
    
    return True, ""

def validate_server_id(server_id: str) -> bool:
    """Validate server ID"""
    return server_id in SERVERS

def validate_plan_id(plan_id: str) -> bool:
    """Validate plan ID"""
    return plan_id in PLANS

def sanitize_username(username: str) -> str:
    """Sanitize username for display"""
    if not username:
        return "Unknown"
    # Remove potentially dangerous characters
    safe_username = re.sub(r'[<>"\']', '', username)
    return safe_username[:50]  # Limit length

# Channel that users must join for Free Test Key
REQUIRED_CHANNEL_ID = "@BurmeseDigitalStore"  # Channel username (with @)
REQUIRED_CHANNEL_LINK = "https://t.me/BurmeseDigitalStore"

def check_channel_membership(user_id):
    """Check if user is a member of the required channel"""
    try:
        member = bot.get_chat_member(REQUIRED_CHANNEL_ID, user_id)
        logger.info(f"Channel membership check for {user_id}: status={member.status}")
        # User is a member if status is creator, administrator, member, or restricted
        return member.status in ['creator', 'administrator', 'member', 'restricted']
    except telebot.apihelper.ApiTelegramException as e:
        if "bot is not a member" in str(e).lower() or "chat not found" in str(e).lower():
            logger.error(f"Bot is not admin in channel {REQUIRED_CHANNEL_ID}. Please add bot as admin!")
            # Return True temporarily if bot can't check (admin needs to add bot to channel)
            return True  # Allow access if bot can't verify
        logger.warning(f"Telegram API error checking membership for {user_id}: {e}")
        return False
    except Exception as e:
        logger.warning(f"Failed to check channel membership for {user_id}: {e}")
        return False

# ===================== KEYBOARDS =====================

def main_menu_keyboard():
    """Main menu keyboard"""
    markup = types.InlineKeyboardMarkup(row_width=1)
    markup.add(
        types.InlineKeyboardButton("🎁 Free Test Key", callback_data="free_test"),
        types.InlineKeyboardButton("💎 Buy VPN Key", callback_data="buy_key"),
        types.InlineKeyboardButton("🔑 My Keys", callback_data="my_keys"),
        types.InlineKeyboardButton("🔄 Change Protocol", callback_data="exchange_key"),
        types.InlineKeyboardButton("📊 Check Usage", callback_data="check_usage")
    )
    markup.row(
        types.InlineKeyboardButton("� Referral", callback_data="referral"),
        types.InlineKeyboardButton("📖 Help", callback_data="help")
    )
    markup.add(types.InlineKeyboardButton("📞 Contact Admin", url="https://t.me/BDS_Admin"))
    return markup

def server_keyboard(for_free=False):
    """Server selection keyboard"""
    markup = types.InlineKeyboardMarkup(row_width=1)
    for server_id, server in SERVERS.items():
        # Skip disabled servers
        if server_id in disabled_servers:
            continue
        # Add panel type indicator
        panel_type = server.get('panel_type', 'xui').upper()
        panel_icon = '🔷' if panel_type == 'HIDDIFY' else '🔸'
        server_name = f"{server['name']} {panel_icon}"
        callback_data = f"free_server_{server_id}" if for_free else f"server_{server_id}"
        markup.add(types.InlineKeyboardButton(server_name, callback_data=callback_data))
    markup.add(types.InlineKeyboardButton("🔙 Back", callback_data="main_menu"))
    return markup

def plan_keyboard(server_id):
    """Device count selection keyboard"""
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.add(
        types.InlineKeyboardButton("📱 1 Device", callback_data=f"device_{server_id}_1"),
        types.InlineKeyboardButton("📱 2 Devices", callback_data=f"device_{server_id}_2"),
        types.InlineKeyboardButton("📱 3 Devices", callback_data=f"device_{server_id}_3"),
        types.InlineKeyboardButton("📱 4 Devices", callback_data=f"device_{server_id}_4"),
        types.InlineKeyboardButton("📱 5 Devices", callback_data=f"device_{server_id}_5"),
    )
    markup.add(types.InlineKeyboardButton("🔙 Back", callback_data="buy_key"))
    return markup

def month_keyboard(server_id, device_count):
    """Month duration selection keyboard"""
    markup = types.InlineKeyboardMarkup(row_width=2)
    
    # Get prices for each duration
    prices = {
        1: PLANS.get(f"{device_count}dev_1month", {}).get('price', 0),
        3: PLANS.get(f"{device_count}dev_3month", {}).get('price', 0),
        5: PLANS.get(f"{device_count}dev_5month", {}).get('price', 0),
        7: PLANS.get(f"{device_count}dev_7month", {}).get('price', 0),
        9: PLANS.get(f"{device_count}dev_9month", {}).get('price', 0),
        12: PLANS.get(f"{device_count}dev_12month", {}).get('price', 0),
    }
    
    markup.add(
        types.InlineKeyboardButton(f"1 Month - {prices[1]:,} Ks", callback_data=f"plan_{server_id}_{device_count}dev_1month"),
        types.InlineKeyboardButton(f"3 Months - {prices[3]:,} Ks", callback_data=f"plan_{server_id}_{device_count}dev_3month"),
        types.InlineKeyboardButton(f"5 Months - {prices[5]:,} Ks", callback_data=f"plan_{server_id}_{device_count}dev_5month"),
        types.InlineKeyboardButton(f"7 Months - {prices[7]:,} Ks", callback_data=f"plan_{server_id}_{device_count}dev_7month"),
        types.InlineKeyboardButton(f"9 Months - {prices[9]:,} Ks", callback_data=f"plan_{server_id}_{device_count}dev_9month"),
        types.InlineKeyboardButton(f"12 Months - {prices[12]:,} Ks", callback_data=f"plan_{server_id}_{device_count}dev_12month"),
    )
    markup.add(types.InlineKeyboardButton("🔙 Back", callback_data=f"proto_{server_id}_trojan"))
    return markup

def protocol_keyboard(server_id, is_free=False):
    """Protocol selection keyboard - Trojan first as default"""
    markup = types.InlineKeyboardMarkup(row_width=1)
    
    # Get available protocols from server
    try:
        available = get_available_protocols(server_id)
        if not available:
            available = ['trojan']  # Default fallback
    except Exception as e:
        logger.error(f"Error getting protocols: {e}")
        available = ['trojan']  # Default fallback
    
    prefix = "free_proto" if is_free else "proto"
    
    # Priority order - Trojan first
    priority_order = ['trojan', 'vless', 'vmess', 'shadowsocks', 'wireguard']
    
    # Sort available protocols by priority
    sorted_protocols = []
    for proto in priority_order:
        if proto in available:
            sorted_protocols.append(proto)
    # Add any remaining protocols not in priority list
    for proto in available:
        if proto not in sorted_protocols:
            sorted_protocols.append(proto)
    
    # Show protocols with Trojan as recommended
    for i, proto in enumerate(sorted_protocols):
        name = PROTOCOL_NAMES.get(proto, f"🔗 {proto.upper()}")
        if proto == 'trojan':  # Trojan is always recommended
            name += " ⭐"
        markup.add(types.InlineKeyboardButton(
            name,
            callback_data=f"{prefix}_{server_id}_{proto}"
        ))
    
    markup.add(types.InlineKeyboardButton("🔙 Back", callback_data="main_menu" if is_free else "buy_key"))
    return markup

def admin_order_keyboard(order_id, user_id):
    """Admin approval keyboard"""
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.add(
        types.InlineKeyboardButton("✅ Approve", callback_data=f"approve_{order_id}_{user_id}"),
        types.InlineKeyboardButton("❌ Reject", callback_data=f"reject_{order_id}_{user_id}")
    )
    return markup

def admin_menu_keyboard():
    """Admin menu keyboard"""
    markup = types.InlineKeyboardMarkup(row_width=1)
    markup.add(
        types.InlineKeyboardButton("📊 Sales Report", callback_data="admin_sales"),
        types.InlineKeyboardButton("� Statistics", callback_data="admin_stats"),
        types.InlineKeyboardButton("📋 Pending Orders", callback_data="admin_pending"),
        types.InlineKeyboardButton("👥 All Users", callback_data="admin_users"),
        types.InlineKeyboardButton("🚫 Ban Management", callback_data="admin_bans"),
        types.InlineKeyboardButton("🔔 Send Broadcast", callback_data="admin_broadcast"),
        types.InlineKeyboardButton("🖥️ Server Management", callback_data="admin_servers"),
        types.InlineKeyboardButton("⚙️ Feature Management", callback_data="admin_features"),
        types.InlineKeyboardButton("📦 Manual Backup", callback_data="admin_backup")
    )
    return markup

def server_management_keyboard():
    """Server management keyboard for admin"""
    markup = types.InlineKeyboardMarkup(row_width=1)
    for server_id, server in SERVERS.items():
        status = "🔴 Disabled" if server_id in disabled_servers else "🟢 Active"
        db_tag = " 📦" if server.get('from_database') else ""
        markup.add(types.InlineKeyboardButton(
            f"{server['name']} - {status}{db_tag}",
            callback_data=f"toggle_server_{server_id}"
        ))
    markup.add(
        types.InlineKeyboardButton("➕ Add New Server", callback_data="add_server_start"),
        types.InlineKeyboardButton("🗑️ Delete Server", callback_data="delete_server_start")
    )
    markup.add(types.InlineKeyboardButton("🔙 Back to Admin", callback_data="admin_back"))
    return markup

def add_server_type_keyboard():
    """Server type selection keyboard"""
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.add(
        types.InlineKeyboardButton("🖥️ 3X-UI Panel", callback_data="add_server_xui"),
        types.InlineKeyboardButton("🌐 Hiddify Panel", callback_data="add_server_hiddify")
    )
    markup.add(types.InlineKeyboardButton("❌ Cancel", callback_data="admin_servers"))
    return markup

def delete_server_keyboard():
    """Delete server selection keyboard (only database servers)"""
    markup = types.InlineKeyboardMarkup(row_width=1)
    db_servers = get_all_db_servers(active_only=False)
    
    if not db_servers:
        markup.add(types.InlineKeyboardButton("📭 No custom servers to delete", callback_data="admin_servers"))
    else:
        for server_id, server in db_servers.items():
            markup.add(types.InlineKeyboardButton(
                f"🗑️ {server['name']} ({server_id})",
                callback_data=f"confirm_delete_server_{server_id}"
            ))
    
    markup.add(types.InlineKeyboardButton("🔙 Back", callback_data="admin_servers"))
    return markup

def feature_management_keyboard():
    """Feature management keyboard for admin"""
    markup = types.InlineKeyboardMarkup(row_width=1)
    
    features = [
        ('referral_system', '👥 Referral System'),
        ('free_test_key', '🎁 Free Test Key'),
        ('protocol_change', '🔄 Protocol Change'),
        ('auto_approve', '🤖 Auto-Approve (OCR)'),
    ]
    
    for feature_id, feature_name in features:
        status = "🟢 ON" if feature_flags.get(feature_id, True) else "🔴 OFF"
        markup.add(types.InlineKeyboardButton(
            f"{feature_name} - {status}",
            callback_data=f"toggle_feature_{feature_id}"
        ))
    
    markup.add(types.InlineKeyboardButton("🔙 Back to Admin", callback_data="admin_back"))
    return markup

def stats_period_keyboard():
    """Statistics period selection keyboard"""
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.add(
        types.InlineKeyboardButton("📅 Today", callback_data="stats_today"),
        types.InlineKeyboardButton("📆 This Week", callback_data="stats_week"),
        types.InlineKeyboardButton("🗓️ This Month", callback_data="stats_month"),
        types.InlineKeyboardButton("📊 All Time", callback_data="stats_all")
    )
    markup.add(
        types.InlineKeyboardButton("🏆 Top Users", callback_data="stats_top_users"),
        types.InlineKeyboardButton("💰 Revenue Chart", callback_data="stats_revenue")
    )
    markup.add(types.InlineKeyboardButton("🔙 Back to Admin", callback_data="admin_back"))
    return markup

def ban_management_keyboard():
    """Ban management keyboard for admin"""
    markup = types.InlineKeyboardMarkup(row_width=1)
    markup.add(
        types.InlineKeyboardButton("🚫 Ban User", callback_data="ban_user_start"),
        types.InlineKeyboardButton("✅ Unban User", callback_data="unban_user_start"),
        types.InlineKeyboardButton("📋 Banned Users List", callback_data="ban_list")
    )
    markup.add(types.InlineKeyboardButton("🔙 Back to Admin", callback_data="admin_back"))
    return markup

# ===================== HANDLERS =====================

@bot.message_handler(commands=['start'])
def start(message):
    """Start command handler with referral support"""
    user = message.from_user
    user_id = user.id
    
    # Security: Check if user is banned
    if is_user_banned(user_id):
        bot.reply_to(message, "⚠️ You are temporarily blocked. Please try again later.")
        return
    
    # Security: Rate limiting
    allowed, error_msg = check_rate_limit(user_id, 'message')
    if not allowed:
        bot.reply_to(message, error_msg)
        return
    
    # Check if user is new
    existing_user = get_user(user_id)
    is_new_user = existing_user is None
    
    create_user(user.id, user.username, user.first_name, user.last_name)
    
    # Handle referral code from deep link: /start REF_XXXXXXXX
    if is_new_user:
        parts = message.text.split()
        if len(parts) > 1 and parts[1].startswith('REF_'):
            ref_code = parts[1][4:]  # Remove 'REF_' prefix
            referrer_id = get_user_by_referral_code(ref_code)
            
            if referrer_id and referrer_id != user_id:
                success, status = add_referral(referrer_id, user_id)
                if success:
                    # Notify referrer with reply keyboard (menu buttons)
                    try:
                        ref_menu_kb = types.ReplyKeyboardMarkup(row_width=2, resize_keyboard=True, one_time_keyboard=True)
                        ref_menu_kb.add(
                            types.KeyboardButton("📊 My Referrals"),
                            types.KeyboardButton("🔗 Share Link")
                        )
                        ref_menu_kb.add(
                            types.KeyboardButton("🔑 My Keys"),
                            types.KeyboardButton("🏠 Main Menu")
                        )
                        bot.send_message(
                            referrer_id,
                            f"🎉 *Referral အသစ်ရောက်လာပါပြီ!*\n\n"
                            f"@{user.username or user.first_name} က သင့် link မှတစ်ဆင့် Join ဝင်လာပါတယ်။\n\n"
                            f"📌 သူတို့ Key ဝယ်ရင် သင် **+5 Days** ရပါမယ်!\n"
                            f"📌 3 ယောက်ဝယ်ရင် **1 Month Free Key** ရပါမယ်!",
                            parse_mode='Markdown',
                            reply_markup=ref_menu_kb
                        )
                    except:
                        pass
    
    bot.send_message(
        message.chat.id,
        MESSAGES['welcome'],
        reply_markup=main_menu_keyboard()
    )

@bot.message_handler(commands=['ban'])
def ban_command(message):
    """Ban a user (Admin only)"""
    user_id = message.from_user.id
    
    if user_id != ADMIN_CHAT_ID:
        return
    
    parts = message.text.split(' ', 2)
    if len(parts) < 2:
        bot.reply_to(message, "Usage: /ban <user_id> [reason]")
        return
    
    try:
        target_id = int(parts[1])
        reason = parts[2] if len(parts) > 2 else "No reason provided"
    except ValueError:
        bot.reply_to(message, "❌ Invalid user ID")
        return
    
    if ban_user(target_id, reason):
        SecurityLogger.log_admin_action(user_id, "ban_user", f"target={target_id}, reason={reason}")
        bot.reply_to(message, f"✅ User {target_id} has been banned.\nReason: {reason}")
    else:
        bot.reply_to(message, f"❌ Failed to ban user {target_id}")

@bot.message_handler(commands=['unban'])
def unban_command(message):
    """Unban a user (Admin only)"""
    user_id = message.from_user.id
    
    if user_id != ADMIN_CHAT_ID:
        return
    
    parts = message.text.split(' ', 1)
    if len(parts) < 2:
        bot.reply_to(message, "Usage: /unban <user_id>")
        return
    
    try:
        target_id = int(parts[1])
    except ValueError:
        bot.reply_to(message, "❌ Invalid user ID")
        return
    
    if unban_user(target_id):
        SecurityLogger.log_admin_action(user_id, "unban_user", f"target={target_id}")
        bot.reply_to(message, f"✅ User {target_id} has been unbanned.")
    else:
        bot.reply_to(message, f"❌ Failed to unban user {target_id}")

@bot.message_handler(commands=['admin'])
def admin_command(message):
    """Admin panel command"""
    user_id = message.from_user.id
    
    # Security: Rate limiting
    allowed, error_msg = check_rate_limit(user_id, 'message')
    if not allowed:
        return
    
    logger.info(f"Admin command from user_id: {user_id}, ADMIN_CHAT_ID: {ADMIN_CHAT_ID}")
    
    if user_id != ADMIN_CHAT_ID:
        # Security: Log unauthorized access attempt
        SecurityLogger.log_failed_auth(user_id, "admin_command")
        bot.reply_to(message, f"❌ Admin only!")
        return
    
    SecurityLogger.log_admin_action(user_id, "accessed_admin_panel")
    bot.send_message(
        message.chat.id,
        "🔐 *Admin Panel*",
        reply_markup=admin_menu_keyboard()
    )

@bot.message_handler(commands=['broadcast'])
def broadcast_command(message):
    """Broadcast message to all users"""
    user_id = message.from_user.id
    
    if user_id != ADMIN_CHAT_ID:
        SecurityLogger.log_failed_auth(user_id, "broadcast_command")
        return
    
    # Security: Validate input
    text_parts = message.text.split(' ', 1)
    if len(text_parts) < 2:
        bot.reply_to(message, "Usage: /broadcast <message>")
        return
    
    broadcast_message = text_parts[1]
    
    # Security: Check for malicious content
    is_safe, threat_type = InputValidator.is_safe_text(broadcast_message)
    if not is_safe:
        bot.reply_to(message, f"⚠️ Message contains potentially unsafe content: {threat_type}")
        return
    
    # Sanitize message
    broadcast_message = InputValidator.sanitize_text(broadcast_message, max_length=4000)
    
    SecurityLogger.log_admin_action(user_id, "broadcast", f"message_length={len(broadcast_message)}")
    
    users = get_all_users()
    
    sent = 0
    for user in users:
        try:
            bot.send_message(
                user[1],  # telegram_id
                f"📢 *Announcement*\n\n{broadcast_message}"
            )
            sent += 1
        except Exception as e:
            logger.error(f"Failed to send to {user[1]}: {e}")
    
    bot.reply_to(message, f"✅ Broadcast sent to {sent}/{len(users)} users")

@bot.message_handler(commands=['backup'])
def backup_command(message):
    """Manual backup command for admin"""
    user_id = message.from_user.id
    
    if user_id != ADMIN_CHAT_ID:
        SecurityLogger.log_failed_auth(user_id, "backup_command")
        return
    
    bot.reply_to(message, "⏳ Creating backup...")
    
    if manual_backup():
        bot.reply_to(message, "✅ Backup created and sent to Payment Channel!")
    else:
        bot.reply_to(message, "❌ Backup failed! Check logs for details.")

@bot.callback_query_handler(func=lambda call: True)
def button_callback(call):
    """Handle button callbacks"""
    user_id = call.from_user.id
    data = call.data
    
    # Security: Check if user is banned or blocked by abuse detector
    if is_user_banned(user_id):
        bot.answer_callback_query(call.id, "⚠️ You are temporarily blocked.", show_alert=True)
        return
    
    # Security: Rate limiting for callbacks
    allowed, error_msg = check_rate_limit(user_id, 'callback')
    if not allowed:
        bot.answer_callback_query(call.id, "⚠️ Too many requests. Please slow down.", show_alert=True)
        # Record potential flood attempt
        abuse_detector.check_message_flood(user_id)
        return
    
    # Security: Validate callback data format and check for injection
    is_safe, threat_type = InputValidator.is_safe_text(data)
    if not is_safe:
        should_block, _ = abuse_detector.check_injection_attempt(user_id, threat_type)
        bot.answer_callback_query(call.id, "❌ Invalid action.", show_alert=True)
        return
    
    if not is_valid_callback(data):
        SecurityLogger.log_suspicious_activity(user_id, "INVALID_CALLBACK", data[:100])
        abuse_detector.record_suspicious_activity(user_id, "INVALID_CALLBACK_DATA", 2)
        bot.answer_callback_query(call.id, "❌ Invalid action.", show_alert=True)
        return
    
    bot.answer_callback_query(call.id)
    
    # Main menu
    if data == "main_menu":
        bot.edit_message_text(
            MESSAGES['welcome'],
            call.message.chat.id,
            call.message.message_id,
            reply_markup=main_menu_keyboard()
        )
    
    # Free test key
    elif data == "free_test":
        # Check if feature is enabled
        if not feature_flags.get('free_test_key', True):
            bot.edit_message_text(
                "🚫 *Free Test Key ယယက္ခံ ပိတ်ထားပါသည်။*\n\nကျေးဇူးပြု၍ VPN Key ဝယ်ယူပါ။",
                call.message.chat.id,
                call.message.message_id,
                reply_markup=main_menu_keyboard()
            )
            return
        
        # Check if user has joined the required channel
        if not check_channel_membership(user_id):
            markup = types.InlineKeyboardMarkup(row_width=1)
            markup.add(
                types.InlineKeyboardButton("📢 Channel Join မည်", url=REQUIRED_CHANNEL_LINK),
                types.InlineKeyboardButton("✅ Join ပြီးပါပြီ", callback_data="free_test_verify")
            )
            markup.add(types.InlineKeyboardButton("🏠 Main Menu", callback_data="main_menu"))
            bot.edit_message_text(
                "📢 *Free Test Key ရယူရန်*\n\n"
                "Free Test Key ရရှိရန် အောက်ပါ Channel ကို အရင်ဦးဆုံး Join ပါ:\n\n"
                f"👉 {REQUIRED_CHANNEL_LINK}\n\n"
                "Join ပြီးပါက *'✅ Join ပြီးပါပြီ'* ကို နှိပ်ပါ။",
                call.message.chat.id,
                call.message.message_id,
                parse_mode='Markdown',
                reply_markup=markup
            )
            return
        
        if has_used_free_test(user_id):
            bot.edit_message_text(
                MESSAGES['free_key_limit'],
                call.message.chat.id,
                call.message.message_id,
                reply_markup=main_menu_keyboard()
            )
        else:
            bot.edit_message_text(
                "🖥️ *Free Test Key အတွက် Server ရွေးပါ:*",
                call.message.chat.id,
                call.message.message_id,
                reply_markup=server_keyboard(for_free=True)
            )
    
    # Free test key verification after channel join
    elif data == "free_test_verify":
        # Re-check channel membership
        if not check_channel_membership(user_id):
            markup = types.InlineKeyboardMarkup(row_width=1)
            markup.add(
                types.InlineKeyboardButton("📢 Channel Join မည်", url=REQUIRED_CHANNEL_LINK),
                types.InlineKeyboardButton("✅ Join ပြီးပါပြီ", callback_data="free_test_verify")
            )
            markup.add(types.InlineKeyboardButton("🏠 Main Menu", callback_data="main_menu"))
            bot.edit_message_text(
                "❌ *Channel Join မလုပ်ရသေးပါ!*\n\n"
                "Free Test Key ရရှိရန် အောက်ပါ Channel ကို Join ပါ:\n\n"
                f"👉 {REQUIRED_CHANNEL_LINK}\n\n"
                "Join ပြီးပါက *'✅ Join ပြီးပါပြီ'* ကို ပြန်နှိပ်ပါ။",
                call.message.chat.id,
                call.message.message_id,
                parse_mode='Markdown',
                reply_markup=markup
            )
            return
        
        # Check if feature is enabled
        if not feature_flags.get('free_test_key', True):
            bot.edit_message_text(
                "🚫 *Free Test Key ယယက္ခံ ပိတ်ထားပါသည်။*\n\nကျေးဇူးပြု၍ VPN Key ဝယ်ယူပါ။",
                call.message.chat.id,
                call.message.message_id,
                reply_markup=main_menu_keyboard()
            )
            return
        
        # User has joined - proceed to server selection
        if has_used_free_test(user_id):
            bot.edit_message_text(
                MESSAGES['free_key_limit'],
                call.message.chat.id,
                call.message.message_id,
                reply_markup=main_menu_keyboard()
            )
        else:
            bot.edit_message_text(
                "✅ *Channel Join အတည်ပြုပြီးပါပြီ!*\n\n🖥️ *Free Test Key အတွက် Server ရွေးပါ:*",
                call.message.chat.id,
                call.message.message_id,
                parse_mode='Markdown',
                reply_markup=server_keyboard(for_free=True)
            )
    
    # Free server selection - now goes to protocol selection (skip for Hiddify)
    elif data.startswith("free_server_"):
        server_id = data.replace("free_server_", "")
        
        # Security: Validate server_id
        if not validate_server_id(server_id):
            SecurityLogger.log_suspicious_activity(user_id, "INVALID_SERVER_ID", server_id)
            bot.answer_callback_query(call.id, "❌ Invalid server.", show_alert=True)
            return
        
        user_sessions[user_id] = {'server_id': server_id, 'is_free': True}
        
        # Check if server is Hiddify - skip protocol selection
        server_config = SERVERS.get(server_id, {})
        if server_config.get('panel_type') == 'hiddify':
            # Skip protocol selection for Hiddify - directly create key
            username = call.from_user.username if call.from_user.username else call.from_user.first_name
            existing_keys = get_user_keys(user_id)
            key_number = len(existing_keys) + 1
            
            bot.edit_message_text(
                "⏳ Key ဖန်တီးနေပါသည်...",
                call.message.chat.id,
                call.message.message_id
            )
            
            # Create free test key for Hiddify (no protocol needed)
            result = create_vpn_key(
                server_id=server_id,
                telegram_id=user_id,
                username=username,
                data_limit_gb=3,  # 3GB limit
                expiry_days=3,    # 72 hours
                devices=1,
                protocol='hiddify',  # Hiddify handles protocols automatically
                key_number=key_number
            )
            
            if result and result.get('success'):
                mark_free_test_used(user_id)
                config_link = result.get('config_link', result['sub_link'])
                save_vpn_key(
                    telegram_id=user_id,
                    order_id=None,
                    server_id=server_id,
                    client_email=result['client_email'],
                    client_id=result['client_id'],
                    sub_link=result['sub_link'],
                    config_link=config_link,
                    data_limit=3,
                    expiry_date=result['expiry_date']
                )
                
                expiry_str = result['expiry_date'].strftime('%Y-%m-%d %H:%M')
                message_text = MESSAGES['key_generated'].format(
                    server=SERVERS[server_id]['name'],
                    plan="🎁 Free Test",
                    expiry=expiry_str,
                    data_limit="3 GB",
                    config_link=config_link,
                    sub_link=result['sub_link']
                )
                
                markup = types.InlineKeyboardMarkup(row_width=2)
                markup.add(
                    types.InlineKeyboardButton("🛒 Key ထပ်ဝယ်ရန်", callback_data="buy_key"),
                    types.InlineKeyboardButton("📞 Admin ဆက်သွယ်ရန်", url="https://t.me/blackc0der404")
                )
                markup.add(types.InlineKeyboardButton("🏠 Main Menu", callback_data="main_menu"))
                
                bot.edit_message_text(
                    message_text,
                    call.message.chat.id,
                    call.message.message_id,
                    reply_markup=markup,
                    disable_web_page_preview=True
                )
            else:
                bot.edit_message_text(
                    "❌ Key ဖန်တီးရာတွင် အမှားရှိပါသည်။ ကျေးဇူးပြု၍ နောက်မှ ထပ်ကြိုးစားပါ။",
                    call.message.chat.id,
                    call.message.message_id,
                    reply_markup=main_menu_keyboard()
                )
            return
        
        # XUI panel - show protocol selection
        bot.edit_message_text(
            "🔐 *Protocol ရွေးချယ်ပါ:*\n\n_⭐ ပြထားသော Protocol သည် အကောင်းဆုံး ဖြစ်ပါသည်_",
            call.message.chat.id,
            call.message.message_id,
            reply_markup=protocol_keyboard(server_id, is_free=True)
        )
    
    # Free protocol selection - create key
    elif data.startswith("free_proto_"):
        parts = data.replace("free_proto_", "").split("_")
        server_id = parts[0]
        protocol = parts[1] if len(parts) > 1 else 'trojan'
        
        # Get username
        username = call.from_user.username if call.from_user.username else call.from_user.first_name
        
        # Get current key count for this user to determine key number
        existing_keys = get_user_keys(user_id)
        key_number = len(existing_keys) + 1
        
        bot.edit_message_text(
            "⏳ Key ဖန်တီးနေပါသည်...",
            call.message.chat.id,
            call.message.message_id
        )
        
        # Create free test key
        result = create_vpn_key(
            server_id=server_id,
            telegram_id=user_id,
            username=username,
            data_limit_gb=3,  # 3GB limit
            expiry_days=3,    # 72 hours
            devices=1,
            protocol=protocol,
            key_number=key_number
        )
        
        if result and result.get('success'):
            mark_free_test_used(user_id)
            config_link = result.get('config_link', result['sub_link'])
            save_vpn_key(
                telegram_id=user_id,
                order_id=None,
                server_id=server_id,
                client_email=result['client_email'],
                client_id=result['client_id'],
                sub_link=result['sub_link'],
                config_link=config_link,
                data_limit=3,
                expiry_date=result['expiry_date']
            )
            
            expiry_str = result['expiry_date'].strftime('%Y-%m-%d %H:%M')
            message_text = MESSAGES['key_generated'].format(
                server=SERVERS[server_id]['name'],
                plan="🎁 Free Test",
                expiry=expiry_str,
                data_limit="3 GB",
                config_link=config_link,
                sub_link=result['sub_link']
            )
            
            # Create keyboard with buttons
            markup = types.InlineKeyboardMarkup(row_width=2)
            markup.add(
                types.InlineKeyboardButton("🛒 Key ထပ်ဝယ်ရန်", callback_data="buy_key"),
                types.InlineKeyboardButton("📞 Admin ဆက်သွယ်ရန်", url="https://t.me/blackc0der404")
            )
            markup.add(types.InlineKeyboardButton("🏠 Main Menu", callback_data="main_menu"))
            
            bot.edit_message_text(
                message_text,
                call.message.chat.id,
                call.message.message_id,
                reply_markup=markup,
                disable_web_page_preview=True
            )
        else:
            bot.edit_message_text(
                "❌ Key ဖန်တီးရာတွင် အမှားရှိပါသည်။ ကျေးဇူးပြု၍ နောက်မှ ထပ်ကြိုးစားပါ။",
                call.message.chat.id,
                call.message.message_id,
                reply_markup=main_menu_keyboard()
            )
    
    # Buy key - server selection
    elif data == "buy_key":
        bot.edit_message_text(
            MESSAGES['select_server'],
            call.message.chat.id,
            call.message.message_id,
            reply_markup=server_keyboard(for_free=False)
        )
    
    # Server selected for purchase - go to protocol selection (skip for Hiddify)
    elif data.startswith("server_") and not data.startswith("server_selection"):
        server_id = data.replace("server_", "")
        
        # Security: Validate server_id
        if not validate_server_id(server_id):
            SecurityLogger.log_suspicious_activity(user_id, "INVALID_SERVER_ID", server_id)
            bot.answer_callback_query(call.id, "❌ Invalid server.", show_alert=True)
            return
        
        user_sessions[user_id] = {'server_id': server_id}
        
        # Check if server is Hiddify - skip protocol selection
        server_config = SERVERS.get(server_id, {})
        if server_config.get('panel_type') == 'hiddify':
            # Skip protocol selection for Hiddify - go directly to device selection
            user_sessions[user_id]['protocol'] = 'hiddify'  # Hiddify handles protocols
            
            bot.edit_message_text(
                "📱 *Device အရေအတွက် ရွေးချယ်ပါ:*\n\n_Device များများ သုံးလိုပါက များများ ရွေးပါ_",
                call.message.chat.id,
                call.message.message_id,
                reply_markup=plan_keyboard(server_id)
            )
            return
        
        # XUI panel - show protocol selection
        bot.edit_message_text(
            "🔐 *Protocol ရွေးချယ်ပါ:*\n\n_⭐ ပြထားသော Protocol သည် အကောင်းဆုံး ဖြစ်ပါသည်_",
            call.message.chat.id,
            call.message.message_id,
            reply_markup=protocol_keyboard(server_id, is_free=False)
        )
    
    # Protocol selected for purchase - go to device selection
    elif data.startswith("proto_"):
        parts = data.replace("proto_", "").split("_")
        server_id = parts[0]
        protocol = parts[1] if len(parts) > 1 else 'trojan'
        
        user_sessions[user_id] = user_sessions.get(user_id, {})
        user_sessions[user_id]['server_id'] = server_id
        user_sessions[user_id]['protocol'] = protocol
        
        bot.edit_message_text(
            "📱 *Device အရေအတွက် ရွေးချယ်ပါ:*\n\n_Device များများ သုံးလိုပါက များများ ရွေးပါ_",
            call.message.chat.id,
            call.message.message_id,
            reply_markup=plan_keyboard(server_id)
        )
    
    # Device count selected - go to month selection
    elif data.startswith("device_"):
        parts = data.replace("device_", "").split("_")
        server_id = parts[0]
        device_count = parts[1] if len(parts) > 1 else '1'
        
        user_sessions[user_id] = user_sessions.get(user_id, {})
        user_sessions[user_id]['device_count'] = device_count
        
        bot.edit_message_text(
            f"📅 *{device_count} Device အတွက် ကာလ ရွေးချယ်ပါ:*\n\n_ကာလ ကြာကြာ ဝယ်လေ စျေးသက်သာလေ_",
            call.message.chat.id,
            call.message.message_id,
            reply_markup=month_keyboard(server_id, device_count)
        )
    
    # Plan selected
    elif data.startswith("plan_"):
        parts = data.split("_")
        server_id = parts[1]
        plan_id = "_".join(parts[2:])
        
        # Security: Validate server and plan
        if not validate_server_id(server_id):
            SecurityLogger.log_suspicious_activity(user_id, "INVALID_SERVER_ID", server_id)
            bot.answer_callback_query(call.id, "❌ Invalid server.", show_alert=True)
            return
        
        if not validate_plan_id(plan_id):
            SecurityLogger.log_suspicious_activity(user_id, "INVALID_PLAN_ID", plan_id)
            bot.answer_callback_query(call.id, "❌ Invalid plan.", show_alert=True)
            return
        
        plan = PLANS.get(plan_id)
        if not plan:
            bot.answer_callback_query(call.id, "❌ Invalid plan selected.", show_alert=True)
            return
        
        # Keep existing session data and add new data
        existing_session = user_sessions.get(user_id, {})
        protocol = existing_session.get('protocol', 'trojan')
        
        user_sessions[user_id] = {
            'server_id': server_id,
            'plan_id': plan_id,
            'amount': plan['price'],
            'protocol': protocol
        }
        
        # Create order with protocol
        order_id = create_order(user_id, server_id, plan_id, plan['price'], protocol)
        user_sessions[user_id]['order_id'] = order_id
        
        # Show payment info
        payment_text = MESSAGES['payment_info'].format(amount=plan['price'])
        
        markup = types.InlineKeyboardMarkup(row_width=1)
        markup.add(
            types.InlineKeyboardButton("📸 Screenshot ပို့ရန် နှိပ်ပါ", callback_data=f"send_screenshot_{order_id}"),
            types.InlineKeyboardButton("❌ Cancel", callback_data="main_menu")
        )
        
        bot.edit_message_text(
            payment_text,
            call.message.chat.id,
            call.message.message_id,
            reply_markup=markup
        )
    
    # Send screenshot prompt
    elif data.startswith("send_screenshot_"):
        order_id = data.replace("send_screenshot_", "")
        user_sessions[user_id] = user_sessions.get(user_id, {})
        user_sessions[user_id]['waiting_screenshot'] = True
        user_sessions[user_id]['order_id'] = int(order_id)
        
        bot.edit_message_text(
            "📸 *Payment Screenshot ပိုပေးပါ*\n\nScreenshot ကို ဤနေရာတွင် ယခု ပို့ပေးပါ။",
            call.message.chat.id,
            call.message.message_id
        )
    
    # My keys
    elif data == "my_keys":
        keys = get_user_keys(user_id)
        if not keys:
            bot.edit_message_text(
                "🔑 သင့်တွင် Active VPN Key မရှိပါ။",
                call.message.chat.id,
                call.message.message_id,
                reply_markup=main_menu_keyboard()
            )
        else:
            bot.edit_message_text(
                "⏳ *Verifying keys with panel...*",
                call.message.chat.id,
                call.message.message_id
            )
            
            text = "🔑 *သင့် VPN Keys*\n\n"
            valid_keys = []
            
            for key in keys:
                key_id = key[0]
                server_id = key[3]
                client_email = key[4]
                
                # Verify key exists in 3x-ui panel
                client_info = verify_client_exists(server_id, client_email)
                if client_info:
                    valid_keys.append((key, client_info))
                else:
                    # Key doesn't exist in panel - deactivate it
                    logger.info(f"Key {key_id} ({client_email}) not found in panel, deactivating...")
                    deactivate_vpn_key(key_id)
            
            if not valid_keys:
                bot.edit_message_text(
                    "🔑 သင့်တွင် Active VPN Key မရှိပါ။\n\n_(Panel တွင် Key များ မတွေ့ပါ။)_",
                    call.message.chat.id,
                    call.message.message_id,
                    reply_markup=main_menu_keyboard()
                )
                return
            
            for i, (key, client_info) in enumerate(valid_keys, 1):
                server_id = key[3]
                server_name = SERVERS.get(server_id, {}).get('name', 'Unknown')
                panel_type = SERVERS.get(server_id, {}).get('panel_type', 'xui')
                
                # Get expiry from panel (in milliseconds)
                client = client_info['client']
                inbound = client_info['inbound']
                protocol = inbound.get('protocol', 'trojan')
                
                # Handle Hiddify panel differently
                if panel_type == 'hiddify' or protocol == 'hiddify':
                    # For Hiddify, use stored subscription link
                    sub_link = key[6] if len(key) > 6 else None  # sub_link column
                    config_link = key[7] if len(key) > 7 else sub_link  # config_link column
                    
                    # Get expiry from hiddify_user data
                    hiddify_user = client_info.get('hiddify_user', {})
                    package_days = hiddify_user.get('package_days', 0)
                    start_date = hiddify_user.get('start_date')
                    
                    if start_date and package_days:
                        from datetime import timedelta
                        try:
                            if isinstance(start_date, str):
                                start = datetime.strptime(start_date[:10], '%Y-%m-%d')
                            else:
                                start = start_date
                            expiry = start + timedelta(days=package_days)
                            days_left = (expiry - datetime.now()).days
                            expiry_display = f"{expiry.strftime('%Y-%m-%d')} ({days_left} days left)"
                        except:
                            expiry_display = f"{package_days} days package"
                    else:
                        expiry_display = "Active"
                    
                    text += f"*Key {i}:*\n"
                    text += f"├ Server: {server_name}\n"
                    text += f"├ Type: Hiddify (Multi-Protocol)\n"
                    text += f"├ Expiry: {expiry_display}\n"
                    text += f"└ Subscription Link:\n`{sub_link or config_link}`\n\n"
                else:
                    # XUI Panel handling
                    panel_expiry_ms = client.get('expiryTime', 0)
                    
                    if panel_expiry_ms > 0:
                        panel_expiry = datetime.fromtimestamp(panel_expiry_ms / 1000)
                        expiry_str = panel_expiry.strftime('%Y-%m-%d %H:%M')
                        days_left = (panel_expiry - datetime.now()).days
                        expiry_display = f"{expiry_str} ({days_left} days left)"
                    else:
                        expiry_display = "Unlimited"
                    
                    # Get protocol and generate config link
                    port = inbound.get('port', 443)
                    server_domain = SERVERS.get(server_id, {}).get('domain', '')
                    
                    # Generate config link based on protocol
                    if protocol == 'trojan':
                        client_uuid = client.get('password')
                        # Use custom trojan_port if configured, otherwise use inbound port
                        trojan_port = SERVERS.get(server_id, {}).get('trojan_port', port)
                        config_link = f"trojan://{client_uuid}@{server_domain}:{trojan_port}?security=none&type=tcp#{client.get('email')}"
                    elif protocol == 'vless':
                        client_uuid = client.get('id')
                        config_link = f"vless://{client_uuid}@{server_domain}:{port}?type=tcp&security=none#{client.get('email')}"
                    elif protocol == 'vmess':
                        import base64
                        import json as json_lib
                        client_uuid = client.get('id')
                        vmess_config = {
                            "v": "2",
                            "ps": client.get('email'),
                            "add": server_domain,
                            "port": str(port),
                            "id": client_uuid,
                            "aid": "0",
                            "net": "tcp",
                            "type": "none",
                            "tls": ""
                        }
                        config_link = "vmess://" + base64.b64encode(json_lib.dumps(vmess_config).encode()).decode()
                    elif protocol == 'shadowsocks':
                        import base64
                        ss_settings = json.loads(inbound.get('settings', '{}'))
                        method = ss_settings.get('method', 'aes-256-gcm')
                        password = client.get('password', client.get('id'))
                        ss_auth = base64.b64encode(f"{method}:{password}".encode()).decode()
                        config_link = f"ss://{ss_auth}@{server_domain}:{port}#{client.get('email')}"
                    else:
                        config_link = key[7] if key[7] else key[6]  # Fallback to database
                    
                    text += f"*Key {i}:*\n"
                    text += f"├ Server: {server_name}\n"
                    text += f"├ Protocol: {protocol.upper()}\n"
                    text += f"├ Expiry: {expiry_display}\n"
                    text += f"└ Key:\n`{config_link}`\n\n"
            
            text += "_Key ကို Long Press လုပ်ပြီး Copy ယူပါ_"
            
            try:
                bot.edit_message_text(
                    text,
                    call.message.chat.id,
                    call.message.message_id,
                    reply_markup=main_menu_keyboard()
                )
            except Exception as e:
                # Message not modified error - ignore
                pass
    
    # Check usage
    elif data == "check_usage":
        keys = get_user_keys(user_id)
        if not keys:
            bot.edit_message_text(
                "📊 *Usage Check*\n\n❌ သင့်တွင် Active VPN Key မရှိပါ။\n\nKey ဝယ်ပြီးမှ Usage ကြည့်လို့ရပါမည်။",
                call.message.chat.id,
                call.message.message_id,
                reply_markup=main_menu_keyboard()
            )
        else:
            text = "📊 *Usage Check*\n\n"
            text += "သင့် VPN Key ၏ Usage ကို အောက်ပါ Link များမှ ကြည့်နိုင်ပါသည်:\n\n"
            
            for i, key in enumerate(keys, 1):
                server_name = SERVERS.get(key[3], {}).get('name', 'Unknown')
                sub_link = key[6]  # sub_link column
                text += f"*Key {i}* ({server_name}):\n"
                text += f"🔗 [Usage ကြည့်ရန် နှိပ်ပါ]({sub_link})\n\n"
            
            text += "_Link ကို Browser မှာ ဖွင့်ပြီး Traffic, Expiry Date စတာတွေ ကြည့်နိုင်ပါတယ်။_"
            
            bot.edit_message_text(
                text,
                call.message.chat.id,
                call.message.message_id,
                reply_markup=main_menu_keyboard(),
                disable_web_page_preview=True
            )
    
    # Exchange key - show user's keys to select
    elif data == "exchange_key":
        # Check if feature is enabled
        if not feature_flags.get('protocol_change', True):
            bot.edit_message_text(
                "🚫 *Protocol Change ယယက္ခံ ပိတ်ထားပါသည်။*\n\nနောက်မှ ပြန်ဖွင့်ပါမည်။",
                call.message.chat.id,
                call.message.message_id,
                reply_markup=main_menu_keyboard()
            )
            return
        
        keys = get_user_keys(user_id)
        if not keys:
            bot.edit_message_text(
                "🔄 *Key လဲလှယ်ရန်*\n\n❌ သင့်တွင် Active VPN Key မရှိပါ။\n\nKey ဝယ်ပြီးမှ Protocol လဲလှယ်လို့ရပါမည်။",
                call.message.chat.id,
                call.message.message_id,
                reply_markup=main_menu_keyboard()
            )
        else:
            text = "🔄 *Key လဲလှယ်ရန်*\n\nProtocol ပြောင်းလိုသော Key ကို ရွေးပါ:\n\n"
            markup = types.InlineKeyboardMarkup(row_width=1)
            
            for i, key in enumerate(keys, 1):
                key_id = key[0]  # id column
                server_name = SERVERS.get(key[3], {}).get('name', 'Unknown')
                expiry = key[9]
                config_link = key[7] if key[7] else key[6]
                
                # Detect current protocol
                current_proto = "Unknown"
                if config_link.startswith('trojan://'):
                    current_proto = "Trojan"
                elif config_link.startswith('vless://'):
                    current_proto = "VLESS"
                elif config_link.startswith('vmess://'):
                    current_proto = "VMess"
                elif config_link.startswith('ss://'):
                    current_proto = "Shadowsocks"
                
                text += f"*Key {i}:* {server_name}\n"
                text += f"├ Protocol: {current_proto}\n"
                text += f"└ Expiry: {expiry}\n\n"
                
                markup.add(types.InlineKeyboardButton(f"🔄 Key {i} - {current_proto} ပြောင်းရန်", callback_data=f"exkey_{key_id}"))
            
            markup.add(types.InlineKeyboardButton("🔙 Back", callback_data="main_menu"))
            
            bot.edit_message_text(
                text,
                call.message.chat.id,
                call.message.message_id,
                reply_markup=markup
            )
    
    # Exchange key - select key to change protocol
    elif data.startswith("exkey_"):
        key_id = int(data.replace("exkey_", ""))
        key = get_vpn_key_by_id(key_id)
        
        if not key or key[1] != user_id:  # Check ownership
            bot.answer_callback_query(call.id, "❌ Key ရှာမတွေ့ပါ။", show_alert=True)
            return
        
        server_id = key[3]
        user_sessions[user_id] = user_sessions.get(user_id, {})
        user_sessions[user_id]['exchange_key_id'] = key_id
        user_sessions[user_id]['exchange_server_id'] = server_id
        
        # Show protocol selection
        markup = types.InlineKeyboardMarkup(row_width=1)
        
        try:
            available = get_available_protocols(server_id)
            if not available:
                available = ['trojan']
        except:
            available = ['trojan']
        
        protocol_labels = {
            'trojan': '⭐ Trojan (အကောင်းဆုံး)',
            'vless': 'VLESS',
            'vmess': 'VMess',
            'shadowsocks': 'Shadowsocks',
            'wireguard': 'WireGuard'
        }
        
        for proto in available:
            label = protocol_labels.get(proto, proto.upper())
            markup.add(types.InlineKeyboardButton(label, callback_data=f"expro_{key_id}_{proto}"))
        
        markup.add(types.InlineKeyboardButton("🔙 Back", callback_data="exchange_key"))
        
        bot.edit_message_text(
            f"🔐 *Protocol ရွေးချယ်ပါ*\n\n_ပြောင်းလိုသော Protocol ကို ရွေးပါ:_\n\n⭐ = အကောင်းဆုံး (ISP အားလုံးအတွက်)",
            call.message.chat.id,
            call.message.message_id,
            reply_markup=markup
        )
    
    # Exchange key - change protocol
    elif data.startswith("expro_"):
        parts = data.replace("expro_", "").split("_")
        key_id = int(parts[0])
        new_protocol = parts[1]
        
        key = get_vpn_key_by_id(key_id)
        if not key or key[1] != user_id:
            bot.answer_callback_query(call.id, "❌ Key ရှာမတွေ့ပါ။", show_alert=True)
            return
        
        server_id = key[3]
        old_client_email = key[4]
        
        # Parse expiry date with multiple format support
        expiry_str = str(key[9])
        try:
            if '.' in expiry_str:
                expiry_date = datetime.strptime(expiry_str, '%Y-%m-%d %H:%M:%S.%f')
            elif 'T' in expiry_str:
                expiry_date = datetime.fromisoformat(expiry_str)
            else:
                expiry_date = datetime.strptime(expiry_str, '%Y-%m-%d %H:%M:%S')
        except:
            # Fallback - try other formats
            try:
                expiry_date = datetime.strptime(expiry_str[:19], '%Y-%m-%d %H:%M:%S')
            except:
                expiry_date = datetime.strptime(expiry_str[:10], '%Y-%m-%d')
        
        # Calculate exact expiry timestamp in milliseconds (keep ORIGINAL expiry date)
        expiry_timestamp = int(expiry_date.timestamp() * 1000)
        logger.info(f"Exchange key: Original expiry = {expiry_date}, timestamp = {expiry_timestamp}")
        
        # Extract devices from old client_email (format: "username - 2D / Key 1")
        devices = 1
        try:
            device_match = re.search(r'(\d+)D', old_client_email)
            if device_match:
                devices = int(device_match.group(1))
        except:
            pass
        
        # Get username
        username = call.from_user.username if call.from_user.username else call.from_user.first_name
        
        bot.edit_message_text(
            "⏳ Protocol ပြောင်းနေပါသည်...",
            call.message.chat.id,
            call.message.message_id
        )
        
        # Find the key number from old client name or use key position
        existing_keys = get_user_keys(user_id)
        key_position = 1
        for i, k in enumerate(existing_keys, 1):
            if k[0] == key_id:
                key_position = i
                break
        
        # Create new key with new protocol FIRST (using EXACT original expiry timestamp)
        result = create_vpn_key(
            server_id=server_id,
            telegram_id=user_id,
            username=username,
            data_limit_gb=key[8] if key[8] else 0,  # Keep same data limit
            expiry_days=30,  # Not used when expiry_timestamp is provided
            devices=devices,  # Use extracted devices count
            protocol=new_protocol,
            expiry_timestamp=expiry_timestamp,  # Use EXACT original expiry
            key_number=key_position
        )
        
        if result and result.get('success'):
            config_link = result.get('config_link', result['sub_link'])
            
            # Delete old key from 3x-ui panel AFTER successful creation
            try:
                delete_vpn_client(server_id, old_client_email)
                logger.info(f"Deleted old key: {old_client_email}")
            except Exception as e:
                logger.error(f"Error deleting old key: {e}")
            
            # Update database
            update_vpn_key(
                key_id=key_id,
                sub_link=result['sub_link'],
                config_link=config_link,
                client_email=result['client_email'],
                client_id=result['client_id']
            )
            
            expiry_str = expiry_date.strftime('%Y-%m-%d %H:%M')
            
            success_text = f"""
✅ *Protocol ပြောင်းလဲပြီးပါပြီ!*

🖥️ *Server:* {SERVERS[server_id]['name']}
🔐 *New Protocol:* {new_protocol.upper()}
📅 *Expiry:* {expiry_str}

🔑 *Your New VPN Key:*
```
{config_link}
```

_Key အသစ်ကို App မှာ ပြန်ထည့်ပါ။_
"""
            
            markup = types.InlineKeyboardMarkup(row_width=1)
            markup.add(types.InlineKeyboardButton("🏠 Main Menu", callback_data="main_menu"))
            
            bot.edit_message_text(
                success_text,
                call.message.chat.id,
                call.message.message_id,
                reply_markup=markup
            )
        else:
            bot.edit_message_text(
                "❌ Protocol ပြောင်းရာတွင် အမှားရှိပါသည်။ Admin ကို ဆက်သွယ်ပါ။",
                call.message.chat.id,
                call.message.message_id,
                reply_markup=main_menu_keyboard()
            )
    
    # Help
    elif data == "help":
        Help_text = """
📖 *အကူအညီ*

*VPN Key ဝယ်နည်း:*
1️⃣ "💎 Buy VPN Key" နှိပ်ပါ
2️⃣ Server ရွေးပါ
3️⃣ Plan ရွေးပါ
4️⃣ ငွေလွှဲပြီး Screenshot ပို့ပါ
5️⃣ Admin Approve ပြီးရင် Key ရပါမည်

*Key အသုံးပြုနည်း:*
1️⃣ V2rayNG/Nekobox app ထည့်ပါ
2️⃣ Key ကို Long Press လုပ်ပြီး Copy ကူးပါ
3️⃣ App မှာ + နှိပ်ပြီး Import လုပ်ပါ
4️⃣ Connect နှိပ်ပါ

*ပြဿနာရှိပါက:*
📞 Admin ကို ဆက်သွယ်ပါ
"""
        bot.edit_message_text(
            Help_text,
            call.message.chat.id,
            call.message.message_id,
            reply_markup=main_menu_keyboard()
        )
    
    # Contact
    elif data == "contact":
        bot.edit_message_text(
            "📞 *ဆက်သွယ်ရန်*\n\nAdmin: @BDS\\_Admin\n\nအကူအညီလိုပါက Message ပို့ပေးပါ။",
            call.message.chat.id,
            call.message.message_id,
            reply_markup=main_menu_keyboard()
        )
    
    # Referral System
    elif data == "referral":
        # Check if feature is enabled
        if not feature_flags.get('referral_system', True):
            bot.edit_message_text(
                "🚫 *Referral System ယယက္ခံ ပိတ်ထားပါသည်။*\n\nနောက်မှ ပြန်ဖွင့်ပါမည်။",
                call.message.chat.id,
                call.message.message_id,
                reply_markup=main_menu_keyboard()
            )
            return
        show_referral_menu(call)
    
    elif data == "my_referral_link":
        show_referral_link(call)
    
    elif data == "referral_stats":
        show_referral_stats(call)
    
    elif data == "claim_free_month":
        claim_referral_reward(call)
    
    # Admin approve referral free key (must be BEFORE generic approve_ handler)
    elif data.startswith("approve_freekey_"):
        # Allow approval from Payment Channel or Admin
        if call.message.chat.id != PAYMENT_CHANNEL_ID and user_id != ADMIN_CHAT_ID:
            bot.answer_callback_query(call.id, "❌ Admin only!", show_alert=True)
            return
        
        try:
            customer_id = int(data.split("_")[2])
        except (ValueError, IndexError):
            bot.answer_callback_query(call.id, "❌ Invalid data.", show_alert=True)
            return
        
        # Check if user can still claim
        stats = get_referral_stats(customer_id)
        if not stats['can_claim_free_month']:
            bot.edit_message_text(
                "❌ *Request Invalid*\n\nUser သည် Free Key ရယူပိုင်ခွင့် မရှိတော့ပါ။",
                call.message.chat.id,
                call.message.message_id,
                parse_mode='Markdown'
            )
            return
        
        # Update message to show processing
        bot.edit_message_text(
            "⏳ *Key ဖန်တီးနေပါသည်...*",
            call.message.chat.id,
            call.message.message_id,
            parse_mode='Markdown'
        )
        
        # Get customer info
        customer = get_user(customer_id)
        customer_username = customer[2] if customer and customer[2] else f"User_{customer_id}"
        
        # Get existing keys count for key number
        existing_keys = get_user_keys(customer_id)
        key_number = len(existing_keys) + 1
        
        # Create free key - Use first available server (prefer Hiddify, else first XUI server)
        server_id = None
        for sid, server in SERVERS.items():
            if server.get('panel_type') == 'hiddify':
                server_id = sid
                break
        if not server_id:
            server_id = list(SERVERS.keys())[0]  # First available server
        
        # Free key plan: 1 Month, 1 Device
        free_plan = {
            'name': '🎁 Referral Free Key (1 Month)',
            'data_limit': 0,  # Unlimited
            'expiry_days': 30,
            'devices': 1
        }
        
        result = create_vpn_key(
            server_id=server_id,
            telegram_id=customer_id,
            username=customer_username,
            data_limit_gb=free_plan['data_limit'],
            expiry_days=free_plan['expiry_days'],
            devices=free_plan['devices'],
            protocol='trojan',
            key_number=key_number
        )
        
        if result and result.get('success'):
            # Record the claim in database
            success, status = claim_free_month_reward(customer_id)
            
            config_link = result.get('config_link', result['sub_link'])
            save_vpn_key(
                telegram_id=customer_id,
                order_id=None,  # No order for free key
                server_id=server_id,
                client_email=result['client_email'],
                client_id=result['client_id'],
                sub_link=result['sub_link'],
                config_link=config_link,
                data_limit=free_plan['data_limit'],
                expiry_date=result['expiry_date']
            )
            
            # Notify customer
            expiry_str = result['expiry_date'].strftime('%Y-%m-%d %H:%M')
            customer_message = f"""
🎉 *Congratulations!*

🎁 *Referral Reward Key ရရှိပါပြီ!*

🖥️ *Server:* {SERVERS[server_id]['name']}
📦 *Plan:* {free_plan['name']}
⏰ *Expiry:* {expiry_str}
📊 *Data:* Unlimited

📲 *Subscription Link:*
```
{result['sub_link']}
```

🔑 *Config Link:*
```
{config_link}
```

_App မှာ Subscription Link ထည့်ပြီး အသုံးပြုပါ။_

🙏 Referral အတွက် ကျေးဇူးတင်ပါသည်!
"""
            nav_keyboard = types.InlineKeyboardMarkup(row_width=1)
            nav_keyboard.add(
                types.InlineKeyboardButton("🔑 My Keys", callback_data="my_keys"),
                types.InlineKeyboardButton("🏠 Main Menu", callback_data="main_menu")
            )
            bot.send_message(customer_id, customer_message, parse_mode='Markdown', reply_markup=nav_keyboard)
            
            # Update admin message
            customer_username_display = customer_username.replace("_", "\\_")
            bot.edit_message_text(
                f"✅ *Referral Free Key Approved!*\n\n"
                f"👤 User: @{customer_username_display} (`{customer_id}`)\n"
                f"🖥️ Server: {SERVERS[server_id]['name']}\n"
                f"📦 Plan: {free_plan['name']}\n"
                f"⏰ Expiry: {expiry_str}\n\n"
                f"✓ Key created and sent to user",
                call.message.chat.id,
                call.message.message_id,
                parse_mode='Markdown'
            )
        else:
            bot.edit_message_text(
                f"❌ *Failed to create key*\n\n"
                f"👤 User: @{customer_username} ({customer_id})\n"
                f"Error: {result.get('error', 'Unknown error') if result else 'No response'}",
                call.message.chat.id,
                call.message.message_id,
                parse_mode='Markdown'
            )
    
    # Admin reject referral free key (must be BEFORE generic reject_ handler)
    elif data.startswith("reject_freekey_"):
        # Allow rejection from Payment Channel or Admin
        if call.message.chat.id != PAYMENT_CHANNEL_ID and user_id != ADMIN_CHAT_ID:
            bot.answer_callback_query(call.id, "❌ Admin only!", show_alert=True)
            return
        
        try:
            customer_id = int(data.split("_")[2])
        except (ValueError, IndexError):
            bot.answer_callback_query(call.id, "❌ Invalid data.", show_alert=True)
            return
        
        # Get customer info
        customer = get_user(customer_id)
        customer_username = customer[2] if customer and customer[2] else f"User_{customer_id}"
        customer_username_display = customer_username.replace("_", "\\_") if customer_username else f"User\\_{customer_id}"
        
        # Notify customer
        reject_keyboard = types.InlineKeyboardMarkup(row_width=1)
        reject_keyboard.add(
            types.InlineKeyboardButton("👥 Referral Menu", callback_data="referral"),
            types.InlineKeyboardButton("📞 Admin ဆက်သွယ်ရန်", url="https://t.me/BDS_Admin"),
            types.InlineKeyboardButton("🏠 Main Menu", callback_data="main_menu")
        )
        bot.send_message(
            customer_id,
            "❌ *Referral Free Key Request Rejected*\n\n"
            "ပြဿနာရှိပါက Admin ကို ဆက်သွယ်ပါ။",
            parse_mode='Markdown',
            reply_markup=reject_keyboard
        )
        
        # Update admin message
        bot.edit_message_text(
            f"❌ *Referral Free Key Rejected*\n\n"
            f"👤 User: @{customer_username_display} (`{customer_id}`)\n\n"
            f"✗ Request rejected by admin",
            call.message.chat.id,
            call.message.message_id,
            parse_mode='Markdown'
        )
    
    # Admin approve order (from Payment Channel)
    elif data.startswith("approve_"):
        # Allow approval from Payment Channel or Admin
        if call.message.chat.id != PAYMENT_CHANNEL_ID and user_id != ADMIN_CHAT_ID:
            SecurityLogger.log_failed_auth(user_id, "approve_order")
            bot.answer_callback_query(call.id, "❌ Admin only!", show_alert=True)
            return
        
        parts = data.split("_")
        
        # Security: Validate order_id and customer_id are integers
        try:
            order_id = int(parts[1])
            customer_id = int(parts[2])
        except (ValueError, IndexError):
            SecurityLogger.log_suspicious_activity(user_id, "INVALID_APPROVE_DATA", data)
            bot.answer_callback_query(call.id, "❌ Invalid order data.", show_alert=True)
            return
        
        SecurityLogger.log_admin_action(user_id, "approve_order", f"order_id={order_id}")
        
        # Get order details
        order = get_order(order_id)
        if not order:
            bot.answer_callback_query(call.id, "Order not found!", show_alert=True)
            return
        
        # Check if order is already approved
        if order[6] != 'pending':  # status column
            safe_username = str(customer_id)
            customer = get_user(customer_id)
            if customer and customer[2]:
                safe_username = str(customer[2]).replace('_', '\\_')
            
            bot.edit_message_caption(
                caption=f"ℹ️ *Order #{order_id} Already Processed*\n\n"
                        f"👤 User: @{safe_username} ({customer_id})\n"
                        f"📊 Status: {order[6]}\n\n"
                        f"_This order was already handled._",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                parse_mode='Markdown'
            )
            return
        
        # Cancel auto-approve timer if exists
        cancel_auto_approve(order_id)
        
        server_id = order[2]
        plan_id = order[3]
        protocol = order[5] if len(order) > 5 else 'trojan'  # protocol column
        plan = PLANS.get(plan_id)
        
        # Get customer username
        customer = get_user(customer_id)
        customer_username = customer[2] if customer and customer[2] else f"User_{customer_id}"
        
        # Get current key count for this customer to determine key number
        existing_keys = get_user_keys(customer_id)
        key_number = len(existing_keys) + 1
        
        bot.edit_message_caption(
            caption="⏳ Key ဖန်တီးနေပါသည်...",
            chat_id=call.message.chat.id,
            message_id=call.message.message_id
        )
        
        # Create VPN key with username and protocol
        result = create_vpn_key(
            server_id=server_id,
            telegram_id=customer_id,
            username=customer_username,
            data_limit_gb=plan['data_limit'],
            expiry_days=plan['expiry_days'],
            devices=plan['devices'],
            protocol=protocol,
            key_number=key_number
        )
        
        if result and result.get('success'):
            approve_order(order_id, user_id)
            config_link = result.get('config_link', result['sub_link'])
            save_vpn_key(
                telegram_id=customer_id,
                order_id=order_id,
                server_id=server_id,
                client_email=result['client_email'],
                client_id=result['client_id'],
                sub_link=result['sub_link'],
                config_link=config_link,
                data_limit=plan['data_limit'],
                expiry_date=result['expiry_date']
            )
            
            # Notify customer
            expiry_str = result['expiry_date'].strftime('%Y-%m-%d %H:%M')
            data_limit_str = "Unlimited" if plan['data_limit'] == 0 else f"{plan['data_limit']} GB"
            
            customer_message = MESSAGES['key_generated'].format(
                server=SERVERS[server_id]['name'],
                plan=plan['name'],
                expiry=expiry_str,
                data_limit=data_limit_str,
                config_link=config_link,
                sub_link=result['sub_link']
            )
            
            # Create keyboard with buttons for customer
            markup = types.InlineKeyboardMarkup(row_width=2)
            markup.add(
                types.InlineKeyboardButton("🛒 Key ထပ်ဝယ်ရန်", callback_data="buy_key"),
                types.InlineKeyboardButton("📞 Admin ဆက်သွယ်ရန်", url="https://t.me/BDS_Admin")
            )
            markup.add(types.InlineKeyboardButton("🏠 Main Menu", callback_data="main_menu"))
            
            bot.send_message(customer_id, customer_message, reply_markup=markup, disable_web_page_preview=True)
            
            # Process referral reward
            process_referral_on_purchase(customer_id, order_id)
            
            # Update admin message with full order details
            bot.edit_message_caption(
                caption=f"✅ *Order #{order_id} Approved!*\n\n"
                        f"👤 User: @{customer_username} ({customer_id})\n"
                        f"🖥️ Server: {SERVERS[server_id]['name']}\n"
                        f"📦 Plan: {plan['name']}\n"
                        f"💰 Amount: {plan['price']:,} Ks\n"
                        f"📅 Expiry: {expiry_str}\n"
                        f"🔑 Key: {result['client_email']}\n\n"
                        f"✓ Key sent to user",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                parse_mode='Markdown'
            )
        else:
            bot.edit_message_caption(
                caption=f"❌ *Failed to create key*\n\n"
                        f"Order #{order_id}\n"
                        f"👤 User: @{customer_username} ({customer_id})\n"
                        f"🖥️ Server: {SERVERS[server_id]['name']}\n"
                        f"📦 Plan: {plan['name']}\n"
                        f"💰 Amount: {plan['price']:,} Ks",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                parse_mode='Markdown'
            )
    
    # Admin reject order (from Payment Channel)
    elif data.startswith("reject_"):
        # Allow rejection from Payment Channel or Admin
        if call.message.chat.id != PAYMENT_CHANNEL_ID and user_id != ADMIN_CHAT_ID:
            SecurityLogger.log_failed_auth(user_id, "reject_order")
            bot.answer_callback_query(call.id, "❌ Admin only!", show_alert=True)
            return
        
        parts = data.split("_")
        
        # Security: Validate order_id and customer_id are integers
        try:
            order_id = int(parts[1])
            customer_id = int(parts[2])
        except (ValueError, IndexError):
            SecurityLogger.log_suspicious_activity(user_id, "INVALID_REJECT_DATA", data)
            bot.answer_callback_query(call.id, "❌ Invalid order data.", show_alert=True)
            return
        
        # Cancel auto-approve timer if exists
        cancel_auto_approve(order_id)
        
        # Get order details for logging
        order = get_order(order_id)
        order_server_id = order[2] if order else 'Unknown'
        order_plan_id = order[3] if order else 'Unknown'
        order_amount = order[4] if order else 0
        plan = PLANS.get(order_plan_id, {})
        
        # Get customer info
        customer = get_user(customer_id)
        customer_username = customer[2] if customer and customer[2] else f"User_{customer_id}"
        
        SecurityLogger.log_admin_action(user_id, "reject_order", f"order_id={order_id}")
        
        reject_order(order_id, user_id)
        
        # Notify customer with navigation buttons
        reject_keyboard = types.InlineKeyboardMarkup(row_width=2)
        reject_keyboard.add(
            types.InlineKeyboardButton("🛒 Key ထပ်ဝယ်ရန်", callback_data="buy_key"),
            types.InlineKeyboardButton("📞 Admin ဆက်သွယ်ရန်", url="https://t.me/BDS_Admin")
        )
        reject_keyboard.add(
            types.InlineKeyboardButton("📖 Help", callback_data="help"),
            types.InlineKeyboardButton("🏠 Main Menu", callback_data="main_menu")
        )
        bot.send_message(
            customer_id, 
            "❌ *သင့် Order ပယ်ချခံရပါသည်။*\n\n"
            "ပြဿနာရှိပါက Admin ကို ဆက်သွယ်ပါ။\n"
            "သို့မဟုတ် ထပ်မံ Order တင်နိုင်ပါသည်။",
            reply_markup=reject_keyboard
        )
        
        # Update admin message with full order details
        bot.edit_message_caption(
            caption=f"❌ *Order #{order_id} Rejected!*\n\n"
                    f"👤 User: @{customer_username} ({customer_id})\n"
                    f"🖥️ Server: {SERVERS.get(order_server_id, {}).get('name', 'Unknown')}\n"
                    f"📦 Plan: {plan.get('name', order_plan_id)}\n"
                    f"💰 Amount: {order_amount:,} Ks\n\n"
                    f"✗ Order rejected by admin",
            chat_id=call.message.chat.id,
            message_id=call.message.message_id,
            parse_mode='Markdown'
        )
    
    # Admin menu handlers
    elif data == "admin_sales":
        if user_id != ADMIN_CHAT_ID:
            return
        
        stats = get_sales_stats()
        text = f"""
📊 *Sales Report*

💰 *Total Sales:* {stats['total_sales']:,} Ks
📅 *Today's Sales:* {stats['today_sales']:,} Ks
👥 *Total Users:* {stats['total_users']}
🔑 *Active Keys:* {stats['active_keys']}
⏳ *Pending Orders:* {stats['pending_orders']}
"""
        bot.edit_message_text(
            text,
            call.message.chat.id,
            call.message.message_id,
            reply_markup=admin_menu_keyboard()
        )
    
    elif data == "admin_pending":
        if user_id != ADMIN_CHAT_ID:
            return
        
        orders = get_all_orders('pending')
        if not orders:
            text = "✅ No pending orders"
        else:
            text = f"⏳ *Pending Orders ({len(orders)})*\n\n"
            for order in orders[:10]:  # Show last 10
                text += f"Order #{order[0]} - {order[4]:,} Ks\n"
        
        bot.edit_message_text(
            text,
            call.message.chat.id,
            call.message.message_id,
            reply_markup=admin_menu_keyboard()
        )
    
    elif data == "admin_users":
        if user_id != ADMIN_CHAT_ID:
            return
        
        users = get_all_users()
        text = f"👥 *All Users ({len(users)})*\n\n"
        for user in users[:20]:  # Show last 20
            username = user[2] if user[2] else "No username"
            text += f"• @{username} (ID: {user[1]})\n"
        
        bot.edit_message_text(
            text,
            call.message.chat.id,
            call.message.message_id,
            reply_markup=admin_menu_keyboard()
        )
    
    # Server management
    elif data == "admin_servers":
        if user_id != ADMIN_CHAT_ID:
            return
        
        db_server_count = len(get_all_db_servers(active_only=False))
        text = "🖥️ *Server Management*\n\n"
        text += "Server ကို နှိပ်ပြီး Enable/Disable လုပ်နိုင်ပါတယ်။\n"
        text += f"📦 = Database မှ ထည့်ထားသော Server\n\n"
        text += f"📊 Total: {len(SERVERS)} servers ({db_server_count} custom)\n\n"
        
        for server_id, server in SERVERS.items():
            status = "🔴" if server_id in disabled_servers else "🟢"
            db_tag = " 📦" if server.get('from_database') else ""
            panel_type = server.get('panel_type', 'xui').upper()
            text += f"{status} {server['name']} [{panel_type}]{db_tag}\n"
        
        bot.edit_message_text(
            text,
            call.message.chat.id,
            call.message.message_id,
            reply_markup=server_management_keyboard()
        )
    
    elif data.startswith("toggle_server_"):
        if user_id != ADMIN_CHAT_ID:
            return
        
        server_id = data.replace("toggle_server_", "")
        
        if server_id in disabled_servers:
            disabled_servers.remove(server_id)
            action = "✅ Enabled"
        else:
            disabled_servers.add(server_id)
            action = "🔴 Disabled"
        
        server_name = SERVERS.get(server_id, {}).get('name', server_id)
        bot.answer_callback_query(call.id, f"{action}: {server_name}", show_alert=True)
        
        # Refresh server management page
        db_server_count = len(get_all_db_servers(active_only=False))
        text = "🖥️ *Server Management*\n\n"
        text += "Server ကို နှိပ်ပြီး Enable/Disable လုပ်နိုင်ပါတယ်။\n"
        text += f"📦 = Database မှ ထည့်ထားသော Server\n\n"
        text += f"📊 Total: {len(SERVERS)} servers ({db_server_count} custom)\n\n"
        
        for sid, server in SERVERS.items():
            status = "🔴" if sid in disabled_servers else "🟢"
            db_tag = " 📦" if server.get('from_database') else ""
            panel_type = server.get('panel_type', 'xui').upper()
            text += f"{status} {server['name']} [{panel_type}]{db_tag}\n"
        
        bot.edit_message_text(
            text,
            call.message.chat.id,
            call.message.message_id,
            reply_markup=server_management_keyboard()
        )
    
    # ==================== ADD SERVER ====================
    elif data == "add_server_start":
        if user_id != ADMIN_CHAT_ID:
            return
        
        text = "➕ *Add New Server*\n\n"
        text += "Panel Type ရွေးချယ်ပါ:"
        
        bot.edit_message_text(
            text,
            call.message.chat.id,
            call.message.message_id,
            reply_markup=add_server_type_keyboard()
        )
    
    elif data == "add_server_xui":
        if user_id != ADMIN_CHAT_ID:
            return
        
        user_sessions[user_id] = {'action': 'add_server', 'panel_type': 'xui', 'step': 1}
        
        text = "🖥️ *Add 3X-UI Server*\n\n"
        text += "အောက်ပါ Format အတိုင်း Server Info ထည့်ပါ:\n\n"
        text += "```\n"
        text += "Server ID: sg4\n"
        text += "Name: 🇸🇬 Singapore 4\n"
        text += "URL: https://sg4.example.com:8080\n"
        text += "Panel Path: /mka\n"
        text += "Domain: sg4.example.com\n"
        text += "Sub Port: 2096\n"
        text += "```\n\n"
        text += "💡 Format:\n`server_id,name,url,panel_path,domain,sub_port`\n\n"
        text += "Example:\n`sg4,🇸🇬 Singapore 4,https://sg4.example.com:8080,/mka,sg4.example.com,2096`"
        
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton("❌ Cancel", callback_data="admin_servers"))
        
        bot.edit_message_text(
            text,
            call.message.chat.id,
            call.message.message_id,
            reply_markup=markup
        )
    
    elif data == "add_server_hiddify":
        if user_id != ADMIN_CHAT_ID:
            return
        
        user_sessions[user_id] = {'action': 'add_server', 'panel_type': 'hiddify', 'step': 1}
        
        text = "🌐 *Add Hiddify Server*\n\n"
        text += "အောက်ပါ Format အတိုင်း Server Info ထည့်ပါ:\n\n"
        text += "```\n"
        text += "Server ID: hiddify2\n"
        text += "Name: 🌐 Hiddify Server 2\n"
        text += "URL: https://hiddify2.example.com\n"
        text += "Admin Path: AdminUUID123\n"
        text += "Domain: hiddify2.example.com\n"
        text += "API Key: your-api-key\n"
        text += "User Sub Path: UserSubPath\n"
        text += "```\n\n"
        text += "💡 Format:\n`server_id,name,url,admin_path,domain,api_key,user_sub_path`\n\n"
        text += "Example:\n`hiddify2,🌐 Hiddify 2,https://h2.example.com,AdminPath,h2.example.com,api-key-here,UserSubPath`"
        
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton("❌ Cancel", callback_data="admin_servers"))
        
        bot.edit_message_text(
            text,
            call.message.chat.id,
            call.message.message_id,
            reply_markup=markup
        )
    
    # ==================== DELETE SERVER ====================
    elif data == "delete_server_start":
        if user_id != ADMIN_CHAT_ID:
            return
        
        text = "🗑️ *Delete Server*\n\n"
        text += "⚠️ Config.py မှ Server များကို ဖျက်၍မရပါ။\n"
        text += "Database မှ ထည့်ထားသော Server များသာ ဖျက်နိုင်ပါသည်။\n\n"
        text += "ဖျက်မည့် Server ကို ရွေးပါ:"
        
        bot.edit_message_text(
            text,
            call.message.chat.id,
            call.message.message_id,
            reply_markup=delete_server_keyboard()
        )
    
    elif data.startswith("confirm_delete_server_"):
        if user_id != ADMIN_CHAT_ID:
            return
        
        server_id = data.replace("confirm_delete_server_", "")
        server = get_server(server_id)
        
        if not server:
            bot.answer_callback_query(call.id, "❌ Server not found!", show_alert=True)
            return
        
        text = f"⚠️ *Confirm Delete*\n\n"
        text += f"Server: {server['name']}\n"
        text += f"ID: `{server_id}`\n"
        text += f"Type: {server['panel_type'].upper()}\n\n"
        text += "ဒီ Server ကို ဖျက်မှာ သေချာပါသလား?"
        
        markup = types.InlineKeyboardMarkup(row_width=2)
        markup.add(
            types.InlineKeyboardButton("✅ Yes, Delete", callback_data=f"do_delete_server_{server_id}"),
            types.InlineKeyboardButton("❌ Cancel", callback_data="delete_server_start")
        )
        
        bot.edit_message_text(
            text,
            call.message.chat.id,
            call.message.message_id,
            reply_markup=markup
        )
    
    elif data.startswith("do_delete_server_"):
        if user_id != ADMIN_CHAT_ID:
            return
        
        server_id = data.replace("do_delete_server_", "")
        
        if delete_server(server_id):
            # Reload servers
            load_servers()
            bot.answer_callback_query(call.id, f"✅ Server {server_id} deleted!", show_alert=True)
        else:
            bot.answer_callback_query(call.id, "❌ Delete failed!", show_alert=True)
        
        # Go back to server management
        db_server_count = len(get_all_db_servers(active_only=False))
        text = "🖥️ *Server Management*\n\n"
        text += f"📊 Total: {len(SERVERS)} servers ({db_server_count} custom)\n\n"
        
        for sid, server in SERVERS.items():
            status = "🔴" if sid in disabled_servers else "🟢"
            db_tag = " 📦" if server.get('from_database') else ""
            text += f"{status} {server['name']}{db_tag}\n"
        
        bot.edit_message_text(
            text,
            call.message.chat.id,
            call.message.message_id,
            reply_markup=server_management_keyboard()
        )
    
    elif data == "admin_back":
        if user_id != ADMIN_CHAT_ID:
            return
        
        bot.edit_message_text(
            "🔐 *Admin Panel*",
            call.message.chat.id,
            call.message.message_id,
            reply_markup=admin_menu_keyboard()
        )
    
    # Manual Backup
    elif data == "admin_backup":
        if user_id != ADMIN_CHAT_ID:
            return
        
        bot.answer_callback_query(call.id, "⏳ Creating backup...", show_alert=False)
        
        # Run backup in separate thread to not block
        def do_backup():
            if manual_backup():
                bot.send_message(
                    ADMIN_CHAT_ID,
                    "✅ Backup created and sent to Payment Channel!"
                )
            else:
                bot.send_message(
                    ADMIN_CHAT_ID,
                    "❌ Backup failed! Check logs."
                )
        
        threading.Thread(target=do_backup, daemon=True).start()
    
    # Feature Management
    elif data == "admin_features":
        if user_id != ADMIN_CHAT_ID:
            return
        
        text = "⚙️ *Feature Management*\n\n"
        text += "Feature ကို နှိပ်ပြီး Enable/Disable လုပ်နိုင်ပါတယ်။\n\n"
        
        feature_names = {
            'referral_system': '👥 Referral System',
            'free_test_key': '🎁 Free Test Key',
            'protocol_change': '🔄 Protocol Change',
            'auto_approve': '🤖 Auto-Approve (OCR)',
        }
        
        for feature_id, feature_name in feature_names.items():
            status = "🟢 ON" if feature_flags.get(feature_id, True) else "🔴 OFF"
            text += f"• {feature_name} - {status}\n"
        
        bot.edit_message_text(
            text,
            call.message.chat.id,
            call.message.message_id,
            reply_markup=feature_management_keyboard()
        )
    
    elif data.startswith("toggle_feature_"):
        if user_id != ADMIN_CHAT_ID:
            return
        
        feature_id = data.replace("toggle_feature_", "")
        
        # Toggle feature
        if feature_id in feature_flags:
            new_value = not feature_flags[feature_id]
            feature_flags[feature_id] = new_value
            # Save to database
            set_feature_flag(feature_id, new_value, updated_by=user_id)
            action = "✅ Enabled" if new_value else "🔴 Disabled"
        else:
            bot.answer_callback_query(call.id, "❌ Unknown feature", show_alert=True)
            return
        
        feature_names = {
            'referral_system': 'Referral System',
            'free_test_key': 'Free Test Key',
            'protocol_change': 'Protocol Change',
            'auto_approve': 'Auto-Approve',
        }
        
        feature_name = feature_names.get(feature_id, feature_id)
        bot.answer_callback_query(call.id, f"{action}: {feature_name}", show_alert=True)
        
        # Refresh feature management page
        text = "⚙️ *Feature Management*\n\n"
        text += "Feature ကို နှိပ်ပြီး Enable/Disable လုပ်နိုင်ပါတယ်။\n\n"
        
        for fid, fname in feature_names.items():
            status = "🟢 ON" if feature_flags.get(fid, True) else "🔴 OFF"
            text += f"• {fname} - {status}\n"
        
        bot.edit_message_text(
            text,
            call.message.chat.id,
            call.message.message_id,
            reply_markup=feature_management_keyboard()
        )
    
    # ==================== STATISTICS ====================
    elif data == "admin_stats":
        if user_id != ADMIN_CHAT_ID:
            return
        
        bot.edit_message_text(
            "📈 *Statistics Dashboard*\n\n"
            "အချိန်ကာလ ရွေးချယ်ပါ:",
            call.message.chat.id,
            call.message.message_id,
            reply_markup=stats_period_keyboard()
        )
    
    elif data.startswith("stats_"):
        if user_id != ADMIN_CHAT_ID:
            return
        
        period = data.replace("stats_", "")
        
        if period == "top_users":
            top_users = get_top_users(10)
            text = "🏆 *Top 10 Users (By Spending)*\n\n"
            
            if not top_users:
                text += "User မရှိသေးပါ။"
            else:
                for i, user in enumerate(top_users, 1):
                    name = user['username'] or user['first_name'] or f"User {user['telegram_id']}"
                    text += f"{i}. {name}\n"
                    text += f"   💰 {user['total_spent']:,} Ks | 🛒 {user['order_count']} orders\n\n"
            
            markup = types.InlineKeyboardMarkup()
            markup.add(types.InlineKeyboardButton("🔙 Back", callback_data="admin_stats"))
            
            bot.edit_message_text(
                text,
                call.message.chat.id,
                call.message.message_id,
                reply_markup=markup
            )
            return
        
        elif period == "revenue":
            revenue_data = get_revenue_by_period()
            text = "💰 *Revenue (Last 7 Days)*\n\n"
            
            if not revenue_data:
                text += "Data မရှိသေးပါ။"
            else:
                total = 0
                for day in revenue_data:
                    text += f"📅 {day['date']}: {day['revenue']:,} Ks ({day['orders']} orders)\n"
                    total += day['revenue']
                text += f"\n📊 Total: {total:,} Ks"
            
            markup = types.InlineKeyboardMarkup()
            markup.add(types.InlineKeyboardButton("🔙 Back", callback_data="admin_stats"))
            
            bot.edit_message_text(
                text,
                call.message.chat.id,
                call.message.message_id,
                reply_markup=markup
            )
            return
        
        # Period-based stats
        period_names = {
            'today': 'Today',
            'week': 'This Week',
            'month': 'This Month',
            'all': 'All Time'
        }
        
        stats = get_statistics(period)
        period_name = period_names.get(period, 'All Time')
        
        text = f"📊 *Statistics - {period_name}*\n\n"
        text += f"👥 Users: {stats['total_users']:,}\n"
        text += f"🛒 Total Orders: {stats['total_orders']:,}\n"
        text += f"✅ Completed: {stats['completed_orders']:,}\n"
        text += f"⏳ Pending: {stats['pending_orders']:,}\n"
        text += f"❌ Rejected: {stats['rejected_orders']:,}\n"
        text += f"💰 Revenue: {stats['total_revenue']:,} Ks\n\n"
        text += f"🔑 Active Keys: {stats['active_keys']:,}\n"
        text += f"🎁 Free Tests: {stats['free_tests_used']:,}\n"
        text += f"👥 Referrals: {stats['total_referrals']:,}\n"
        text += f"🚫 Banned Users: {stats['banned_users']:,}\n"
        
        bot.edit_message_text(
            text,
            call.message.chat.id,
            call.message.message_id,
            reply_markup=stats_period_keyboard()
        )
    
    # ==================== BAN MANAGEMENT ====================
    elif data == "admin_bans":
        if user_id != ADMIN_CHAT_ID:
            return
        
        banned = get_banned_users()
        text = "🚫 *Ban Management*\n\n"
        text += f"Currently banned: {len(banned)} users\n\n"
        text += "အောက်ပါ options ကို ရွေးချယ်ပါ:"
        
        bot.edit_message_text(
            text,
            call.message.chat.id,
            call.message.message_id,
            reply_markup=ban_management_keyboard()
        )
    
    elif data == "ban_user_start":
        if user_id != ADMIN_CHAT_ID:
            return
        
        user_sessions[user_id] = {'action': 'ban_user'}
        
        text = "🚫 *Ban User*\n\n"
        text += "Ban လုပ်မည့် User ၏ Telegram ID ထည့်ပါ:\n\n"
        text += "Format: `USER_ID HOURS REASON`\n"
        text += "Example: `123456789 24 Spam messages`\n\n"
        text += "💡 HOURS = 0 သို့မဟုတ် မထည့်ပါက Permanent ban\n"
        text += "💡 REASON မထည့်လည်း ရပါတယ်"
        
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton("❌ Cancel", callback_data="admin_bans"))
        
        bot.edit_message_text(
            text,
            call.message.chat.id,
            call.message.message_id,
            reply_markup=markup
        )
    
    elif data == "unban_user_start":
        if user_id != ADMIN_CHAT_ID:
            return
        
        user_sessions[user_id] = {'action': 'unban_user'}
        
        text = "✅ *Unban User*\n\n"
        text += "Unban လုပ်မည့် User ၏ Telegram ID ထည့်ပါ:"
        
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton("❌ Cancel", callback_data="admin_bans"))
        
        bot.edit_message_text(
            text,
            call.message.chat.id,
            call.message.message_id,
            reply_markup=markup
        )
    
    elif data == "ban_list":
        if user_id != ADMIN_CHAT_ID:
            return
        
        banned = get_banned_users()
        text = "📋 *Banned Users List*\n\n"
        
        if not banned:
            text += "Ban ထားသော user မရှိပါ။ 🎉"
        else:
            for i, user in enumerate(banned[:20], 1):  # Limit to 20
                name = user['username'] or user['first_name'] or f"User"
                ban_type = "♾️ Permanent" if user['is_permanent'] else f"⏱️ Until {user['banned_until'][:16]}"
                text += f"{i}. {name} (`{user['telegram_id']}`)\n"
                text += f"   {ban_type}\n"
                if user['reason']:
                    text += f"   📝 {user['reason'][:30]}\n"
                text += "\n"
            
            if len(banned) > 20:
                text += f"\n... and {len(banned) - 20} more"
        
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton("🔙 Back", callback_data="admin_bans"))
        
        bot.edit_message_text(
            text,
            call.message.chat.id,
            call.message.message_id,
            reply_markup=markup
        )
    
    elif data.startswith("unban_"):
        if user_id != ADMIN_CHAT_ID:
            return
        
        target_id = int(data.replace("unban_", ""))
        if unban_user(target_id, unbanned_by=user_id):
            bot.answer_callback_query(call.id, f"✅ User {target_id} unbanned!", show_alert=True)
        else:
            bot.answer_callback_query(call.id, "❌ Unban failed!", show_alert=True)
        
        # Refresh ban list
        banned = get_banned_users()
        text = "📋 *Banned Users List*\n\n"
        
        if not banned:
            text += "Ban ထားသော user မရှိပါ။ 🎉"
        else:
            for i, user in enumerate(banned[:20], 1):
                name = user['username'] or user['first_name'] or f"User"
                ban_type = "♾️ Permanent" if user['is_permanent'] else f"⏱️ Until {user['banned_until'][:16]}"
                text += f"{i}. {name} (`{user['telegram_id']}`)\n"
                text += f"   {ban_type}\n"
                text += "\n"
        
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton("🔙 Back", callback_data="admin_bans"))
        
        bot.edit_message_text(
            text,
            call.message.chat.id,
            call.message.message_id,
            reply_markup=markup
        )

# ===================== REPLY KEYBOARD BUTTON HANDLERS =====================

@bot.message_handler(func=lambda message: message.text in [
    "📊 My Referrals", "🔗 Share Link", "🔑 My Keys", "🏠 Main Menu", "🎁 Free Key ရယူမည်"
])
def handle_reply_keyboard_buttons(message):
    """Handle reply keyboard button presses"""
    user_id = message.from_user.id
    text = message.text
    
    # Security: Check if user is banned
    if is_user_banned(user_id):
        return
    
    # Remove reply keyboard and show inline keyboard based on button pressed
    if text == "📊 My Referrals":
        stats = get_referral_stats(user_id)
        msg_text = f"""
📊 *Referral Statistics*

👥 စုစုပေါင်း Refer: {stats['total_referred']} ယောက်
✅ ဝယ်ယူပြီးသူ: {stats['paid_referrals']} ယောက်
🎁 Bonus Days: {stats['bonus_days']} ရက်
🏆 Free Month Claimed: {stats['claimed_free_months']} ကြိမ်

{'🎉 **1 Month Free Key ရယူနိုင်ပါပြီ!**' if stats['can_claim_free_month'] else f'📈 Free Key ရဖို့ {3 - (stats["paid_referrals"] % 3)} ယောက် လိုပါသေးသည်'}
"""
        markup = types.InlineKeyboardMarkup(row_width=2)
        if stats['can_claim_free_month']:
            markup.add(types.InlineKeyboardButton("🎁 Free Key ရယူမည်", callback_data="claim_free_month"))
        markup.add(
            types.InlineKeyboardButton("🔗 Share Link", callback_data="my_referral_link"),
            types.InlineKeyboardButton("🔙 Back", callback_data="referral")
        )
        bot.send_message(user_id, msg_text, parse_mode='Markdown', reply_markup=markup)
        
    elif text == "🔗 Share Link":
        user = get_user(user_id)
        ref_code = user[4] if user else None  # referral_code column
        if ref_code:
            ref_link = f"https://t.me/BurmeseDigitalStore_bot?start=REF_{ref_code}"
            msg_text = f"""
🔗 *သင့် Referral Link*

👇 ဒီ Link ကို မျှဝေပါ:
`{ref_link}`

📌 *လုပ်ဆောင်ရန်:*
1. Link ကို Copy ကူးပါ
2. သူငယ်ချင်းများကို မျှဝေပါ
3. သူတို့ဝယ်ရင် သင် Bonus ရမယ်!

🎁 *Rewards:*
• တစ်ယောက်ဝယ်ရင် = +5 Days
• 3 ယောက်ဝယ်ရင် = 1 Month Free Key
"""
            markup = types.InlineKeyboardMarkup()
            markup.add(types.InlineKeyboardButton("📊 My Stats", callback_data="referral_stats"))
            markup.add(types.InlineKeyboardButton("🔙 Back", callback_data="referral"))
            bot.send_message(user_id, msg_text, parse_mode='Markdown', reply_markup=markup)
        else:
            bot.send_message(user_id, "❌ Referral code မရှိပါ။", reply_markup=main_menu_keyboard())
    
    elif text == "🔑 My Keys":
        # Trigger the my_keys callback
        keys = get_user_keys(user_id)
        if not keys:
            markup = types.InlineKeyboardMarkup()
            markup.add(types.InlineKeyboardButton("💎 Buy VPN Key", callback_data="buy_key"))
            markup.add(types.InlineKeyboardButton("🏠 Main Menu", callback_data="main_menu"))
            bot.send_message(user_id, "🔑 သင့်မှာ Key မရှိသေးပါ။\n\n💎 Key ဝယ်ယူရန် အောက်က Button ကို နှိပ်ပါ။", reply_markup=markup)
        else:
            msg_text = "🔑 *သင့် VPN Keys:*\n\n"
            markup = types.InlineKeyboardMarkup(row_width=1)
            for i, key in enumerate(keys, 1):
                key_id, order_id, server_id, client_email, sub_link, config_link, data_limit, expiry_date, created_at = key[:9]
                server_name = SERVERS.get(server_id, {}).get('name', 'Unknown')
                expiry_str = expiry_date if isinstance(expiry_date, str) else expiry_date.strftime('%Y-%m-%d')
                msg_text += f"*{i}. {server_name}*\nExpiry: {expiry_str}\n\n"
                markup.add(types.InlineKeyboardButton(f"🔑 Key {i}: {server_name}", callback_data=f"view_key_{key_id}"))
            markup.add(types.InlineKeyboardButton("🏠 Main Menu", callback_data="main_menu"))
            bot.send_message(user_id, msg_text, parse_mode='Markdown', reply_markup=markup)
    
    elif text == "🏠 Main Menu":
        bot.send_message(
            user_id,
            MESSAGES['welcome'],
            reply_markup=main_menu_keyboard()
        )
    
    elif text == "🎁 Free Key ရယူမည်":
        # Check eligibility and send request to admin channel
        stats = get_referral_stats(user_id)
        if stats['can_claim_free_month']:
            user = get_user(user_id)
            username = user[2] if user and user[2] else f"User_{user_id}"
            username_display = username.replace("_", "\\_") if username else f"User\\_{user_id}"
            
            admin_text = f"""🎁 *Referral Free Key Request*

👤 User: @{username_display}
🆔 User ID: `{user_id}`

📊 *Referral Stats:*
• စုစုပေါင်း Refer: {stats['total_referred']} ယောက်
• ဝယ်ယူပြီးသူ: {stats['paid_referrals']} ယောက်
• Claimed Free Keys: {stats['claimed_free_months']} ကြိမ်

🎁 *Request:* 1 Month Free Key (1 Device)

✅ Approve နှိပ်ရင် Key အလိုအလျောက် ဖန်တီးပေးပါမည်။"""
            
            admin_markup = types.InlineKeyboardMarkup(row_width=2)
            admin_markup.add(
                types.InlineKeyboardButton("✅ Approve", callback_data=f"approve_freekey_{user_id}"),
                types.InlineKeyboardButton("❌ Reject", callback_data=f"reject_freekey_{user_id}")
            )
            
            try:
                bot.send_message(PAYMENT_CHANNEL_ID, admin_text, parse_mode='Markdown', reply_markup=admin_markup)
            except Exception as e:
                logger.error(f"Error sending free key request: {e}")
            
            bot.send_message(
                user_id,
                "🎉 *Request Sent!*\n\n"
                "သင့် 1 Month Free Key request ကို Admin ထံ ပို့လိုက်ပါပြီ!\n\n"
                "⏳ Admin Approve ပြီးတာနဲ့ Key အလိုအလျောက် ရရှိမှာပါ။",
                parse_mode='Markdown',
                reply_markup=main_menu_keyboard()
            )
        else:
            remaining = 3 - (stats['paid_referrals'] % 3)
            bot.send_message(
                user_id,
                f"❌ *ရယူ၍မရသေးပါ*\n\n"
                f"Free Key ရဖို့ {remaining} ယောက် လိုပါသေးသည်။\n\n"
                f"📌 သင့် Referral Link ကို မျှဝေပြီး ဆက်လက် Refer လုပ်ပါ!",
                parse_mode='Markdown',
                reply_markup=main_menu_keyboard()
            )

# ===================== ADMIN TEXT INPUT HANDLER =====================

@bot.message_handler(func=lambda message: message.from_user.id == ADMIN_CHAT_ID and 
                     message.from_user.id in user_sessions and 
                     user_sessions.get(message.from_user.id, {}).get('action') in ['ban_user', 'unban_user', 'add_server'])
def handle_admin_text_input(message):
    """Handle admin text input for ban/unban/add_server"""
    user_id = message.from_user.id
    session = user_sessions.get(user_id, {})
    action = session.get('action')
    
    # ==================== ADD SERVER ====================
    if action == 'add_server':
        panel_type = session.get('panel_type', 'xui')
        text = message.text.strip()
        
        try:
            parts = [p.strip() for p in text.split(',')]
            
            if panel_type == 'xui':
                # Format: server_id,name,url,panel_path,domain,sub_port
                if len(parts) < 5:
                    bot.reply_to(message, "❌ Invalid format!\n\nFormat: `server_id,name,url,panel_path,domain,sub_port`", parse_mode='Markdown')
                    return
                
                server_id = parts[0].lower().replace(' ', '_')
                name = parts[1]
                url = parts[2]
                panel_path = parts[3]
                domain = parts[4]
                sub_port = int(parts[5]) if len(parts) > 5 else 2096
                
                # Validate
                if server_id in SERVERS:
                    bot.reply_to(message, f"❌ Server ID `{server_id}` already exists!", parse_mode='Markdown')
                    user_sessions.pop(user_id, None)
                    return
                
                # Add to database
                if add_server(
                    server_id=server_id,
                    name=name,
                    url=url,
                    panel_path=panel_path,
                    domain=domain,
                    panel_type='xui',
                    sub_port=sub_port,
                    created_by=user_id
                ):
                    # Reload servers
                    load_servers()
                    
                    bot.reply_to(
                        message,
                        f"✅ *Server Added Successfully!*\n\n"
                        f"🆔 ID: `{server_id}`\n"
                        f"📛 Name: {name}\n"
                        f"🌐 URL: {url}\n"
                        f"🔧 Panel: 3X-UI\n"
                        f"📍 Domain: {domain}\n"
                        f"🔌 Sub Port: {sub_port}\n\n"
                        f"Server ကို အသုံးပြုနိုင်ပါပြီ!",
                        parse_mode='Markdown'
                    )
                else:
                    bot.reply_to(message, "❌ Failed to add server! Please try again.")
                    
            elif panel_type == 'hiddify':
                # Format: server_id,name,url,admin_path,domain,api_key,user_sub_path
                if len(parts) < 6:
                    bot.reply_to(message, "❌ Invalid format!\n\nFormat: `server_id,name,url,admin_path,domain,api_key,user_sub_path`", parse_mode='Markdown')
                    return
                
                server_id = parts[0].lower().replace(' ', '_')
                name = parts[1]
                url = parts[2]
                admin_path = parts[3]  # panel_path for Hiddify
                domain = parts[4]
                api_key = parts[5]
                user_sub_path = parts[6] if len(parts) > 6 else admin_path
                
                # Validate
                if server_id in SERVERS:
                    bot.reply_to(message, f"❌ Server ID `{server_id}` already exists!", parse_mode='Markdown')
                    user_sessions.pop(user_id, None)
                    return
                
                # Add to database
                if add_server(
                    server_id=server_id,
                    name=name,
                    url=url,
                    panel_path=admin_path,
                    domain=domain,
                    panel_type='hiddify',
                    api_key=api_key,
                    admin_uuid=api_key,
                    proxy_path=admin_path,
                    user_sub_path=user_sub_path,
                    created_by=user_id
                ):
                    # Reload servers
                    load_servers()
                    
                    bot.reply_to(
                        message,
                        f"✅ *Hiddify Server Added Successfully!*\n\n"
                        f"🆔 ID: `{server_id}`\n"
                        f"📛 Name: {name}\n"
                        f"🌐 URL: {url}\n"
                        f"🔧 Panel: Hiddify\n"
                        f"📍 Domain: {domain}\n\n"
                        f"Server ကို အသုံးပြုနိုင်ပါပြီ!",
                        parse_mode='Markdown'
                    )
                else:
                    bot.reply_to(message, "❌ Failed to add server! Please try again.")
        
        except Exception as e:
            bot.reply_to(message, f"❌ Error: {str(e)}\n\nPlease check the format and try again.")
        
        user_sessions.pop(user_id, None)
        return
    
    # ==================== BAN USER ====================
    elif action == 'ban_user':
        # Parse: USER_ID HOURS REASON
        parts = message.text.strip().split(maxsplit=2)
        
        try:
            target_id = int(parts[0])
        except (ValueError, IndexError):
            bot.reply_to(message, "❌ Invalid user ID! Format: `USER_ID HOURS REASON`", parse_mode='Markdown')
            return
        
        # Get hours (optional, default = permanent)
        hours = None
        reason = None
        if len(parts) >= 2:
            try:
                hours = int(parts[1])
                if hours == 0:
                    hours = None  # Permanent
            except ValueError:
                # Second part is reason, not hours
                reason = parts[1]
        
        if len(parts) >= 3:
            reason = parts[2]
        
        # Check if user exists
        target_user = get_user(target_id)
        if not target_user:
            bot.reply_to(message, f"⚠️ User {target_id} not found in database. Ban anyway?")
        
        # Perform ban
        if ban_user(target_id, reason=reason, duration_hours=hours, banned_by=user_id):
            ban_type = f"⏱️ {hours} hours" if hours else "♾️ Permanent"
            reason_text = f"\n📝 Reason: {reason}" if reason else ""
            
            bot.reply_to(
                message, 
                f"✅ *User Banned*\n\n"
                f"👤 User ID: `{target_id}`\n"
                f"🚫 Ban Type: {ban_type}{reason_text}",
                parse_mode='Markdown'
            )
            
            # Try to notify the banned user
            try:
                ban_msg = "⚠️ *Account Suspended*\n\n"
                if hours:
                    ban_msg += f"Your account has been temporarily suspended for {hours} hours.\n"
                else:
                    ban_msg += "Your account has been suspended.\n"
                if reason:
                    ban_msg += f"\nReason: {reason}"
                ban_msg += "\n\nContact support if you believe this is a mistake."
                bot.send_message(target_id, ban_msg, parse_mode='Markdown')
            except:
                pass  # User may have blocked the bot
        else:
            bot.reply_to(message, "❌ Ban failed! Please try again.")
        
        # Clear session
        user_sessions.pop(user_id, None)
    
    elif action == 'unban_user':
        try:
            target_id = int(message.text.strip())
        except ValueError:
            bot.reply_to(message, "❌ Invalid user ID!")
            return
        
        # Check if user is actually banned
        ban_info = is_user_banned_db(target_id)
        if not ban_info:
            bot.reply_to(message, f"⚠️ User {target_id} is not banned.")
            user_sessions.pop(user_id, None)
            return
        
        # Perform unban
        if unban_user(target_id, unbanned_by=user_id):
            bot.reply_to(
                message,
                f"✅ *User Unbanned*\n\n"
                f"👤 User ID: `{target_id}`",
                parse_mode='Markdown'
            )
            
            # Try to notify the user
            try:
                bot.send_message(
                    target_id,
                    "✅ *Account Restored*\n\n"
                    "Your account has been unbanned. You can now use the bot again.\n\n"
                    "Type /start to continue.",
                    parse_mode='Markdown'
                )
            except:
                pass
        else:
            bot.reply_to(message, "❌ Unban failed! Please try again.")
        
        # Clear session
        user_sessions.pop(user_id, None)

@bot.message_handler(content_types=['photo'])
def handle_photo(message):
    """Handle payment screenshots with OCR verification"""
    user_id = message.from_user.id
    
    # Security: Check if user is banned
    if is_user_banned(user_id):
        return
    
    # Security: Rate limiting for screenshots
    allowed, error_msg = check_rate_limit(user_id, 'screenshot')
    if not allowed:
        bot.reply_to(message, error_msg)
        return
    
    # Debug: Log photo received
    print(f"📷 Photo received from user {user_id}")
    print(f"   Session exists: {user_id in user_sessions}")
    if user_id in user_sessions:
        print(f"   Waiting screenshot: {user_sessions[user_id].get('waiting_screenshot')}")
        print(f"   Order ID: {user_sessions[user_id].get('order_id')}")
    
    if user_id not in user_sessions or not user_sessions[user_id].get('waiting_screenshot'):
        bot.reply_to(message, "⚠️ Order အရင်လုပ်ပြီးမှ Screenshot ပို့ပါ။\n\n🛒 Buy Key -> Server ရွေး -> Plan ရွေး -> Screenshot ပို့ပါ")
        return
    
    session = user_sessions[user_id]
    order_id = session.get('order_id')
    
    if not order_id:
        bot.reply_to(message, "❌ No active order found.")
        return
    
    # Check if order is already processed (prevent duplicate submissions)
    order = get_order(order_id)
    if order and order[6] != 'pending':  # status column
        user_sessions[user_id]['waiting_screenshot'] = False
        bot.reply_to(message, 
            f"✅ *Order #{order_id} အတွက် Key ရပြီးသားပါ!*\n\n"
            "🔑 My Keys ကို နှိပ်ပြီး Key ကြည့်ပါ။",
            reply_markup=main_menu_keyboard()
        )
        return
    
    # Get photo file ID
    photo = message.photo[-1]  # Highest resolution
    file_id = photo.file_id
    print(f"   File ID: {file_id[:30]}...")
    
    # Security: Validate file size (max 10MB)
    if photo.file_size and photo.file_size > 10 * 1024 * 1024:
        bot.reply_to(message, "❌ File too large. Maximum size is 10MB.")
        return
    
    # Skip abuse check for now - database compatibility issue
    # try:
    #     recent_orders = get_user_orders(user_id, limit=10)
    #     should_block, _ = abuse_detector.check_order_pattern(user_id, recent_orders)
    #     if should_block:
    #         bot.reply_to(message, "⚠️ Too many submissions. Please wait before trying again.")
    #         return
    # except Exception as e:
    #     print(f"   ⚠️ Abuse check error (skipped): {e}")
    
    print(f"   Updating order {order_id} with screenshot...")
    # Update order with screenshot
    update_order_screenshot(order_id, file_id)
    
    # Get order details
    server_id = session.get('server_id')
    plan_id = session.get('plan_id')
    plan = PLANS.get(plan_id)
    expected_amount = session.get('amount', 0)
    
    # Clear session
    user_sessions[user_id]['waiting_screenshot'] = False
    
    # OCR Verification
    ocr_result = None
    ocr_verified = False
    ocr_amount = None
    
    # Check if auto-approve feature is enabled via feature flags
    auto_approve_enabled = OCR_ENABLED and AUTO_APPROVE_ENABLED and feature_flags.get('auto_approve', True)
    
    if auto_approve_enabled:
        bot.reply_to(message, "⏳ Screenshot စစ်ဆေးနေပါသည်...")
        
        try:
            ocr_result = process_payment_screenshot(bot, file_id, expected_amount, user_id=user_id)
            ocr_verified = ocr_result.get('verified', False)
            ocr_amount = ocr_result.get('ocr_amount')
            logger.info(f"OCR Result for order {order_id}: verified={ocr_verified}, amount={ocr_amount}, expected={expected_amount}")
        except Exception as e:
            logger.error(f"OCR Error: {e}")
            ocr_result = {'success': False, 'error': str(e)}
    
    # Create user navigation keyboard
    user_nav_keyboard = types.InlineKeyboardMarkup(row_width=2)
    user_nav_keyboard.add(
        types.InlineKeyboardButton("📖 Help", callback_data="help"),
        types.InlineKeyboardButton("📞 Contact", url="https://t.me/BDS_Admin")
    )
    user_nav_keyboard.add(types.InlineKeyboardButton("🏠 Main Menu", callback_data="main_menu"))
    
    # Notify user - Don't reveal OCR details to prevent fraud attempts
    bot.send_message(
        message.chat.id,
        "✅ *Screenshot လက်ခံရရှိပါပြီ!*\n\n"
        "Admin Approve ပြုလုပ်ပြီးသည်နှင့် VPN Key ကို ပေးပို့ပါမည်။\n"
        "ကျေးဇူးပြု၍ စောင့်ဆိုင်းပေးပါ။",
        reply_markup=user_nav_keyboard
    )
    
    # Notify admin
    user = message.from_user
    username_display = user.username if user.username else user.first_name
    username_display = sanitize_username(username_display)
    if username_display:
        username_display = username_display.replace("_", "\\_")
    
    # Build admin message with OCR info
    ocr_status = ""
    if ocr_result:
        if ocr_verified:
            ocr_status = f"\n\n🤖 *OCR Verification:*\n✅ Amount Match: {ocr_amount:,} Ks\n⏱️ 1 မိနစ်အတွင်း Auto-Approve"
        else:
            ocr_status = f"\n\n🤖 *OCR Verification:*\n❌ {ocr_result.get('reason', 'Failed')}"
            if ocr_amount:
                ocr_status += f"\n📖 Detected: {ocr_amount:,} Ks"
    
    # Check if user was referred by someone
    referral_info = ""
    referrer_id = get_referrer_id(user_id)
    if referrer_id:
        referrer = get_user(referrer_id)
        if referrer:
            referrer_username = referrer[2] if referrer[2] else f"User_{referrer_id}"
            # Escape underscores for Markdown
            referrer_username_display = referrer_username.replace("_", "\\_") if referrer_username else f"User\\_{referrer_id}"
            referral_info = f"\n\n🔗 *Referral Info:*\n👥 Referred by: @{referrer_username_display}\n🎁 Referrer will get +5 Days bonus"
    
    # Escape username for Markdown
    user_display = user.username if user.username else user.first_name
    if user_display:
        user_display = user_display.replace("_", "\\_")
    
    admin_text = f"""🛒 *Order အသစ် #{order_id}*

👤 User: @{user_display}
🆔 User ID: {user_id}
🖥️ Server: {SERVERS.get(server_id, {}).get('name', 'Unknown')}
📦 Plan: {plan['name'] if plan else 'Unknown'}
💰 Expected: {expected_amount:,} Ks{referral_info}{ocr_status}

📸 Payment Screenshot အောက်တွင်..."""
    
    # Send to Payment Proof Channel with screenshot
    try:
        admin_msg = bot.send_photo(
            PAYMENT_CHANNEL_ID,
            file_id,
            caption=admin_text,
            reply_markup=admin_order_keyboard(order_id, user_id),
            parse_mode='Markdown'
        )
        
        # Setup auto-approve timer if OCR verified and feature enabled
        if ocr_verified and AUTO_APPROVE_ENABLED and feature_flags.get('auto_approve', True):
            setup_auto_approve_timer(
                order_id=order_id,
                customer_id=user_id,
                server_id=server_id,
                plan_id=plan_id,
                admin_message_id=admin_msg.message_id,
                ocr_amount=ocr_amount
            )
            
    except Exception as e:
        logger.error(f"Error sending to payment channel: {e}")
        bot.send_photo(
            PAYMENT_CHANNEL_ID,
            file_id,
            caption=f"New Order #{order_id} from {user_id} - {expected_amount:,} Ks",
            reply_markup=admin_order_keyboard(order_id, user_id)
        )


# ===================== REFERRAL SYSTEM =====================

def show_referral_menu(call):
    """Show referral system menu"""
    user_id = call.from_user.id
    stats = get_referral_stats(user_id)
    
    text = f"""
👥 *Referral Program*

🎁 *သူငယ်ချင်းရှာပြီး ဆုရယူပါ!*

📌 *Reward များ:*
• Referral 1 ယောက်ဝယ်ရင် → **+5 Days** (Key သက်တမ်းတိုး)
• Referral 3 ယောက်ဝယ်ရင် → **1 Month Free Key**

📊 *သင့် Stats:*
• စုစုပေါင်း Refer: {stats['total_referred']} ယောက်
• ဝယ်ယူပြီးသူ: {stats['paid_referrals']} ယောက်
• Bonus Days: {stats['bonus_days']} ရက်
• Free Month Claimed: {stats['claimed_free_months']} ကြိမ်

{'🎉 **1 Month Free Key ရယူနိုင်ပါပြီ!**' if stats['can_claim_free_month'] else f'📈 Free Key ရဖို့ {3 - (stats["paid_referrals"] % 3)} ယောက် လိုပါသေးသည်'}
"""
    
    markup = types.InlineKeyboardMarkup(row_width=1)
    markup.add(
        types.InlineKeyboardButton("🔗 ကျွန်ုပ်၏ Referral Link", callback_data="my_referral_link"),
        types.InlineKeyboardButton("📊 Referral Stats", callback_data="referral_stats")
    )
    
    # Only show claim button when user has 3 paid referrals
    if stats['can_claim_free_month']:
        markup.add(types.InlineKeyboardButton("🎁 1 Month Free Key ရယူမည်", callback_data="claim_free_month"))
    
    markup.add(types.InlineKeyboardButton("🔙 Back", callback_data="main_menu"))
    
    bot.edit_message_text(
        text,
        call.message.chat.id,
        call.message.message_id,
        parse_mode='Markdown',
        reply_markup=markup
    )

def show_referral_link(call):
    """Show user's referral link"""
    user_id = call.from_user.id
    ref_code = get_referral_code(user_id)
    
    # Bot username - update this to your bot's username
    bot_username = "BurmeseDigitalStore_bot"
    ref_link = f"https://t.me/{bot_username}?start=REF_{ref_code}"
    
    text = f"""
🔗 *သင့် Referral Link*

Link:
`{ref_link}`

📋 *အသုံးပြုနည်း:*
1️⃣ Link ကို Copy ကူးပါ။
2️⃣ သူငယ်ချင်းတွေကို Share ပါ။
3️⃣ သူတို့ Key ဝယ်ရင် သင် Bonus ရပါမယ်။

🎁 *Rewards:*
• 1 ယောက်ဝယ်ရင် = +5 Days (Key သက်တမ်းတိုး)
• 3 ယောက်ဝယ်ရင် = 1 Month Free Key

📝 *မှတ်ချက်:*
• Fake Referral များ ခွင့်မပြုပါ။
• Self-referral လုပ်လို့မရပါ။
• တစ်ယောက်ကို တစ်ခါသာ Refer လုပ်လို့ရပါသည်။
"""
    
    markup = types.InlineKeyboardMarkup()
    markup.add(types.InlineKeyboardButton("📤 Share Link", url=f"https://t.me/share/url?url={ref_link}&text=VPN Key ဝယ်ဖို့ ဒီ link သုံးပါ"))
    markup.add(types.InlineKeyboardButton("🔙 Back", callback_data="referral"))
    
    bot.edit_message_text(
        text,
        call.message.chat.id,
        call.message.message_id,
        parse_mode='Markdown',
        reply_markup=markup
    )

def show_referral_stats(call):
    """Show detailed referral statistics"""
    user_id = call.from_user.id
    stats = get_referral_stats(user_id)
    
    # Progress bar for free month
    progress = stats['paid_referrals'] % 3
    progress_bar = "🟢" * progress + "⚪" * (3 - progress)
    
    text = f"""
📊 *Referral Statistics*

👥 *Referral Overview:*
• Join ဝင်လာသူ: {stats['total_referred']} ယောက်
• Key ဝယ်ပြီးသူ: {stats['paid_referrals']} ယောက်

🎁 *Rewards Earned:*
• Bonus Days: {stats['bonus_days']} ရက်
• Free Months: {stats['claimed_free_months']} ကြိမ်

📈 *Progress to Free Month:*
{progress_bar} ({progress}/3)
{f'🎉 ရယူနိုင်ပါပြီ!' if stats['can_claim_free_month'] else f'{3 - progress} ယောက် လိုပါသေးသည်'}

💡 *Tips:*
• Social media မှာ Share ပါ
• Group တွေမှာ Recommend ပါ
• Review ကောင်းကောင်း ပေးပါ
"""
    
    markup = types.InlineKeyboardMarkup()
    if stats['can_claim_free_month']:
        markup.add(types.InlineKeyboardButton("🎁 1 Month Free Key ရယူမည်", callback_data="claim_free_month"))
    markup.add(types.InlineKeyboardButton("🔙 Back", callback_data="referral"))
    
    bot.edit_message_text(
        text,
        call.message.chat.id,
        call.message.message_id,
        parse_mode='Markdown',
        reply_markup=markup
    )

def claim_referral_reward(call):
    """Claim free month reward - Send to Payment Channel for Admin Approval"""
    user_id = call.from_user.id
    
    # Check eligibility first (without claiming yet)
    stats = get_referral_stats(user_id)
    
    # Only proceed if user has 3 paid referrals
    if stats['can_claim_free_month']:
        # Send to Payment Channel for Admin approval
        try:
            user = get_user(user_id)
            username = user[2] if user and user[2] else f"User_{user_id}"
            username_display = username.replace("_", "\\_") if username else f"User\\_{user_id}"
            
            # Get detailed referral list
            referred_users = get_referred_users_details(user_id)
            
            # Build referred users list
            referred_list = ""
            paid_count = 0
            for i, ref in enumerate(referred_users, 1):
                ref_username = ref['username'] or ref['first_name'] or f"User_{ref['user_id']}"
                ref_username_display = ref_username.replace("_", "\\_") if ref_username else f"User\\_{ref['user_id']}"
                
                if ref['is_paid']:
                    paid_count += 1
                    # Get plan name
                    plan_name = PLANS.get(ref['plan_id'], {}).get('name', ref['plan_id'] or 'Unknown')
                    amount = ref['amount'] or 0
                    paid_date = ref['paid_at'][:10] if ref['paid_at'] else 'N/A'
                    referred_list += f"  ✅ {paid_count}. @{ref_username_display}\n"
                    referred_list += f"      └ Order #{ref['order_id']}: {plan_name} ({amount:,} Ks) - {paid_date}\n"
                else:
                    referred_list += f"  ⏳ @{ref_username_display} _(မဝယ်ရသေး)_\n"
            
            if not referred_list:
                referred_list = "  _(Referral မရှိသေးပါ)_"
            
            admin_text = f"""🎁 *Referral Free Key Request*

👤 *User:* @{username_display}
🆔 *User ID:* `{user_id}`

📊 *Referral Stats:*
• စုစုပေါင်း Refer: {stats['total_referred']} ယောက်
• ဝယ်ယူပြီးသူ: {stats['paid_referrals']} ယောက်
• Claimed Free Keys: {stats['claimed_free_months']} ကြိမ်

👥 *Referred Users & Orders:*
{referred_list}
🎁 *Request:* 1 Month Free Key (1 Device)

✅ Approve နှိပ်ရင် Key အလိုအလျောက် ဖန်တီးပေးပါမည်။"""
            
            # Create approve/reject keyboard
            markup = types.InlineKeyboardMarkup(row_width=2)
            markup.add(
                types.InlineKeyboardButton("✅ Approve", callback_data=f"approve_freekey_{user_id}"),
                types.InlineKeyboardButton("❌ Reject", callback_data=f"reject_freekey_{user_id}")
            )
            
            bot.send_message(
                PAYMENT_CHANNEL_ID,
                admin_text,
                parse_mode='Markdown',
                reply_markup=markup
            )
        except Exception as e:
            logger.error(f"Error sending free key request to channel: {e}")
        
        text = """
🎉 *Request Sent!*

သင့် 1 Month Free Key request ကို Admin ထံ ပို့လိုက်ပါပြီ!

⏳ Admin Approve ပြီးတာနဲ့ Key အလိုအလျောက် ရရှိမှာပါ။
ခဏစောင့်ပါ။

🙏 Referral အတွက် ကျေးဇူးတင်ပါသည်!
"""
    else:
        text = """
❌ *ရယူ၍မရပါ*

Free Month ရယူရန် Referral 3 ယောက် ဝယ်ပြီးမှသာ ရနိုင်ပါသည်။

📌 သင်ဆက်လက် Refer လုပ်နိုင်ပါသည်!
"""
    
    markup = types.InlineKeyboardMarkup()
    markup.add(types.InlineKeyboardButton("🔙 Back", callback_data="referral"))
    
    bot.edit_message_text(
        text,
        call.message.chat.id,
        call.message.message_id,
        parse_mode='Markdown',
        reply_markup=markup
    )

def process_referral_on_purchase(buyer_id, order_id):
    """Process referral reward when a purchase is made"""
    referrer_id = mark_referral_paid(buyer_id, order_id)
    
    if referrer_id:
        # Get stats
        stats = get_referral_stats(referrer_id)
        
        # Auto-extend referrer's active keys by 5 days
        extended_keys = []
        active_keys = get_user_active_keys(referrer_id)
        
        for key in active_keys:
            key_id, server_id, client_id, expiry_date = key
            server = SERVERS.get(server_id, {})
            panel_type = server.get('panel_type', 'xui')
            
            try:
                if panel_type == 'hiddify' and client_id:
                    # Extend on Hiddify panel
                    from hiddify_api import HiddifyApi
                    api = HiddifyApi(server_id)
                    new_expiry = api.extend_user_expiry(client_id, 5)
                    if new_expiry:
                        extend_key_expiry(key_id, 5)
                        extended_keys.append((server['name'], new_expiry))
                else:
                    # Just extend in database for XUI (manual extend on panel needed)
                    new_expiry = extend_key_expiry(key_id, 5)
                    if new_expiry:
                        extended_keys.append((server['name'], new_expiry))
            except Exception as e:
                logger.error(f"Error extending key {key_id}: {e}")
        
        # Notify referrer about +5 Days bonus
        try:
            if stats['can_claim_free_month']:
                bonus_msg = "🎉 **3 ယောက်ပြည့်သွားပါပြီ! 1 Month Free Key ရယူနိုင်ပါပြီ!**"
            else:
                remaining = 3 - (stats['paid_referrals'] % 3)
                bonus_msg = f"📈 1 Month Free Key ရဖို့ {remaining} ယောက် လိုပါသေးသည်။"
            
            # Build extended keys info
            if extended_keys:
                extend_info = "\n\n✅ *သင့် Key များ သက်တမ်းတိုးပြီးပါပြီ:*\n"
                for server_name, new_exp in extended_keys:
                    extend_info += f"• {server_name}: {new_exp.strftime('%Y-%m-%d')}\n"
            else:
                extend_info = "\n\n_(Active Key မရှိသဖြင့် Bonus Days သိမ်းဆည်းထားပါသည်)_"
            
            # Create reply keyboard (menu buttons) for referral reward
            reward_kb = types.ReplyKeyboardMarkup(row_width=2, resize_keyboard=True, one_time_keyboard=True)
            if stats['can_claim_free_month']:
                reward_kb.add(types.KeyboardButton("🎁 Free Key ရယူမည်"))
            reward_kb.add(
                types.KeyboardButton("📊 My Referrals"),
                types.KeyboardButton("🔗 Share Link")
            )
            reward_kb.add(
                types.KeyboardButton("🔑 My Keys"),
                types.KeyboardButton("🏠 Main Menu")
            )
            
            bot.send_message(
                referrer_id,
                f"🎉 *Referral Reward!*\n\n"
                f"သင် Refer လုပ်ထားသူ Key ဝယ်သွားပါပြီ!\n\n"
                f"🎁 **+5 Days** သက်တမ်းတိုးပြီးပါပြီ!{extend_info}\n"
                f"{bonus_msg}",
                parse_mode='Markdown',
                reply_markup=reward_kb
            )
        except Exception as e:
            logger.error(f"Error notifying referrer: {e}")


# ===================== AUTO-APPROVE FUNCTIONS =====================

def setup_auto_approve_timer(order_id, customer_id, server_id, plan_id, admin_message_id, ocr_amount):
    """Setup timer for auto-approve after 5 minutes"""
    global pending_auto_approvals
    
    # Cancel existing timer if any
    if order_id in pending_auto_approvals:
        existing = pending_auto_approvals[order_id]
        if existing.get('timer'):
            existing['timer'].cancel()
    
    # Store approval data
    approval_data = {
        'order_id': order_id,
        'customer_id': customer_id,
        'server_id': server_id,
        'plan_id': plan_id,
        'admin_message_id': admin_message_id,
        'ocr_amount': ocr_amount,
        'created_at': datetime.now()
    }
    
    # Create timer
    timer = threading.Timer(AUTO_APPROVE_TIMEOUT, auto_approve_order, args=[order_id])
    timer.start()
    
    approval_data['timer'] = timer
    pending_auto_approvals[order_id] = approval_data
    
    logger.info(f"⏱️ Auto-approve timer set for order #{order_id} (5 minutes)")


def auto_approve_order(order_id):
    """Auto-approve order after timeout"""
    global pending_auto_approvals
    
    if order_id not in pending_auto_approvals:
        logger.info(f"Order #{order_id} already processed, skipping auto-approve")
        return
    
    approval_data = pending_auto_approvals.pop(order_id)
    
    try:
        # Get order details
        order = get_order(order_id)
        if not order:
            logger.error(f"Order #{order_id} not found for auto-approve")
            return
        
        # Check if already approved
        if order[6] != 'pending':  # status column
            logger.info(f"Order #{order_id} already processed (status: {order[6]})")
            return
        
        customer_id = approval_data['customer_id']
        server_id = approval_data['server_id']
        plan_id = approval_data['plan_id']
        plan = PLANS.get(plan_id)
        protocol = order[5] if len(order) > 5 else 'trojan'
        
        # Get customer info
        customer = get_user(customer_id)
        customer_username = customer[2] if customer and customer[2] else f"User_{customer_id}"
        
        # Get key count
        existing_keys = get_user_keys(customer_id)
        key_number = len(existing_keys) + 1
        
        logger.info(f"🤖 Auto-approving order #{order_id} for user {customer_id}")
        
        # Create VPN key
        result = create_vpn_key(
            server_id=server_id,
            telegram_id=customer_id,
            username=customer_username,
            data_limit_gb=plan['data_limit'],
            expiry_days=plan['expiry_days'],
            devices=plan['devices'],
            protocol=protocol,
            key_number=key_number
        )
        
        if result and result.get('success'):
            # Mark as approved (auto)
            approve_order(order_id, 0)  # 0 = auto-approved
            
            config_link = result.get('config_link', result['sub_link'])
            save_vpn_key(
                telegram_id=customer_id,
                order_id=order_id,
                server_id=server_id,
                client_email=result['client_email'],
                client_id=result['client_id'],
                sub_link=result['sub_link'],
                config_link=config_link,
                data_limit=plan['data_limit'],
                expiry_date=result['expiry_date']
            )
            
            # Notify customer
            expiry_str = result['expiry_date'].strftime('%Y-%m-%d %H:%M')
            data_limit_str = "Unlimited" if plan['data_limit'] == 0 else f"{plan['data_limit']} GB"
            
            customer_message = f"""
🤖 *Auto-Approved!*

✅ သင့် VPN Key ဖန်တီးပြီးပါပြီ!

🖥️ *Server:* {SERVERS[server_id]['name']}
📦 *Plan:* {plan['name']}
📅 *Expiry:* {expiry_str}
📊 *Data Limit:* {data_limit_str}

🔑 *Your VPN Key (Copy လုပ်ပါ):*
```
{config_link}
```

📲 *Subscription Link:*
{result['sub_link']}

📖 *V2rayNG/Nekobox မှာ ထည့်နည်း:*
1. အထက်က Key ကို Long Press လုပ်ပြီး Copy လုပ်ပါ
2. App ဖွင့်ပြီး + ကိုနှိပ်ပါ
3. "Import config from clipboard" ရွေးပါ
4. Connect နှိပ်ပါ
"""
            
            markup = types.InlineKeyboardMarkup(row_width=2)
            markup.add(
                types.InlineKeyboardButton("🛒 Key ထပ်ဝယ်ရန်", callback_data="buy_key"),
                types.InlineKeyboardButton("📞 Admin ဆက်သွယ်ရန်", url="https://t.me/BDS_Admin")
            )
            markup.add(types.InlineKeyboardButton("🏠 Main Menu", callback_data="main_menu"))
            
            bot.send_message(customer_id, customer_message, reply_markup=markup, disable_web_page_preview=True)
            
            # Process referral reward
            process_referral_on_purchase(customer_id, order_id)
            
            # Update admin message with full order details
            try:
                # Escape underscores for Markdown
                safe_username = str(customer_username).replace('_', '\\_')
                safe_client_email = str(result['client_email']).replace('_', '\\_')
                expiry_str = result['expiry_date'].strftime('%Y-%m-%d %H:%M')
                data_limit_str = "Unlimited" if plan['data_limit'] == 0 else f"{plan['data_limit']} GB"
                
                bot.edit_message_caption(
                    caption=f"🤖 *AUTO-APPROVED* Order #{order_id}\n\n"
                            f"👤 User: @{safe_username} (`{customer_id}`)\n"
                            f"🖥️ Server: {SERVERS[server_id]['name']}\n"
                            f"📦 Plan: {plan['name']}\n"
                            f"💰 Amount: {approval_data['ocr_amount']:,} Ks\n"
                            f"📅 Expiry: {expiry_str}\n"
                            f"📊 Data: {data_limit_str}\n"
                            f"🔑 Key: `{safe_client_email}`\n\n"
                            f"✅ OCR Verified & Key sent to user",
                    chat_id=PAYMENT_CHANNEL_ID,
                    message_id=approval_data['admin_message_id'],
                    parse_mode='Markdown'
                )
            except Exception as e:
                logger.error(f"Error updating admin message: {e}")
            
            # Log auto-approval for admin review
            log_auto_approval(order_id, customer_id, approval_data['ocr_amount'], result)
            
            logger.info(f"✅ Order #{order_id} auto-approved successfully")
            
        else:
            # Check if it's a duplicate key error (key already exists)
            error_msg = result.get('error', '') if result else ''
            if 'Duplicate' in error_msg or 'duplicate' in error_msg:
                logger.warning(f"⚠️ Duplicate key detected for order #{order_id}, marking as approved")
                # Key already exists - mark order as approved
                approve_order(order_id, 0)
                
                # Update admin message to show it was already processed
                try:
                    safe_username = str(customer_username).replace('_', '\\_')
                    bot.edit_message_caption(
                        caption=f"🤖 *AUTO-APPROVED* Order #{order_id}\n\n"
                                f"✅ Key already exists for @{safe_username} ({customer_id})\n"
                                f"💰 Amount: {approval_data['ocr_amount']:,} Ks (OCR verified)\n\n"
                                f"_Key was created earlier_",
                        chat_id=PAYMENT_CHANNEL_ID,
                        message_id=approval_data['admin_message_id'],
                        parse_mode='Markdown'
                    )
                except Exception as e:
                    logger.error(f"Error updating admin message for duplicate: {e}")
                
                logger.info(f"✅ Order #{order_id} marked as approved (duplicate key)")
            else:
                logger.error(f"❌ Failed to create key for auto-approve order #{order_id}")
                # Notify admin about failure
                try:
                    bot.send_message(
                        ADMIN_CHAT_ID,
                        f"⚠️ Auto-approve failed for order #{order_id}\n"
                        f"User: {customer_id}\n"
                        f"Error: {error_msg}\n"
                        f"Please review manually."
                    )
                except:
                    pass
                
    except Exception as e:
        logger.error(f"Auto-approve error for order #{order_id}: {e}")
        import traceback
        traceback.print_exc()


def cancel_auto_approve(order_id):
    """Cancel auto-approve timer (called when admin manually approves/rejects)"""
    global pending_auto_approvals
    
    if order_id in pending_auto_approvals:
        approval_data = pending_auto_approvals.pop(order_id)
        if approval_data.get('timer'):
            approval_data['timer'].cancel()
            logger.info(f"⏱️ Auto-approve timer cancelled for order #{order_id}")


def log_auto_approval(order_id, customer_id, ocr_amount, result):
    """Log auto-approval to security events only (no admin message)"""
    try:
        # Log to security events for database record
        log_security_event(
            'AUTO_APPROVE',
            f"Order #{order_id} auto-approved for user {customer_id}, amount: {ocr_amount} Ks, key: {result.get('client_email')}"
        )
        # Note: Payment Channel message is already updated in auto_approve_order()
        # No need to send separate admin message
        
    except Exception as e:
        logger.error(f"Error logging auto-approval: {e}")


# ===================== AUTO BACKUP SYSTEM =====================

# Yangon timezone
YANGON_TZ = pytz.timezone('Asia/Yangon')
backup_timer = None

def create_backup():
    """Create a backup of the database file"""
    try:
        yangon_now = datetime.now(YANGON_TZ)
        backup_filename = f"vpn_bot_backup_{yangon_now.strftime('%Y%m%d_%H%M%S')}.db"
        backup_path = os.path.join(os.path.dirname(DATABASE_PATH), backup_filename)
        
        # Copy database file
        shutil.copy2(DATABASE_PATH, backup_path)
        
        logger.info(f"📦 Backup created: {backup_filename}")
        return backup_path, backup_filename
    except Exception as e:
        logger.error(f"Backup creation failed: {e}")
        return None, None

def send_backup_to_channel():
    """Send backup file to payment channel"""
    try:
        backup_path, backup_filename = create_backup()
        
        if not backup_path:
            logger.error("Failed to create backup")
            return False
        
        yangon_now = datetime.now(YANGON_TZ)
        
        # Get statistics for the backup message
        stats = get_statistics('all')
        
        caption = f"""🔒 *Daily Database Backup*

📅 Date: {yangon_now.strftime('%Y-%m-%d')}
⏰ Time: {yangon_now.strftime('%H:%M:%S')} (Myanmar Time)

📊 *Database Statistics:*
👥 Total Users: {stats['total_users']:,}
🛒 Total Orders: {stats['total_orders']:,}
✅ Completed: {stats['completed_orders']:,}
💰 Total Revenue: {stats['total_revenue']:,} Ks
🔑 Active Keys: {stats['active_keys']:,}

_Auto-backup by VPN Bot System_"""
        
        # Send backup file to payment channel
        with open(backup_path, 'rb') as backup_file:
            bot.send_document(
                PAYMENT_CHANNEL_ID,
                backup_file,
                caption=caption,
                parse_mode='Markdown'
            )
        
        logger.info(f"✅ Backup sent to payment channel: {backup_filename}")
        
        # Clean up backup file after sending
        try:
            os.remove(backup_path)
            logger.info(f"🗑️ Backup file cleaned up: {backup_filename}")
        except:
            pass
        
        return True
    except Exception as e:
        logger.error(f"Failed to send backup: {e}")
        return False

def schedule_next_backup():
    """Schedule the next midnight backup"""
    global backup_timer
    
    # Get current time in Yangon
    yangon_now = datetime.now(YANGON_TZ)
    
    # Calculate next midnight
    next_midnight = yangon_now.replace(hour=0, minute=0, second=0, microsecond=0)
    if yangon_now >= next_midnight:
        next_midnight += timedelta(days=1)
    
    # Calculate seconds until next midnight
    seconds_until_midnight = (next_midnight - yangon_now).total_seconds()
    
    logger.info(f"⏰ Next backup scheduled in {seconds_until_midnight/3600:.1f} hours ({next_midnight.strftime('%Y-%m-%d %H:%M')} MMT)")
    
    # Cancel existing timer if any
    if backup_timer:
        backup_timer.cancel()
    
    # Schedule backup
    backup_timer = threading.Timer(seconds_until_midnight, run_midnight_backup)
    backup_timer.daemon = True
    backup_timer.start()

def run_midnight_backup():
    """Run midnight backup and schedule next one"""
    logger.info("🌙 Midnight backup starting...")
    
    # Send backup
    success = send_backup_to_channel()
    
    if success:
        logger.info("✅ Midnight backup completed successfully")
    else:
        logger.error("❌ Midnight backup failed")
        # Notify admin
        try:
            bot.send_message(
                ADMIN_CHAT_ID,
                "⚠️ *Backup Failed*\n\n"
                "Midnight auto-backup failed. Please check the logs.",
                parse_mode='Markdown'
            )
        except:
            pass
    
    # Schedule next backup
    schedule_next_backup()

def manual_backup():
    """Trigger manual backup (admin command)"""
    return send_backup_to_channel()


def main():
    """Main function to run the bot"""
    # Initialize database
    init_db()
    
    # Load servers from config + database
    load_servers()
    
    # Load feature flags from database
    load_feature_flags()
    
    # Setup DDoS auto-block callback to database
    def db_ban_wrapper(user_id, reason, hours):
        """Wrapper to ban user in database"""
        try:
            ban_user(user_id, reason=reason, duration_hours=hours, banned_by=0)  # 0 = system
            logger.info(f"🔒 DDoS auto-block: User {user_id} banned in database for {hours}h - {reason}")
        except Exception as e:
            logger.error(f"Failed to persist DDoS ban: {e}")
    
    rate_limiter.set_db_ban_callback(db_ban_wrapper)
    
    # Security initialization
    print("🔒 Security features enabled:")
    print("   ├ Rate limiting: ✅")
    print("   ├ Input validation: ✅")
    print("   ├ Callback validation: ✅")
    print("   ├ Abuse detection: ✅")
    print("   └ DDoS Auto-Block: ✅")
    
    # Feature flags status
    print("📋 Feature Flags:")
    for flag_name, is_enabled in feature_flags.items():
        status = "✅" if is_enabled else "❌"
        print(f"   ├ {flag_name}: {status}")
    
    # OCR and Auto-approve status
    if OCR_ENABLED:
        print("🤖 OCR Payment Verification: ✅")
    else:
        print("🤖 OCR Payment Verification: ❌")
    
    if AUTO_APPROVE_ENABLED:
        print(f"⏱️ Auto-Approve: ✅ ({AUTO_APPROVE_TIMEOUT} seconds timeout)")
    else:
        print("⏱️ Auto-Approve: ❌")
    
    # Start auto backup scheduler
    print("📦 Auto Backup: ✅ (Daily at 00:00 MMT)")
    schedule_next_backup()
    
    # Start the bot
    print("🚀 VPN Seller Bot started!")
    print(f"📱 Bot: @{bot.get_me().username}")
    print("Press Ctrl+C to stop")
    
    # Start polling
    bot.infinity_polling(skip_pending=True)

if __name__ == '__main__':
    main()