import telebot
from telebot import types
import logging
import re
import json
from datetime import datetime, timedelta
from config import BOT_TOKEN, ADMIN_CHAT_ID, PAYMENT_CHANNEL_ID, SERVERS, PLANS, PAYMENT_INFO, MESSAGES
from database import (
    init_db, create_user, get_user, has_used_free_test, mark_free_test_used,
    create_order, update_order_screenshot, approve_order, reject_order,
    get_order, save_vpn_key, get_user_keys, get_vpn_key_by_id, update_vpn_key,
    get_sales_stats, get_all_orders, get_expiring_keys, get_all_users,
    deactivate_vpn_key, ban_user, unban_user, is_user_banned_db, log_security_event
)
from xui_api import create_vpn_key, get_available_protocols, delete_vpn_client, verify_client_exists
from security import (
    rate_limiter, InputValidator, is_valid_callback, SecurityLogger,
    abuse_detector, VALID_CALLBACK_PREFIXES
)

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

# Banned users set
banned_users = set()

# ===================== SECURITY HELPERS =====================

def check_rate_limit(user_id: int, action_type: str = 'message') -> tuple:
    """Check rate limit and return (is_allowed, error_message)"""
    return rate_limiter.check_rate_limit(user_id, action_type)

def is_user_banned(user_id: int) -> bool:
    """Check if user is banned (runtime or database)"""
    return user_id in banned_users or rate_limiter.is_banned(user_id) or is_user_banned_db(user_id)

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
        types.InlineKeyboardButton("📖 Help", callback_data="help"),
        types.InlineKeyboardButton("📞 Contact", url="https://t.me/BDS_Admin")
    )
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
        types.InlineKeyboardButton("📋 Pending Orders", callback_data="admin_pending"),
        types.InlineKeyboardButton("👥 All Users", callback_data="admin_users"),
        types.InlineKeyboardButton("🔔 Send Broadcast", callback_data="admin_broadcast"),
        types.InlineKeyboardButton("🖥️ Server Management", callback_data="admin_servers")
    )
    return markup

def server_management_keyboard():
    """Server management keyboard for admin"""
    markup = types.InlineKeyboardMarkup(row_width=1)
    for server_id, server in SERVERS.items():
        status = "🔴 Disabled" if server_id in disabled_servers else "🟢 Active"
        markup.add(types.InlineKeyboardButton(
            f"{server['name']} - {status}",
            callback_data=f"toggle_server_{server_id}"
        ))
    markup.add(types.InlineKeyboardButton("🔙 Back to Admin", callback_data="admin_back"))
    return markup

# ===================== HANDLERS =====================

@bot.message_handler(commands=['start'])
def start(message):
    """Start command handler"""
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
    
    create_user(user.id, user.username, user.first_name, user.last_name)
    
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

@bot.callback_query_handler(func=lambda call: True)
def button_callback(call):
    """Handle button callbacks"""
    user_id = call.from_user.id
    data = call.data
    
    # Security: Check if user is banned
    if is_user_banned(user_id):
        bot.answer_callback_query(call.id, "⚠️ You are temporarily blocked.", show_alert=True)
        return
    
    # Security: Rate limiting for callbacks
    allowed, error_msg = check_rate_limit(user_id, 'callback')
    if not allowed:
        bot.answer_callback_query(call.id, "⚠️ Too many requests. Please slow down.", show_alert=True)
        return
    
    # Security: Validate callback data
    if not is_valid_callback(data):
        SecurityLogger.log_suspicious_activity(user_id, "INVALID_CALLBACK", data[:100])
        abuse_detector.record_suspicious_activity(user_id, 2)
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
    
    # Free server selection - now goes to protocol selection
    elif data.startswith("free_server_"):
        server_id = data.replace("free_server_", "")
        
        # Security: Validate server_id
        if not validate_server_id(server_id):
            SecurityLogger.log_suspicious_activity(user_id, "INVALID_SERVER_ID", server_id)
            bot.answer_callback_query(call.id, "❌ Invalid server.", show_alert=True)
            return
        
        user_sessions[user_id] = {'server_id': server_id, 'is_free': True}
        
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
    
    # Server selected for purchase - go to protocol selection
    elif data.startswith("server_") and not data.startswith("server_selection"):
        server_id = data.replace("server_", "")
        
        # Security: Validate server_id
        if not validate_server_id(server_id):
            SecurityLogger.log_suspicious_activity(user_id, "INVALID_SERVER_ID", server_id)
            bot.answer_callback_query(call.id, "❌ Invalid server.", show_alert=True)
            return
        
        user_sessions[user_id] = {'server_id': server_id}
        
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
            types.InlineKeyboardButton("📸 Screenshot ပို့မယ်", callback_data=f"send_screenshot_{order_id}"),
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
            "📸 *Payment Screenshot ပို့ပေးပါ*\n\nScreenshot ကို ဤနေရာတွင် ပို့ပေးပါ။",
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
                server_name = SERVERS.get(key[3], {}).get('name', 'Unknown')
                
                # Get expiry from panel (in milliseconds)
                client = client_info['client']
                inbound = client_info['inbound']
                panel_expiry_ms = client.get('expiryTime', 0)
                
                if panel_expiry_ms > 0:
                    panel_expiry = datetime.fromtimestamp(panel_expiry_ms / 1000)
                    expiry_str = panel_expiry.strftime('%Y-%m-%d %H:%M')
                    days_left = (panel_expiry - datetime.now()).days
                    expiry_display = f"{expiry_str} ({days_left} days left)"
                else:
                    expiry_display = "Unlimited"
                
                # Get protocol and generate config link
                protocol = inbound.get('protocol', 'trojan')
                port = inbound.get('port', 443)
                server_domain = SERVERS.get(key[3], {}).get('domain', '')
                
                # Generate config link based on protocol
                if protocol == 'trojan':
                    client_uuid = client.get('password')
                    config_link = f"trojan://{client_uuid}@{server_domain}:{port}?security=none&type=tcp#{client.get('email')}"
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
            
            bot.edit_message_caption(
                caption=f"✅ Order #{order_id} Approved!\n\nKey sent to @{customer_username} ({customer_id})",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id
            )
        else:
            bot.edit_message_caption(
                caption=f"❌ Failed to create key for Order #{order_id}",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id
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
        
        SecurityLogger.log_admin_action(user_id, "reject_order", f"order_id={order_id}")
        
        reject_order(order_id, user_id)
        
        # Notify customer
        bot.send_message(customer_id, MESSAGES['order_rejected'])
        
        bot.edit_message_caption(
            caption=f"❌ Order #{order_id} Rejected!",
            chat_id=call.message.chat.id,
            message_id=call.message.message_id
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
        
        text = "🖥️ *Server Management*\n\n"
        text += "Server ကို နှိပ်ပြီး Enable/Disable လုပ်နိုင်ပါတယ်။\n\n"
        for server_id, server in SERVERS.items():
            status = "🔴 Disabled" if server_id in disabled_servers else "🟢 Active"
            text += f"• {server['name']} - {status}\n"
        
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
        text = "🖥️ *Server Management*\n\n"
        text += "Server ကို နှိပ်ပြီး Enable/Disable လုပ်နိုင်ပါတယ်။\n\n"
        for sid, server in SERVERS.items():
            status = "🔴 Disabled" if sid in disabled_servers else "🟢 Active"
            text += f"• {server['name']} - {status}\n"
        
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

@bot.message_handler(content_types=['photo'])
def handle_photo(message):
    """Handle payment screenshots"""
    user_id = message.from_user.id
    
    # Security: Check if user is banned
    if is_user_banned(user_id):
        return
    
    # Security: Rate limiting for screenshots
    allowed, error_msg = check_rate_limit(user_id, 'screenshot')
    if not allowed:
        bot.reply_to(message, error_msg)
        return
    
    if user_id not in user_sessions or not user_sessions[user_id].get('waiting_screenshot'):
        return
    
    session = user_sessions[user_id]
    order_id = session.get('order_id')
    
    if not order_id:
        bot.reply_to(message, "❌ No active order found.")
        return
    
    # Get photo file ID
    photo = message.photo[-1]  # Highest resolution
    file_id = photo.file_id
    
    # Update order with screenshot
    update_order_screenshot(order_id, file_id)
    
    # Get order details
    server_id = session.get('server_id')
    plan_id = session.get('plan_id')
    plan = PLANS.get(plan_id)
    
    # Clear session
    user_sessions[user_id]['waiting_screenshot'] = False
    
    # Notify user
    bot.reply_to(
        message,
        "✅ *Screenshot လက်ခံရရှိပါပြီ!*\n\nAdmin Approve ပြုလုပ်ပြီးသည်နှင့် VPN Key ကို ပေးပို့ပါမည်။\n\nကျေးဇူးပြု၍ စောင့်ဆိုင်းပေးပါ။"
    )
    
    # Notify admin
    user = message.from_user
    # Escape special characters in username for Markdown
    username_display = user.username if user.username else user.first_name
    # Security: Sanitize username
    username_display = sanitize_username(username_display)
    if username_display:
        username_display = username_display.replace("_", "\\_")
    
    admin_text = f"""🛒 *Order အသစ်*

👤 User: @{user.username if user.username else user.first_name}
🆔 User ID: {user_id}
🖥️ Server: {SERVERS.get(server_id, {}).get('name', 'Unknown')}
📦 Plan: {plan['name'] if plan else 'Unknown'}
💰 Amount: {session.get('amount', 0)} Ks

📸 Payment Screenshot အောက်တွင်..."""
    
    # Send to Payment Proof Channel with screenshot
    try:
        bot.send_photo(
            PAYMENT_CHANNEL_ID,
            file_id,
            caption=admin_text,
            reply_markup=admin_order_keyboard(order_id, user_id),
            parse_mode=None  # Disable Markdown to avoid parsing issues
        )
    except Exception as e:
        logger.error(f"Error sending to payment channel: {e}")
        # Try without markdown
        bot.send_photo(
            PAYMENT_CHANNEL_ID,
            file_id,
            caption=f"New Order from {user_id}",
            reply_markup=admin_order_keyboard(order_id, user_id)
        )

def main():
    """Main function to run the bot"""
    # Initialize database
    init_db()
    
    # Security initialization
    print("🔒 Security features enabled:")
    print("   ├ Rate limiting: ✅")
    print("   ├ Input validation: ✅")
    print("   ├ Callback validation: ✅")
    print("   └ Abuse detection: ✅")
    
    # Start the bot
    print("🚀 VPN Seller Bot started!")
    print(f"📱 Bot: @{bot.get_me().username}")
    print("Press Ctrl+C to stop")
    
    # Start polling
    bot.infinity_polling(skip_pending=True)

if __name__ == '__main__':
    main()

