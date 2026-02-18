# ===========================================
# VPN Seller Bot Configuration
# ===========================================

import os
from pathlib import Path

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    env_path = Path(__file__).parent / '.env'
    if env_path.exists():
        load_dotenv(env_path)
        print("✅ Loaded configuration from .env file")
except ImportError:
    print("⚠️ python-dotenv not installed. Using system environment variables.")

# Telegram Bot Settings (from environment variables)
BOT_TOKEN = os.environ.get('BOT_TOKEN', '')
ADMIN_CHAT_ID = int(os.environ.get('ADMIN_CHAT_ID', '0'))
PAYMENT_CHANNEL_ID = int(os.environ.get('PAYMENT_CHANNEL_ID', '0'))

# 3x-ui Panel Credentials (from environment variables)
XUI_USERNAME = os.environ.get('XUI_USERNAME', '')
XUI_PASSWORD = os.environ.get('XUI_PASSWORD', '')

# Validate required credentials
if not BOT_TOKEN:
    raise ValueError("❌ BOT_TOKEN is required! Set it in .env file.")
if not ADMIN_CHAT_ID:
    raise ValueError("❌ ADMIN_CHAT_ID is required! Set it in .env file.")
if not XUI_USERNAME or not XUI_PASSWORD:
    print("⚠️ Warning: XUI credentials not set. XUI panel features will be disabled.")

# Server List
SERVERS = {
    "sg1": {
        "name": "🇸🇬 Singapore 1",
        "url": "https://jan.burmesedigital.store:8080",
        "panel_path": "/mka",
        "domain": "jan.burmesedigital.store",
        "sub_port": 2096,
        "panel_type": "xui",
        "trojan_port": 22716  # Custom port for Trojan protocol
    },
    "sg2": {
        "name": "🇸🇬 Singapore 2", 
        "url": "https://sg2.burmesedigital.store:8080",
        "panel_path": "/mka",
        "domain": "sg2.burmesedigital.store",
        "sub_port": 2096,
        "panel_type": "xui"
    },
    "sg3": {
        "name": "🇸🇬 Singapore 3",
        "url": "https://sg3.burmesedigital.store:8080",
        "panel_path": "/mka",
        "domain": "sg3.burmesedigital.store",
        "sub_port": 2096,
        "panel_type": "xui"
    },
    "us1": {
        "name": "🇺🇸 US United States 1",
        "url": "https://us.burmesedigital.store:8080",
        "panel_path": "/mka",
        "domain": "us.burmesedigital.store",
        "sub_port": 8080,
        "panel_type": "xui"
    },
}

# VPN Plans - Format: {devices}dev_{months}month
PLANS = {
    "free_test": {
        "name": "🎁 Free Test Key",
        "data_limit": 3,  # GB
        "expiry_days": 3,  # 72 hours
        "price": 0,
        "devices": 1
    },
    # 1 Device Plans (1 Month = 3000 Ks)
    "1dev_1month": {"name": "📱 1 Device - 1 Month", "data_limit": 0, "expiry_days": 30, "price": 3000, "devices": 1},
    "1dev_3month": {"name": "📱 1 Device - 3 Months", "data_limit": 0, "expiry_days": 90, "price": 8000, "devices": 1},
    "1dev_5month": {"name": "📱 1 Device - 5 Months", "data_limit": 0, "expiry_days": 150, "price": 13000, "devices": 1},
    "1dev_7month": {"name": "📱 1 Device - 7 Months", "data_limit": 0, "expiry_days": 210, "price": 18000, "devices": 1},
    "1dev_9month": {"name": "📱 1 Device - 9 Months", "data_limit": 0, "expiry_days": 270, "price": 23000, "devices": 1},
    "1dev_12month": {"name": "📱 1 Device - 12 Months", "data_limit": 0, "expiry_days": 365, "price": 30000, "devices": 1},
    # 2 Devices Plans (1 Month = 4000 Ks)
    "2dev_1month": {"name": "📱 2 Devices - 1 Month", "data_limit": 0, "expiry_days": 30, "price": 4000, "devices": 2},
    "2dev_3month": {"name": "📱 2 Devices - 3 Months", "data_limit": 0, "expiry_days": 90, "price": 10000, "devices": 2},
    "2dev_5month": {"name": "📱 2 Devices - 5 Months", "data_limit": 0, "expiry_days": 150, "price": 17000, "devices": 2},
    "2dev_7month": {"name": "📱 2 Devices - 7 Months", "data_limit": 0, "expiry_days": 210, "price": 24000, "devices": 2},
    "2dev_9month": {"name": "📱 2 Devices - 9 Months", "data_limit": 0, "expiry_days": 270, "price": 30000, "devices": 2},
    "2dev_12month": {"name": "📱 2 Devices - 12 Months", "data_limit": 0, "expiry_days": 365, "price": 40000, "devices": 2},
    # 3 Devices Plans (1 Month = 5000 Ks)
    "3dev_1month": {"name": "📱 3 Devices - 1 Month", "data_limit": 0, "expiry_days": 30, "price": 5000, "devices": 3},
    "3dev_3month": {"name": "📱 3 Devices - 3 Months", "data_limit": 0, "expiry_days": 90, "price": 13000, "devices": 3},
    "3dev_5month": {"name": "📱 3 Devices - 5 Months", "data_limit": 0, "expiry_days": 150, "price": 21000, "devices": 3},
    "3dev_7month": {"name": "📱 3 Devices - 7 Months", "data_limit": 0, "expiry_days": 210, "price": 29000, "devices": 3},
    "3dev_9month": {"name": "📱 3 Devices - 9 Months", "data_limit": 0, "expiry_days": 270, "price": 37000, "devices": 3},
    "3dev_12month": {"name": "📱 3 Devices - 12 Months", "data_limit": 0, "expiry_days": 365, "price": 50000, "devices": 3},
    # 4 Devices Plans (1 Month = 6000 Ks)
    "4dev_1month": {"name": "📱 4 Devices - 1 Month", "data_limit": 0, "expiry_days": 30, "price": 6000, "devices": 4},
    "4dev_3month": {"name": "📱 4 Devices - 3 Months", "data_limit": 0, "expiry_days": 90, "price": 16000, "devices": 4},
    "4dev_5month": {"name": "📱 4 Devices - 5 Months", "data_limit": 0, "expiry_days": 150, "price": 25000, "devices": 4},
    "4dev_7month": {"name": "📱 4 Devices - 7 Months", "data_limit": 0, "expiry_days": 210, "price": 35000, "devices": 4},
    "4dev_9month": {"name": "📱 4 Devices - 9 Months", "data_limit": 0, "expiry_days": 270, "price": 45000, "devices": 4},
    "4dev_12month": {"name": "📱 4 Devices - 12 Months", "data_limit": 0, "expiry_days": 365, "price": 60000, "devices": 4},
    # 5 Devices Plans (1 Month = 7000 Ks)
    "5dev_1month": {"name": "📱 5 Devices - 1 Month", "data_limit": 0, "expiry_days": 30, "price": 7000, "devices": 5},
    "5dev_3month": {"name": "📱 5 Devices - 3 Months", "data_limit": 0, "expiry_days": 90, "price": 18000, "devices": 5},
    "5dev_5month": {"name": "📱 5 Devices - 5 Months", "data_limit": 0, "expiry_days": 150, "price": 30000, "devices": 5},
    "5dev_7month": {"name": "📱 5 Devices - 7 Months", "data_limit": 0, "expiry_days": 210, "price": 40000, "devices": 5},
    "5dev_9month": {"name": "📱 5 Devices - 9 Months", "data_limit": 0, "expiry_days": 270, "price": 52000, "devices": 5},
    "5dev_12month": {"name": "📱 5 Devices - 12 Months", "data_limit": 0, "expiry_days": 365, "price": 70000, "devices": 5},
}

# Payment Information
PAYMENT_INFO = {
    "name": "Myo Ko Aung",
    "phone": "09950569539",
    "methods": ["KBZPay", "WavePay", "AYA Pay", "UAB Pay"]
}

# Database (from environment variables)
DATABASE_PATH = os.environ.get('DATABASE_PATH', 'vpn_bot.db')

# Bot Messages (Burmese)
MESSAGES = {
    "welcome": """
🌟 *Burmese Digital Store VPN Bot* မှ ကြိုဆိုပါတယ်!

✨ မြန်ဆန်သော Singapore Servers
✨ Unlimited Data Plans
✨ Auto Key Generation
✨ 24/7 Service

အောက်ပါ Menu မှ ရွေးချယ်ပါ 👇
""",
    
    "select_server": """
🖥️ *Server ရွေးချယ်ပါ*

သင့်အတွက် သင့်တော်သော Server ကို ရွေးပါ:
""",
    
    "select_plan": """
📦 *Plan ရွေးချယ်ပါ*

*🎁 Free Test Key*
└ Data: 3GB | Duration: 72 Hours

*💎 Paid Plans (Unlimited Data)*
├ 1-5 Devices ရွေးချယ်နိုင်
└ 1, 3, 5, 7, 9, 12 Months ရွေးချယ်နိုင်

_ကာလ ကြာကြာ ဝယ်လေ စျေးသက်သာလေ_ 💰
""",
    
    "payment_info": """
💳 *ငွေလွှဲရန် အချက်အလက်*

📛 *Name:* `Myo Ko Aung`
📱 *Phone:* `09950569539`
💰 *Amount:* `{amount} Ks`

*Payment Methods:*
├ KBZPay ✅
├ WavePay ✅
├ AYA Pay ✅
└ UAB Pay ✅

⚠️ *အရေးကြီး သတိပေးချက်*
ငွေလွှဲသည့်အခါ မှတ်ချက် (Note) တွင် "VPN" နှင့် သက်ဆိုင်သော စာသားများ *လုံးဝ မရေးပါနဲ့*!

✅ ငွေလွှဲပြီးပါက Screenshot ပို့ပေးပါ။
""",
    
    "free_key_limit": "⚠️ သင် Free Test Key ကို တစ်ကြိမ် ရယူပြီးပါပြီ။",
    
    "key_generated": """
✅ *သင့် VPN Key အောင်မြင်စွာ ဖန်တီးပြီးပါပြီ!*

🖥️ *Server:* {server}
📦 *Plan:* {plan}
📅 *Expiry:* {expiry}
📊 *Data Limit:* {data_limit}

🔑 *Your VPN Key (Copy လုပ်ပါ):*
```
{config_link}
```

📱 *V2rayNG/Nekobox မှာ ထည့်နည်း:*
1. အထက်က Key ကို Long Press လုပ်ပြီး Copy လုပ်ပါ
2. App ဖွင့်ပြီး + ကိုနှိပ်ပါ  
3. "Import config from clipboard" ရွေးပါ
4. Connect နှိပ်ပါ

🔗 [Key အသေးစိတ်ကြည့်ရန်]({sub_link})
""",
    
    "admin_new_order": """
🛒 *Order အသစ်*

👤 *User:* {user}
🆔 *User ID:* `{user_id}`
🖥️ *Server:* {server}
📦 *Plan:* {plan}
💰 *Amount:* {amount} Ks

📸 Payment Screenshot အောက်တွင်...
""",
    
    "order_approved": "✅ သင့် Order အတည်ပြုပြီးပါပြီ! VPN Key ကို ခဏစောင့်ပါ...",
    
    "order_rejected": "❌ သင့် Order ပယ်ချခံရပါသည်။ ပြဿနာရှိပါက Admin ကို ဆက်သွယ်ပါ။"
}
