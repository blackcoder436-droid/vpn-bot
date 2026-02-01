# Hiddify Panel Integration Guide
# Hiddify Panel ကို Bot နဲ့ ဘယ်လို ချိတ်ဆက်မလဲ

## 📋 အဆင့်ဆင့် လုပ်ဆောင်ရန်

### 1. Hiddify Panel မှ API Key ရယူခြင်း

1. Hiddify Panel သို့ Admin အဖြစ် Login ဝင်ပါ
2. Settings → API သို့ သွားပါ
3. API Key ကို Generate လုပ်ပြီး Copy ကူးယူပါ
4. Admin UUID ကိုလည်း မှတ်သားပါ (Admin User Details မှာ ရှိပါမယ်)

### 2. Bot Configuration ထဲ ထည့်သွင်းခြင်း

`.env` file ကို ဖွင့်ပြီး အောက်ပါ အချက်အလက်များ ထည့်ပါ:

```env
# Hiddify Panel Configuration
HIDDIFY_API_KEY=your_actual_api_key_here
HIDDIFY_ADMIN_UUID=your_actual_admin_uuid_here
```

### 3. Server Configuration (config.py)

`config.py` file ထဲမှာ Hiddify server အသစ် ထည့်ပါ:

```python
SERVERS = {
    # ... existing servers ...
    
    "hiddify1": {
        "name": "🌐 Hiddify Server 1",
        "url": "https://your-hiddify-domain.com",
        "panel_path": "your_proxy_path",  # ဥပမာ: SeS1TFUTYLdZXv7F
        "domain": "your-hiddify-domain.com",
        "panel_type": "hiddify",
        "api_key": HIDDIFY_API_KEY,
        "admin_uuid": HIDDIFY_ADMIN_UUID,
        "proxy_path": "your_proxy_path"
    }
}
```

### 4. Proxy Path ရှာခြင်း

Hiddify Panel URL ကို ကြည့်ပါ:
```
https://main.burmesedigital.store/SeS1TFUTYLdZXv7F/admin/
```

ဒီမှာ `SeS1TFUTYLdZXv7F` က proxy_path ဖြစ်ပါတယ်။

### 5. Bot ကို Run ခြင်း

```bash
python bot.py
```

## 🎯 အသုံးပြုပုံ

Bot က အလိုလို Hiddify နဲ့ XUI Panel နှစ်ခုစလုံး ကို ထောက်ပံ့ပေးပါတယ်။

### Free Test Key ရယူခြင်း
- `/start` ကို နှိပ်ပါ
- "🎁 Free Test Key" ကို ရွေးပါ
- Hiddify server ကို ရွေးပါ
- Key ကို လက်ခံရရှိမှာ ဖြစ်ပါတယ်

### VPN Key ဝယ်ယူခြင်း
- "💎 Buy VPN Key" ကို နှိပ်ပါ
- Plan ရွေးပါ
- Hiddify server ကို ရွေးပါ
- Payment လုပ်ပါ

## 🔧 Hiddify API Features

Bot က အောက်ပါ Hiddify features များကို ထောက်ပံ့ပါတယ်:

- ✅ User အသစ် ဖန်တီးခြင်း
- ✅ User ဖျက်ခြင်း
- ✅ User Update လုပ်ခြင်း
- ✅ Data Usage စစ်ဆေးခြင်း
- ✅ Multi-protocol support (VLESS, VMess, Trojan, Shadowsocks, Reality, Hysteria, TUIC, WireGuard)
- ✅ Connection limit (Max IPs)
- ✅ Data limit
- ✅ Expiry date
- ✅ Enable/Disable user

## 📊 Panel Type ခွဲခြားမှု

Bot က panel_type အရ အလိုလို ခွဲခြားပြီး အသုံးပြုပါတယ်:

- `panel_type: "xui"` → 3X-UI Panel API အသုံးပြုမယ်
- `panel_type: "hiddify"` → Hiddify Panel API အသုံးပြုမယ်

## 🔐 API Authentication

Hiddify က HTTP Header မှာ API Key အသုံးပြုပါတယ်:

```
Hiddify-API-Key: your_api_key_here
```

## 📝 Subscription Link Format

### XUI Panel
```
https://domain:port/sub/subscription_id
```

### Hiddify Panel
```
https://domain/proxy_path/user_uuid/
```

## ⚠️ အရေးကြီးသော မှတ်ချက်များ

1. **API Key လုံခြုံမှု**: `.env` file ကို Git မှာ commit မလုပ်ပါနဲ့
2. **Proxy Path**: သင့် Hiddify panel ရဲ့ proxy path ကို မှန်မှန်ကန်ကန် ထည့်ပါ
3. **SSL Certificate**: Production တွင် valid SSL certificate အသုံးပြုပါ
4. **Rate Limiting**: API calls များ သိပ်မပြန်ခေါ်အောင် သတိထားပါ
5. **Admin UUID**: မှန်ကန်သော Admin UUID ကို အသုံးပြုရပါမယ်

## 🐛 Troubleshooting

### API Key မှားယွင်းနေရင်
```
❌ Failed to create user: 401 - Unauthorized
```
→ API Key ကို ပြန်စစ်ဆေးပါ

### Proxy Path မှားရင်
```
❌ Connection Error: Server may be offline
```
→ URL နဲ့ proxy_path ကို ပြန်စစ်ဆေးပါ

### User Create လုပ်လို့မရရင်
- Admin UUID မှန်ကန်ရဲ့လား စစ်ပါ
- Hiddify panel က online ဖြစ်နေရဲ့လား စစ်ပါ
- API Key က valid ဖြစ်နေရဲ့လား စစ်ပါ

## 📚 API Documentation

Hiddify API အပြည့်အစုံ:
```
https://your-domain/proxy_path/api/docs
```

## 🎉 အောင်မြင်မှု

Bot က Hiddify နဲ့ အောင်မြင်စွာ ချိတ်ဆက်နိုင်ပြီဆိုရင် user creation တွေ automatic လုပ်ပေးနိုင်ပါပြီ။

Multi-protocol support ရှိတာကြောင့် users တွေက VLESS, VMess, Trojan, Reality စတာတွေ အကုန် အသုံးပြုနိုင်ပါတယ်။
