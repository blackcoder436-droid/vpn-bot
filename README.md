# 🤖 Burmese Digital Store - VPN Seller Bot

Telegram Bot for selling VPN keys from 3x-ui panels.

## 📋 Features

- ✅ Free Test Key (3GB, 72 Hours)
- ✅ Multiple Server Selection (Singapore 1, 2, 3)
- ✅ Multiple Pricing Plans (1-5 Devices)
- ✅ Auto VPN Key Generation
- ✅ Payment Screenshot Verification
- ✅ Admin Approval System
- ✅ User Key Management
- ✅ Expiry Reminders
- ✅ Sales Reports
- ✅ Broadcast Messages

## 🛠️ Installation

### 1. Install Python
Make sure you have Python 3.9+ installed.

### 2. Install Dependencies
```bash
cd "c:\Users\Asus\OneDrive\Desktop\Project\2026\vpn bot"
pip install -r requirements.txt
```

### 3. Configure the Bot
Edit `config.py` if you need to change any settings:
- Bot Token
- Admin Chat ID
- Server URLs
- Pricing
- Payment Info

### 4. Initialize Database
```bash
python database.py
```

### 5. Run the Bot
```bash
python bot.py
```

## 📱 Bot Commands

### User Commands
- `/start` - Start the bot and show main menu

### Admin Commands
- `/admin` - Open admin panel
- `/broadcast <message>` - Send message to all users

## 🖥️ How It Works

### For Users:
1. Start the bot with `/start`
2. Choose "Free Test Key" or "Buy VPN Key"
3. Select a server
4. Select a plan (for paid)
5. Send payment screenshot
6. Wait for admin approval
7. Receive VPN subscription link

### For Admin:
1. Receive order notification with screenshot
2. Click "Approve" or "Reject"
3. User automatically receives VPN key if approved

## 📊 Server Configuration

The bot connects to 3x-ui panels:
- Singapore 1: `jan.burmesedigital.store:8080`
- Singapore 2: `sg2.burmesedigital.store:8080`
- Singapore 3: `sg3.burmesedigital.store:8080`

## 💰 Pricing Plans

| Plan | Data | Duration | Price |
|------|------|----------|-------|
| Free Test | 3GB | 72 Hours | Free |
| 1 Device | Unlimited | 30 Days | 3,000 Ks |
| 2 Devices | Unlimited | 30 Days | 4,000 Ks |
| 3 Devices | Unlimited | 30 Days | 6,000 Ks |
| 4 Devices | Unlimited | 30 Days | 8,000 Ks |
| 5 Devices | Unlimited | 30 Days | 10,000 Ks |

## 🔒 Security Notes

- Never share `config.py` with credentials
- Keep bot token secret
- Regularly backup the database
- Monitor for suspicious activity

## 🐛 Troubleshooting

### Bot not responding?
- Check if bot token is correct
- Ensure internet connection
- Check console for errors

### Key generation failing?
- Verify 3x-ui panel URLs are accessible
- Check panel username/password
- Ensure inbounds are configured

### Payment screenshots not received?
- Check admin chat ID is correct
- Ensure bot has permission to send messages

## 📞 Support

For issues, contact the developer.

---
© 2026 Burmese Digital Store
