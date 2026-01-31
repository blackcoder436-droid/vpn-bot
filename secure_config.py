# ===========================================
# Secure Configuration Loader
# ===========================================
# This module loads sensitive credentials from environment variables
# instead of hardcoding them in config.py

import os
from pathlib import Path

# Try to load from .env file if python-dotenv is available
try:
    from dotenv import load_dotenv
    env_path = Path(__file__).parent / '.env'
    if env_path.exists():
        load_dotenv(env_path)
        print("✅ Loaded configuration from .env file")
except ImportError:
    print("⚠️ python-dotenv not installed. Using system environment variables.")


def get_env(key: str, default: str = None, required: bool = False) -> str:
    """Get environment variable with validation"""
    value = os.environ.get(key, default)
    
    if required and not value:
        raise ValueError(f"Required environment variable {key} is not set!")
    
    return value


def get_env_int(key: str, default: int = None, required: bool = False) -> int:
    """Get integer environment variable"""
    value = get_env(key, str(default) if default else None, required)
    
    if value is None:
        return default
    
    try:
        return int(value)
    except ValueError:
        raise ValueError(f"Environment variable {key} must be an integer!")


def get_env_bool(key: str, default: bool = False) -> bool:
    """Get boolean environment variable"""
    value = get_env(key, str(default).lower())
    return value.lower() in ('true', '1', 'yes', 'on')


# ===========================================
# Secure Credentials Loading
# ===========================================

# Telegram Bot Settings
BOT_TOKEN = get_env('BOT_TOKEN', required=True)
ADMIN_CHAT_ID = get_env_int('ADMIN_CHAT_ID', required=True)
PAYMENT_CHANNEL_ID = get_env_int('PAYMENT_CHANNEL_ID', required=True)

# 3x-ui Panel Credentials
XUI_USERNAME = get_env('XUI_USERNAME', required=True)
XUI_PASSWORD = get_env('XUI_PASSWORD', required=True)

# Database
DATABASE_PATH = get_env('DATABASE_PATH', 'vpn_bot.db')

# Security Settings
RATE_LIMIT_ENABLED = get_env_bool('RATE_LIMIT_ENABLED', True)
DEBUG_MODE = get_env_bool('DEBUG_MODE', False)


def validate_config():
    """Validate configuration on startup"""
    errors = []
    
    # Check BOT_TOKEN format
    if not BOT_TOKEN or ':' not in BOT_TOKEN:
        errors.append("Invalid BOT_TOKEN format")
    
    # Check ADMIN_CHAT_ID
    if not ADMIN_CHAT_ID or ADMIN_CHAT_ID <= 0:
        errors.append("Invalid ADMIN_CHAT_ID")
    
    # Check XUI credentials
    if not XUI_USERNAME or not XUI_PASSWORD:
        errors.append("XUI credentials are required")
    
    if errors:
        for error in errors:
            print(f"❌ Config Error: {error}")
        return False
    
    print("✅ Configuration validated successfully")
    return True
