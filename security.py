# ===========================================
# Security Module for VPN Bot
# ===========================================

import time
import re
import hashlib
import logging
from functools import wraps
from collections import defaultdict
from typing import Optional, Dict, Any
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# ===================== RATE LIMITING =====================

class RateLimiter:
    """Rate limiter to prevent spam and abuse"""
    
    def __init__(self):
        # Store: {user_id: [(timestamp, action_type), ...]}
        self.user_actions: Dict[int, list] = defaultdict(list)
        self.banned_users: Dict[int, datetime] = {}  # Temporary bans
        
        # Rate limits configuration
        self.limits = {
            'message': {'count': 30, 'period': 60},      # 30 messages per minute
            'callback': {'count': 60, 'period': 60},     # 60 callbacks per minute
            'free_test': {'count': 1, 'period': 86400},  # 1 free test per day
            'order': {'count': 10, 'period': 3600},      # 10 orders per hour
            'screenshot': {'count': 5, 'period': 300},   # 5 screenshots per 5 minutes
        }
        
        # Ban thresholds
        self.spam_threshold = 100  # Actions in 60 seconds to trigger ban
        self.ban_duration = 300    # 5 minutes ban
        
    def _cleanup_old_actions(self, user_id: int, period: int):
        """Remove actions older than the specified period"""
        cutoff = time.time() - period
        self.user_actions[user_id] = [
            (ts, action) for ts, action in self.user_actions[user_id]
            if ts > cutoff
        ]
    
    def is_banned(self, user_id: int) -> bool:
        """Check if user is temporarily banned"""
        if user_id in self.banned_users:
            if datetime.now() < self.banned_users[user_id]:
                return True
            else:
                del self.banned_users[user_id]
        return False
    
    def check_rate_limit(self, user_id: int, action_type: str = 'message') -> tuple[bool, str]:
        """
        Check if user has exceeded rate limit
        Returns: (is_allowed, error_message)
        """
        # Check if user is banned
        if self.is_banned(user_id):
            remaining = (self.banned_users[user_id] - datetime.now()).seconds
            return False, f"⚠️ You are temporarily blocked. Please wait {remaining} seconds."
        
        current_time = time.time()
        
        # Get limit config
        limit_config = self.limits.get(action_type, self.limits['message'])
        
        # Cleanup old actions
        self._cleanup_old_actions(user_id, limit_config['period'])
        
        # Count recent actions of this type
        action_count = sum(
            1 for ts, action in self.user_actions[user_id]
            if action == action_type
        )
        
        # Check spam (any action type)
        total_actions = len(self.user_actions[user_id])
        if total_actions >= self.spam_threshold:
            # Ban user temporarily
            self.banned_users[user_id] = datetime.now() + timedelta(seconds=self.ban_duration)
            logger.warning(f"User {user_id} banned for spam: {total_actions} actions in 60s")
            return False, "⚠️ Too many requests! You are temporarily blocked for 5 minutes."
        
        # Check specific rate limit
        if action_count >= limit_config['count']:
            return False, f"⚠️ Rate limit exceeded. Please wait before trying again."
        
        # Record this action
        self.user_actions[user_id].append((current_time, action_type))
        return True, ""


# ===================== INPUT VALIDATION =====================

class InputValidator:
    """Validate and sanitize user inputs"""
    
    # Dangerous patterns that could indicate injection attempts
    DANGEROUS_PATTERNS = [
        r'<script',
        r'javascript:',
        r'on\w+\s*=',  # onclick, onerror, etc.
        r'data:text/html',
        r'vbscript:',
        r'\{\{.*\}\}',  # Template injection
        r'\$\{.*\}',    # Template literals
        r'__proto__',
        r'constructor',
        r'prototype',
    ]
    
    # SQL injection patterns
    SQL_PATTERNS = [
        r"('|\")\s*(or|and)\s*('|\"|\d)",
        r";\s*(drop|delete|update|insert|alter)",
        r"union\s+select",
        r"--\s*$",
        r"/\*.*\*/",
    ]
    
    # Command injection patterns
    COMMAND_PATTERNS = [
        r'\|',
        r'&&',
        r'\|\|',
        r';.*\w',
        r'\$\(',
        r'`.*`',
        r'\beval\b',
        r'\bexec\b',
    ]
    
    @classmethod
    def is_safe_text(cls, text: str) -> tuple[bool, str]:
        """
        Check if text is safe from injection attacks
        Returns: (is_safe, threat_type)
        """
        if not text:
            return True, ""
        
        text_lower = text.lower()
        
        # Check dangerous patterns
        for pattern in cls.DANGEROUS_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return False, "dangerous_pattern"
        
        # Check SQL injection
        for pattern in cls.SQL_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return False, "sql_injection"
        
        # Check command injection
        for pattern in cls.COMMAND_PATTERNS:
            if re.search(pattern, text):
                return False, "command_injection"
        
        return True, ""
    
    @classmethod
    def sanitize_text(cls, text: str, max_length: int = 500) -> str:
        """Sanitize text input"""
        if not text:
            return ""
        
        # Truncate to max length
        text = text[:max_length]
        
        # Remove control characters
        text = ''.join(char for char in text if ord(char) >= 32 or char in '\n\t')
        
        # Escape HTML special characters
        text = text.replace('&', '&amp;')
        text = text.replace('<', '&lt;')
        text = text.replace('>', '&gt;')
        text = text.replace('"', '&quot;')
        text = text.replace("'", '&#x27;')
        
        return text.strip()
    
    @classmethod
    def validate_callback_data(cls, data: str, allowed_prefixes: list) -> bool:
        """Validate callback data format"""
        if not data:
            return False
        
        # Check if callback starts with allowed prefix
        for prefix in allowed_prefixes:
            if data.startswith(prefix):
                return True
        
        return False
    
    @classmethod
    def validate_telegram_id(cls, telegram_id: Any) -> bool:
        """Validate Telegram user ID"""
        if not isinstance(telegram_id, int):
            return False
        
        # Telegram IDs are positive integers
        if telegram_id <= 0:
            return False
        
        # Max reasonable value (10^15)
        if telegram_id > 10**15:
            return False
        
        return True
    
    @classmethod
    def validate_server_id(cls, server_id: str, valid_servers: list) -> bool:
        """Validate server ID"""
        if not server_id:
            return False
        
        # Check if server exists
        return server_id in valid_servers
    
    @classmethod
    def validate_plan_id(cls, plan_id: str, valid_plans: list) -> bool:
        """Validate plan ID"""
        if not plan_id:
            return False
        
        return plan_id in valid_plans


# ===================== SECURITY DECORATORS =====================

# Global rate limiter instance
rate_limiter = RateLimiter()

def rate_limit(action_type: str = 'message'):
    """Decorator to apply rate limiting to handlers"""
    def decorator(func):
        @wraps(func)
        def wrapper(message_or_call, *args, **kwargs):
            # Get user_id from message or callback
            if hasattr(message_or_call, 'from_user'):
                user_id = message_or_call.from_user.id
            elif hasattr(message_or_call, 'message'):
                user_id = message_or_call.from_user.id
            else:
                return func(message_or_call, *args, **kwargs)
            
            # Check rate limit
            is_allowed, error_msg = rate_limiter.check_rate_limit(user_id, action_type)
            
            if not is_allowed:
                logger.warning(f"Rate limit exceeded for user {user_id}: {action_type}")
                # Return error message based on handler type
                if hasattr(message_or_call, 'message'):
                    # It's a callback
                    from telebot import TeleBot
                    # Note: You need to pass bot instance or handle differently
                    return None
                return None
            
            return func(message_or_call, *args, **kwargs)
        return wrapper
    return decorator


def validate_input(func):
    """Decorator to validate message input"""
    @wraps(func)
    def wrapper(message, *args, **kwargs):
        if hasattr(message, 'text') and message.text:
            is_safe, threat_type = InputValidator.is_safe_text(message.text)
            if not is_safe:
                logger.warning(f"Unsafe input from user {message.from_user.id}: {threat_type}")
                # Silently ignore malicious input
                return None
        return func(message, *args, **kwargs)
    return wrapper


def admin_only(admin_id: int):
    """Decorator to restrict handler to admin only"""
    def decorator(func):
        @wraps(func)
        def wrapper(message_or_call, *args, **kwargs):
            # Get user_id
            if hasattr(message_or_call, 'from_user'):
                user_id = message_or_call.from_user.id
            else:
                return None
            
            if user_id != admin_id:
                logger.warning(f"Unauthorized admin access attempt by user {user_id}")
                return None
            
            return func(message_or_call, *args, **kwargs)
        return wrapper
    return decorator


# ===================== LOGGING & MONITORING =====================

class SecurityLogger:
    """Log security events"""
    
    @staticmethod
    def log_suspicious_activity(user_id: int, activity_type: str, details: str = ""):
        """Log suspicious activity"""
        logger.warning(f"SECURITY: User {user_id} - {activity_type} - {details}")
    
    @staticmethod
    def log_admin_action(admin_id: int, action: str, target: str = ""):
        """Log admin actions"""
        logger.info(f"ADMIN: {admin_id} performed {action} on {target}")
    
    @staticmethod
    def log_failed_auth(user_id: int, attempted_action: str):
        """Log failed authentication attempts"""
        logger.warning(f"AUTH FAIL: User {user_id} attempted {attempted_action}")


# ===================== CALLBACK DATA VALIDATION =====================

# List of valid callback prefixes
VALID_CALLBACK_PREFIXES = [
    'main_menu',
    'free_test',
    'free_server_',
    'free_proto_',
    'buy_key',
    'server_',
    'proto_',
    'device_',
    'plan_',
    'my_keys',
    'key_detail_',
    'exchange_key',
    'exchange_',
    'new_proto_',
    'check_usage',
    'usage_',
    'help',
    'confirm_payment_',
    'cancel_order_',
    # Admin callbacks
    'admin_',
    'approve_',
    'reject_',
    'toggle_server_',
]

def is_valid_callback(callback_data: str) -> bool:
    """Check if callback data is valid"""
    return InputValidator.validate_callback_data(callback_data, VALID_CALLBACK_PREFIXES)


# ===================== ANTI-ABUSE MEASURES =====================

class AbuseDetector:
    """Detect and prevent abuse patterns"""
    
    def __init__(self):
        self.suspicious_users: Dict[int, int] = defaultdict(int)  # user_id: suspicion_score
        self.suspicion_threshold = 10
        
    def record_suspicious_activity(self, user_id: int, severity: int = 1):
        """Record suspicious activity and increase suspicion score"""
        self.suspicious_users[user_id] += severity
        
        if self.suspicious_users[user_id] >= self.suspicion_threshold:
            SecurityLogger.log_suspicious_activity(
                user_id, 
                "HIGH_SUSPICION_SCORE",
                f"Score: {self.suspicious_users[user_id]}"
            )
            return True  # User should be reviewed
        return False
    
    def check_order_pattern(self, user_id: int, recent_orders: list) -> bool:
        """Check for suspicious order patterns"""
        if not recent_orders:
            return False
        
        # Too many failed orders
        failed_count = sum(1 for order in recent_orders if order.get('status') == 'rejected')
        if failed_count >= 5:
            self.record_suspicious_activity(user_id, 3)
            return True
        
        return False
    
    def reset_user(self, user_id: int):
        """Reset suspicion score for user"""
        if user_id in self.suspicious_users:
            del self.suspicious_users[user_id]


# Global abuse detector
abuse_detector = AbuseDetector()
