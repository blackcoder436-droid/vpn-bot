# ===========================================
# Security Module for VPN Bot
# Enhanced DDoS Protection, Prompt Injection Defense
# ===========================================

import time
import re
import hashlib
import logging
import threading
from functools import wraps
from collections import defaultdict
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# ===================== RATE LIMITING =====================

class RateLimiter:
    """Enhanced rate limiter to prevent spam, DDoS and abuse with auto-block"""
    
    def __init__(self):
        # Store: {user_id: [(timestamp, action_type), ...]}
        self.user_actions: Dict[int, list] = defaultdict(list)
        self.banned_users: Dict[int, datetime] = {}  # Temporary bans (runtime)
        self.ip_tracking: Dict[str, list] = defaultdict(list)  # IP-based tracking
        self.global_request_count = 0
        self.global_request_window_start = time.time()
        self._lock = threading.Lock()
        
        # DDoS detection tracking
        self.ddos_suspects: Dict[int, dict] = defaultdict(lambda: {
            'request_count': 0,
            'first_request': 0,
            'violations': 0,
            'last_violation': 0
        })
        
        # Rate limits configuration - Stricter limits for DDoS protection
        self.limits = {
            'message': {'count': 15, 'period': 60},      # 15 messages per minute
            'callback': {'count': 30, 'period': 60},     # 30 callbacks per minute
            'free_test': {'count': 1, 'period': 86400},  # 1 free test per day
            'order': {'count': 5, 'period': 3600},       # 5 orders per hour
            'screenshot': {'count': 3, 'period': 300},   # 3 screenshots per 5 minutes
            'referral': {'count': 10, 'period': 3600},   # 10 referral actions per hour
            'admin': {'count': 100, 'period': 60},       # Admin has higher limits
        }
        
        # DDoS Protection settings
        self.global_limit = 500           # Max global requests per minute (reduced)
        self.burst_limit = 30             # Max burst requests per second (reduced)
        self.burst_window = []            # Track burst requests
        
        # Auto-ban thresholds (stricter)
        self.spam_threshold = 50          # Actions in 60 seconds to trigger ban
        self.ban_duration = 1800          # 30 minutes ban (increased)
        self.severe_ban_duration = 7200   # 2 hours for severe violations
        
        # DDoS auto-block settings
        self.ddos_threshold = 60          # Requests per minute to consider DDoS
        self.ddos_violation_threshold = 3 # Violations before permanent ban
        self.ddos_window = 10             # Seconds to track rapid requests
        
        # Callback for database ban (set by bot.py)
        self.db_ban_callback = None
        
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
    
    def ban_user(self, user_id: int, duration: int = None, reason: str = "rate_limit", persist_to_db: bool = False):
        """Ban a user temporarily, optionally persist to database"""
        if duration is None:
            duration = self.ban_duration
        self.banned_users[user_id] = datetime.now() + timedelta(seconds=duration)
        logger.warning(f"🚫 User {user_id} banned for {duration}s - Reason: {reason}")
        
        # Persist to database if callback is set and persist_to_db is True
        if persist_to_db and self.db_ban_callback:
            try:
                hours = duration / 3600  # Convert seconds to hours
                self.db_ban_callback(user_id, reason, hours if hours > 0 else None)
                logger.warning(f"📦 User {user_id} ban persisted to database")
            except Exception as e:
                logger.error(f"Failed to persist ban to database: {e}")
    
    def set_db_ban_callback(self, callback):
        """Set callback function for database bans"""
        self.db_ban_callback = callback
    
    def check_ddos_protection(self, user_id: int = None) -> tuple[bool, str]:
        """Check global rate limits for DDoS protection with user tracking"""
        with self._lock:
            current_time = time.time()
            
            # Check burst protection (requests per second)
            self.burst_window = [t for t in self.burst_window if current_time - t < 1]
            if len(self.burst_window) >= self.burst_limit:
                logger.critical(f"🚨 DDOS ALERT: Burst limit exceeded - {len(self.burst_window)} req/sec")
                return False, "burst_exceeded"
            self.burst_window.append(current_time)
            
            # Check global rate (requests per minute)
            if current_time - self.global_request_window_start > 60:
                self.global_request_count = 0
                self.global_request_window_start = current_time
            
            self.global_request_count += 1
            if self.global_request_count > self.global_limit:
                logger.critical(f"🚨 DDOS ALERT: Global limit exceeded - {self.global_request_count} req/min")
                return False, "global_exceeded"
            
            # Track per-user DDoS patterns
            if user_id:
                return self._check_user_ddos_pattern(user_id, current_time)
            
            return True, ""
    
    def _check_user_ddos_pattern(self, user_id: int, current_time: float) -> tuple[bool, str]:
        """Check if a specific user is exhibiting DDoS-like behavior"""
        suspect = self.ddos_suspects[user_id]
        
        # Reset counter if window expired
        if current_time - suspect['first_request'] > self.ddos_window:
            suspect['request_count'] = 0
            suspect['first_request'] = current_time
        
        suspect['request_count'] += 1
        
        # Check if user exceeds DDoS threshold
        requests_per_sec = suspect['request_count'] / max(1, current_time - suspect['first_request'])
        
        if requests_per_sec > 5:  # More than 5 requests per second
            suspect['violations'] += 1
            suspect['last_violation'] = current_time
            
            logger.warning(f"🚨 DDoS Pattern Detected: User {user_id} - {requests_per_sec:.1f} req/sec, Violations: {suspect['violations']}")
            
            if suspect['violations'] >= self.ddos_violation_threshold:
                # Severe violation - long ban + persist to database
                self.ban_user(user_id, self.severe_ban_duration * 2, "ddos_attack", persist_to_db=True)
                logger.critical(f"🚫 AUTO-BLOCKED: User {user_id} for DDoS attack (persisted to DB)")
                return False, "ddos_autoblock"
            elif suspect['violations'] >= 2:
                # Medium violation
                self.ban_user(user_id, self.severe_ban_duration, "ddos_suspected")
                return False, "ddos_banned"
            else:
                # First violation - warning
                self.ban_user(user_id, self.ban_duration, "rapid_requests")
                return False, "rate_warned"
        
        return True, ""
    
    def check_rate_limit(self, user_id: int, action_type: str = 'message') -> tuple[bool, str]:
        """
        Check if user has exceeded rate limit with DDoS auto-block
        Returns: (is_allowed, error_message)
        """
        # Check global DDoS protection first (with user tracking)
        ddos_ok, ddos_reason = self.check_ddos_protection(user_id)
        if not ddos_ok:
            if ddos_reason == "ddos_autoblock":
                return False, "🚫 သင့် Account ကို DDoS attack ကြောင့် block လုပ်ထားပါသည်။"
            elif ddos_reason == "ddos_banned":
                return False, "⚠️ Request များအလွန်အကျွံ ပို့နေပါသည်! 2 နာရီ block ခံရပါမည်။"
            elif ddos_reason == "rate_warned":
                return False, "⚠️ Request များ အများကြီး ပို့နေပါသည်! 30 မိနစ် ယာယီ block ခံရပါမည်။"
            return False, "⚠️ Server is busy. Please try again later."
        
        # Check if user is banned
        if self.is_banned(user_id):
            remaining = (self.banned_users[user_id] - datetime.now()).seconds
            minutes = remaining // 60
            seconds = remaining % 60
            if minutes > 0:
                return False, f"⚠️ သင် ယာယီ block ခံထားရပါသည်။ {minutes} မိနစ် {seconds} စက္ကန့် စောင့်ပါ။"
            return False, f"⚠️ သင် ယာယီ block ခံထားရပါသည်။ {seconds} စက္ကန့် စောင့်ပါ။"
        
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
        
        # Check spam (any action type) - stricter threshold
        total_actions = len(self.user_actions[user_id])
        if total_actions >= self.spam_threshold:
            # Ban user and persist to database for repeated offenders
            persist = total_actions >= self.spam_threshold * 1.5  # Persist if 1.5x threshold
            self.ban_user(user_id, self.severe_ban_duration, "spam_detected", persist_to_db=persist)
            return False, "⚠️ Request များ အများကြီး ပို့နေပါသည်! 2 နာရီ ယာယီ block ခံရပါမည်။"
        
        # Warning at 80% of threshold
        if total_actions >= self.spam_threshold * 0.8:
            logger.warning(f"⚠️ User {user_id} approaching spam threshold: {total_actions}/{self.spam_threshold}")
        
        # Check specific rate limit
        if action_count >= limit_config['count']:
            # Record violation for DDoS tracking
            self.ddos_suspects[user_id]['violations'] += 1
            return False, f"⚠️ Rate limit ကျော်နေပါသည်။ ခဏနေ ပြန်စမ်းပါ။"
        
        # Record this action
        self.user_actions[user_id].append((current_time, action_type))
        return True, ""


# ===================== INPUT VALIDATION =====================

class InputValidator:
    """Enhanced validation and sanitization for user inputs - Protects against prompt injection"""
    
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
        r'<iframe',
        r'<object',
        r'<embed',
        r'<form',
        r'<input',
        r'document\.',
        r'window\.',
        r'localStorage',
        r'sessionStorage',
        r'cookie',
    ]
    
    # SQL injection patterns
    SQL_PATTERNS = [
        r"('|\")\s*(or|and)\s*('|\"|\d)",
        r";\s*(drop|delete|update|insert|alter|truncate|create)",
        r"union\s+(all\s+)?select",
        r"--\s*$",
        r"/\*.*\*/",
        r"xp_",
        r"sp_",
        r"0x[0-9a-fA-F]+",
        r"char\s*\(",
        r"concat\s*\(",
        r"benchmark\s*\(",
        r"sleep\s*\(",
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
        r'\bsystem\b',
        r'\bos\.',
        r'\bsubprocess',
        r'import\s+os',
        r'import\s+subprocess',
        r'__import__',
        r'open\s*\(',
        r'read\s*\(',
        r'write\s*\(',
    ]
    
    # Prompt injection patterns (for AI/bot protection)
    PROMPT_INJECTION_PATTERNS = [
        r'ignore\s+(previous|all|above)\s+instructions?',
        r'disregard\s+(previous|all|above)',
        r'forget\s+(previous|all|everything)',
        r'you\s+are\s+now\s+',
        r'pretend\s+(to\s+be|you\s+are)',
        r'act\s+as\s+(if|a)',
        r'new\s+instructions?:',
        r'override\s+(previous|system)',
        r'system\s*:\s*',
        r'assistant\s*:\s*',
        r'human\s*:\s*',
        r'user\s*:\s*',
        r'admin\s*:\s*',
        r'\[system\]',
        r'\[admin\]',
        r'jailbreak',
        r'bypass\s+(filter|security|restriction)',
        r'reveal\s+(secret|password|key|api)',
        r'show\s+me\s+(the\s+)?(secret|password|config)',
        r'what\s+is\s+(your|the)\s+(password|api\s*key|secret)',
        r'give\s+me\s+(admin|root)\s+access',
        r'execute\s+(this\s+)?command',
        r'run\s+(this\s+)?code',
        r'sudo\s+',
        r'as\s+root',
        r'with\s+elevated\s+privileges',
    ]
    
    # Path traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        r'\.\.',
        r'%2e%2e',
        r'%252e',
        r'\.\./',
        r'\.\.\\\\',
        r'/etc/',
        r'/proc/',
        r'/sys/',
        r'c:\\\\',
        r'\\\\windows',
    ]
    
    @classmethod
    def is_safe_text(cls, text: str) -> tuple[bool, str]:
        """
        Check if text is safe from all injection attacks
        Returns: (is_safe, threat_type)
        """
        if not text:
            return True, ""
        
        text_lower = text.lower()
        
        # Check prompt injection (highest priority for bots)
        for pattern in cls.PROMPT_INJECTION_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                logger.warning(f"Prompt injection attempt detected: {pattern}")
                return False, "prompt_injection"
        
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
        
        # Check path traversal
        for pattern in cls.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return False, "path_traversal"
        
        # Check for excessive length (potential buffer overflow)
        if len(text) > 4096:
            return False, "excessive_length"
        
        # Check for null bytes
        if '\x00' in text:
            return False, "null_byte_injection"
        
        return True, ""
    
    @classmethod
    def sanitize_text(cls, text: str, max_length: int = 500) -> str:
        """Sanitize text input"""
        if not text:
            return ""
        
        # Truncate to max length
        text = text[:max_length]
        
        # Remove null bytes
        text = text.replace('\x00', '')
        
        # Remove control characters (except newline and tab)
        text = ''.join(char for char in text if ord(char) >= 32 or char in '\n\t')
        
        # Escape HTML special characters
        text = text.replace('&', '&amp;')
        text = text.replace('<', '&lt;')
        text = text.replace('>', '&gt;')
        text = text.replace('"', '&quot;')
        text = text.replace("'", '&#x27;')
        text = text.replace('/', '&#x2F;')
        text = text.replace('\\', '&#x5C;')
        
        return text.strip()
    
    @classmethod
    def sanitize_username(cls, username: str) -> str:
        """Sanitize username - only allow safe characters"""
        if not username:
            return ""
        
        # Only allow alphanumeric, underscore
        sanitized = re.sub(r'[^\w]', '', username)
        return sanitized[:64]  # Max 64 chars
    
    @classmethod
    def validate_callback_data(cls, data: str, allowed_prefixes: list) -> bool:
        """Validate callback data format"""
        if not data:
            return False
        
        # Check length
        if len(data) > 64:
            return False
        
        # Check for dangerous characters
        if any(c in data for c in ['<', '>', '"', "'", ';', '|', '&']):
            return False
        
        # Check if callback starts with allowed prefix
        for prefix in allowed_prefixes:
            if data.startswith(prefix) or data == prefix.rstrip('_'):
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
    'free_test_verify',  # Channel membership verification
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
    'exkey_',
    'expro_',
    'new_proto_',
    'check_usage',
    'usage_',
    'help',
    'send_screenshot_',
    'confirm_payment_',
    'cancel_order_',
    # Referral callbacks
    'referral',
    'my_referral_link',
    'referral_stats',
    'claim_free_month',
    # Admin callbacks
    'admin_',
    'approve_freekey_',  # MUST be before 'approve_'
    'reject_freekey_',   # MUST be before 'reject_'
    'approve_',
    'reject_',
    'toggle_server_',
    'toggle_feature_',
    'toggle_protocol_',
    # Statistics callbacks
    'stats_',
    # Ban management callbacks
    'ban_user_start',
    'unban_user_start',
    'ban_list',
    'unban_',
    # Server management callbacks
    'add_server_start',
    'add_server_xui',
    'add_server_hiddify',
    'delete_server_start',
    'confirm_delete_server_',
    'do_delete_server_',
]

def is_valid_callback(callback_data: str) -> bool:
    """Check if callback data is valid"""
    return InputValidator.validate_callback_data(callback_data, VALID_CALLBACK_PREFIXES)


# ===================== ANTI-ABUSE MEASURES =====================

class AbuseDetector:
    """Enhanced abuse detection and prevention"""
    
    def __init__(self):
        self._lock = threading.Lock()
        self.suspicious_users: Dict[int, dict] = defaultdict(lambda: {
            'score': 0,
            'last_activity': 0,
            'activities': [],
            'warnings': 0
        })
        self.blocked_users: Dict[int, float] = {}  # user_id: block_until_timestamp
        
        # Thresholds
        self.suspicion_threshold = 10
        self.warning_threshold = 3  # Warnings before block
        self.block_duration = 3600  # 1 hour block
        self.severe_block_duration = 86400  # 24 hour block for severe abuse
        
        # Activity history limit
        self.max_activity_history = 50
        
        # Abuse patterns config
        self.abuse_patterns = {
            'rapid_orders': {'count': 5, 'window': 60, 'severity': 3},
            'failed_payments': {'count': 3, 'window': 300, 'severity': 4},
            'injection_attempts': {'count': 2, 'window': 600, 'severity': 8},
            'spam_messages': {'count': 10, 'window': 30, 'severity': 5},
            'invalid_callbacks': {'count': 5, 'window': 60, 'severity': 3},
        }
    
    def is_user_blocked(self, user_id: int) -> bool:
        """Check if user is currently blocked"""
        with self._lock:
            if user_id in self.blocked_users:
                if time.time() < self.blocked_users[user_id]:
                    return True
                else:
                    del self.blocked_users[user_id]
            return False
    
    def block_user(self, user_id: int, duration: int = None, reason: str = "abuse"):
        """Block a user for specified duration"""
        with self._lock:
            block_time = duration or self.block_duration
            self.blocked_users[user_id] = time.time() + block_time
            SecurityLogger.log_suspicious_activity(
                user_id, 
                f"USER_BLOCKED",
                f"Duration: {block_time}s, Reason: {reason}"
            )
    
    def record_suspicious_activity(self, user_id: int, activity_type: str, severity: int = 1) -> tuple[bool, str]:
        """
        Record suspicious activity and increase suspicion score
        Returns: (should_block, action_taken)
        """
        with self._lock:
            current_time = time.time()
            user_data = self.suspicious_users[user_id]
            
            # Add activity to history
            user_data['activities'].append({
                'type': activity_type,
                'time': current_time,
                'severity': severity
            })
            
            # Trim old activities
            if len(user_data['activities']) > self.max_activity_history:
                user_data['activities'] = user_data['activities'][-self.max_activity_history:]
            
            # Update score (decay over time)
            time_since_last = current_time - user_data['last_activity']
            if time_since_last > 3600:  # Reduce score after 1 hour of inactivity
                user_data['score'] = max(0, user_data['score'] - 3)
            
            user_data['score'] += severity
            user_data['last_activity'] = current_time
            
            # Log the activity
            SecurityLogger.log_suspicious_activity(user_id, activity_type, f"Severity: {severity}, Total Score: {user_data['score']}")
            
            # Check if user should be blocked
            if user_data['score'] >= self.suspicion_threshold:
                user_data['warnings'] += 1
                
                if user_data['warnings'] >= self.warning_threshold:
                    # Severe block for repeated offenders
                    self.blocked_users[user_id] = current_time + self.severe_block_duration
                    return True, f"severe_block_{self.severe_block_duration}s"
                else:
                    # Regular block
                    self.blocked_users[user_id] = current_time + self.block_duration
                    user_data['score'] = 0  # Reset score but keep warnings
                    return True, f"blocked_{self.block_duration}s"
            
            return False, "recorded"
    
    def check_injection_attempt(self, user_id: int, threat_type: str) -> tuple[bool, str]:
        """Record injection attempts - severe penalty"""
        severity_map = {
            'prompt_injection': 8,
            'sql_injection': 7,
            'command_injection': 9,
            'path_traversal': 6,
            'dangerous_pattern': 5,
            'null_byte_injection': 6,
        }
        severity = severity_map.get(threat_type, 5)
        return self.record_suspicious_activity(user_id, f"INJECTION_{threat_type.upper()}", severity)
    
    def check_order_pattern(self, user_id: int, recent_orders: list) -> tuple[bool, str]:
        """Check for suspicious order patterns"""
        if not recent_orders:
            return False, ""
        
        with self._lock:
            current_time = time.time()
            
            # Count failed orders in last hour
            failed_count = sum(
                1 for order in recent_orders 
                if order.get('status') == 'rejected' 
                and (current_time - order.get('created_at', 0)) < 3600
            )
            
            if failed_count >= 5:
                return self.record_suspicious_activity(user_id, "EXCESSIVE_FAILED_ORDERS", 4)
            
            # Check for rapid order creation
            recent_count = sum(
                1 for order in recent_orders 
                if (current_time - order.get('created_at', 0)) < 60
            )
            
            if recent_count >= 5:
                return self.record_suspicious_activity(user_id, "RAPID_ORDER_CREATION", 3)
            
            # Check for duplicate screenshot submissions
            screenshots = [order.get('screenshot_hash') for order in recent_orders if order.get('screenshot_hash')]
            if len(screenshots) != len(set(screenshots)) and len(screenshots) > 1:
                return self.record_suspicious_activity(user_id, "DUPLICATE_SCREENSHOTS", 5)
        
        return False, ""
    
    def check_message_flood(self, user_id: int) -> tuple[bool, str]:
        """Check for message flooding"""
        return self.record_suspicious_activity(user_id, "MESSAGE_FLOOD", 3)
    
    def reset_user(self, user_id: int):
        """Reset suspicion score and unblock user"""
        with self._lock:
            if user_id in self.suspicious_users:
                del self.suspicious_users[user_id]
            if user_id in self.blocked_users:
                del self.blocked_users[user_id]
    
    def get_user_status(self, user_id: int) -> dict:
        """Get user's current abuse status"""
        with self._lock:
            is_blocked = self.is_user_blocked(user_id)
            user_data = self.suspicious_users.get(user_id, {})
            
            return {
                'is_blocked': is_blocked,
                'block_expires': self.blocked_users.get(user_id, 0),
                'suspicion_score': user_data.get('score', 0),
                'warnings': user_data.get('warnings', 0),
                'recent_activities': user_data.get('activities', [])[-5:]
            }
    
    def cleanup_old_data(self):
        """Clean up old data to prevent memory bloat"""
        with self._lock:
            current_time = time.time()
            
            # Remove expired blocks
            expired_blocks = [uid for uid, exp_time in self.blocked_users.items() if exp_time < current_time]
            for uid in expired_blocks:
                del self.blocked_users[uid]
            
            # Remove users with no recent activity (7 days)
            inactive_users = []
            for uid, data in self.suspicious_users.items():
                if current_time - data.get('last_activity', 0) > 604800:  # 7 days
                    inactive_users.append(uid)
            
            for uid in inactive_users:
                del self.suspicious_users[uid]


# Global abuse detector
abuse_detector = AbuseDetector()
