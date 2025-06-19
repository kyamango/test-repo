import os
import re
import json
import requests
import time
import sys
import io
import shutil
from datetime import datetime, timedelta, timezone
from bs4 import BeautifulSoup
import pandas as pd
from urllib.parse import urlparse, urljoin
import hashlib
import pickle
import difflib
import random
import logging
from openai import OpenAI
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import base64
import uuid
import platform
import argparse
from cryptography.fernet import Fernet
import socket
import threading
import signal
import atexit
from token_encryption import TokenManager
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from core.lib.github_validator import GitHubLicenseValidator

# Check GitHub license
def check_license():
    """Check license before running in GitHub Actions"""
    if os.getenv("GITHUB_ACTIONS"):
        validator = GitHubLicenseValidator()
        if not validator.verify_license():
            print("❌ GitHub license validation failed")
            sys.exit(1)
        return True
    return True

# Run license check at start
if not check_license():
    sys.exit(1)

_language_message_shown = False
_request_handler = None

def log_info(msg):
    # Only print short status/progress, not URLs or long details
    print(msg)

def get_base_dir():
    """Get base directory (parent of core folder)"""
    current_dir = os.path.dirname(os.path.abspath(__file__))  # Get tools dir
    core_dir = os.path.dirname(current_dir)  # Get core dir
    return os.path.dirname(core_dir)  # Get project root dir

def setup_auto_encryption(generator_instance):
    """Setup automatic encryption when program exits"""
    def cleanup_handler(signum=None, frame=None):
        if hasattr(generator_instance, 'token_manager'):
            generator_instance.auto_encrypt_tokens_on_exit()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, cleanup_handler)  # Ctrl+C
    signal.signal(signal.SIGTERM, cleanup_handler)  # Terminate
    atexit.register(lambda: generator_instance.auto_encrypt_tokens_on_exit())

def encrypt_existing_tokens(base_path):
    """Utility function to encrypt existing plain text tokens"""
    token_manager = TokenManager(base_path)
    migrated = token_manager.migrate_existing_tokens()
    
    if migrated:
        print(f"✅ Successfully encrypted {len(migrated)} token files:")
        for file_path in migrated:
            print(f"   - {file_path}")
    else:
        print("ℹ️ No plain text tokens found to encrypt")

def decrypt_tokens_for_viewing(base_path):
    """Utility function to view decrypted tokens (for debugging)"""
    token_manager = TokenManager(base_path)
    token_file = os.path.join(base_path, "token", "tokens.txt")
    
    if not os.path.exists(token_file):
        print("❌ Token file not found")
        return
    
    try:
        with open(token_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        
        print("📋 Decrypted tokens:")
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if line and not line.startswith("#"):
                decrypted = token_manager.encryptor.decrypt_token(line)
                # Only show first 10 characters for security
                masked_token = decrypted[:10] + "..." if len(decrypted) > 10 else decrypted
                print(f"   {i}. {masked_token}")
    except Exception as e:
        print(f"❌ Error reading tokens: {str(e)}")

def ensure_dependencies():
    """
    Check for required dependencies and install if missing
    """
    try:
        import langdetect
    except ImportError:
        print("Installing required dependency: langdetect")
        try:
            import subprocess
            subprocess.check_call([sys.executable, "-m", "pip", "install", "langdetect"])
            print("Successfully installed langdetect")
        except Exception as e:
            print(f"Warning: Failed to install langdetect automatically: {e}")
            print("Please install manually with: pip install langdetect")

# Constants and configurations
BASE_DIR = get_base_dir()

class UserAgentManager:
    """
    Manage user agents with blocking status tracking and priority
    """
    
    def __init__(self, language=None):
        self.language = language
        self.ua_stats_file = os.path.join(get_kw_path(language), "ua_stats.json")
        self.ua_stats = self._load_ua_stats()
        self.rotation_index = 0
        
    def _load_ua_stats(self):
        """Load user agent statistics from file"""
        if os.path.exists(self.ua_stats_file):
            try:
                with open(self.ua_stats_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                pass
        return {
            "user_agents": {},
            "last_updated": datetime.now().isoformat(),
            "global_stats": {
                "total_requests": 0,
                "total_blocks": 0,
                "success_rate": 100.0
            }
        }
    
    def _save_ua_stats(self):
        """Save user agent statistics to file"""
        try:
            self.ua_stats["last_updated"] = datetime.now().isoformat()
            with open(self.ua_stats_file, 'w', encoding='utf-8') as f:
                json.dump(self.ua_stats, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Warning: Could not save UA stats: {e}")
    
    def get_user_agent_list(self):
        """Get user agent list from file or default"""
        user_agent_file = os.path.join(get_kw_path(self.language), "user-agent.txt")
        user_agents = []
        
        if os.path.exists(user_agent_file):
            try:
                with open(user_agent_file, "r", encoding="utf-8") as f:
                    user_agents = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
            except:
                pass
        
        if not user_agents:
            configs = get_default_configurations()
            user_agents = [ua for ua in configs["default_user_agents"] if not ua.startswith("#") and ua.strip()]
        
        return user_agents
    
    def get_prioritized_user_agent(self):
        """
        Get user agent with priority based on success rate
        """
        user_agents = self.get_user_agent_list()
        if not user_agents:
            return self._get_fallback_user_agent()
        
        # Calculate priority based on success rate
        ua_priorities = []
        for ua in user_agents:
            stats = self.ua_stats["user_agents"].get(ua, {
                "requests": 0,
                "blocks": 0,
                "success_rate": 100.0,
                "last_blocked": None,
                "consecutive_blocks": 0
            })
            
            # Calculate penalty based on recent blocks
            penalty = 0
            if stats["last_blocked"]:
                try:
                    last_blocked = datetime.fromisoformat(stats["last_blocked"])
                    hours_since_block = (datetime.now() - last_blocked).total_seconds() / 3600
                    
                    # Penalty decreases over time (recovery period)
                    if hours_since_block < 1:
                        penalty = 50  # High penalty if recently blocked
                    elif hours_since_block < 6:
                        penalty = 20  # Medium penalty
                    elif hours_since_block < 24:
                        penalty = 5   # Low penalty
                except:
                    pass
            
            # Additional penalty for consecutive blocks
            penalty += min(stats["consecutive_blocks"] * 10, 30)
            
            priority_score = max(stats["success_rate"] - penalty, 0)
            ua_priorities.append((ua, priority_score, stats))
        
        # Sort by priority score (descending)
        ua_priorities.sort(key=lambda x: x[1], reverse=True)
        
        # Weighted random selection from top 3 user agents
        top_uas = ua_priorities[:min(3, len(ua_priorities))]
        if not top_uas:
            return self._get_fallback_user_agent()
        
        # Weighted selection
        weights = [score for _, score, _ in top_uas]
        total_weight = sum(weights)
        
        if total_weight == 0:
            return random.choice([ua for ua, _, _ in top_uas])
        
        r = random.uniform(0, total_weight)
        cumulative = 0
        for ua, score, _ in top_uas:
            cumulative += score
            if r <= cumulative:
                return ua
        
        return top_uas[0][0]  # Fallback to highest priority
    
    def _get_fallback_user_agent(self):
        """Fallback user agent if none available"""
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    
    def record_success(self, user_agent):
        """Record successful request"""
        if user_agent not in self.ua_stats["user_agents"]:
            self.ua_stats["user_agents"][user_agent] = {
                "requests": 0,
                "blocks": 0,
                "success_rate": 100.0,
                "last_blocked": None,
                "consecutive_blocks": 0
            }
        
        stats = self.ua_stats["user_agents"][user_agent]
        stats["requests"] += 1
        stats["consecutive_blocks"] = 0  # Reset consecutive blocks
        
        # Update success rate
        if stats["requests"] > 0:
            stats["success_rate"] = ((stats["requests"] - stats["blocks"]) / stats["requests"]) * 100
        
        # Update global stats
        self.ua_stats["global_stats"]["total_requests"] += 1
        total_requests = self.ua_stats["global_stats"]["total_requests"]
        total_blocks = self.ua_stats["global_stats"]["total_blocks"]
        if total_requests > 0:
            self.ua_stats["global_stats"]["success_rate"] = ((total_requests - total_blocks) / total_requests) * 100
        
        self._save_ua_stats()
    
    def record_block(self, user_agent):
        """Record blocked request"""
        if user_agent not in self.ua_stats["user_agents"]:
            self.ua_stats["user_agents"][user_agent] = {
                "requests": 0,
                "blocks": 0,
                "success_rate": 100.0,
                "last_blocked": None,
                "consecutive_blocks": 0
            }
        
        stats = self.ua_stats["user_agents"][user_agent]
        stats["requests"] += 1
        stats["blocks"] += 1
        stats["last_blocked"] = datetime.now().isoformat()
        stats["consecutive_blocks"] += 1
        
        # Update success rate
        if stats["requests"] > 0:
            stats["success_rate"] = ((stats["requests"] - stats["blocks"]) / stats["requests"]) * 100
        
        # Update global stats
        self.ua_stats["global_stats"]["total_requests"] += 1
        self.ua_stats["global_stats"]["total_blocks"] += 1
        total_requests = self.ua_stats["global_stats"]["total_requests"]
        total_blocks = self.ua_stats["global_stats"]["total_blocks"]
        if total_requests > 0:
            self.ua_stats["global_stats"]["success_rate"] = ((total_requests - total_blocks) / total_requests) * 100
        
        self._save_ua_stats()
    
    def get_stats_summary(self):
        """Get statistics summary"""
        total_uas = len(self.ua_stats["user_agents"])
        blocked_uas = sum(1 for stats in self.ua_stats["user_agents"].values() if stats["blocks"] > 0)
        
        return {
            "total_user_agents": total_uas,
            "blocked_user_agents": blocked_uas,
            "global_success_rate": self.ua_stats["global_stats"]["success_rate"],
            "total_requests": self.ua_stats["global_stats"]["total_requests"],
            "total_blocks": self.ua_stats["global_stats"]["total_blocks"]
        }

class EnhancedRequestHandler:
    """
    Enhanced HTTP request handler with anti-block features
    """
    
    def __init__(self, language=None, max_retries=5, base_delay=1.0):
        self.language = language
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.ua_manager = UserAgentManager(language)
        self.session = None
        self._setup_session()
        
        # Patterns to detect blocking
        self.block_patterns = [
            "blocked", "forbidden", "access denied", "rate limited",
            "too many requests", "captcha", "robot", "bot detected",
            "suspicious activity", "temporarily unavailable"
        ]
        
        # Status codes indicating blocking
        self.block_status_codes = [403, 429, 503, 509, 999]
        
    def _setup_session(self):
        """Setup session with connection pooling"""
        self.session = requests.Session()
        
        # Setup retry strategy for connection errors
        retry_strategy = Retry(
            total=0,  # We handle retry manually
            backoff_factor=0,
            status_forcelist=[],
            allowed_methods=["GET", "POST"]
        )
        
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=20,
            pool_maxsize=100
        )
        
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
    
    def _is_blocked_response(self, response):
        """
        Check if response indicates blocking
        """
        if not response:
            return False
            
        # Check status code
        if response.status_code in self.block_status_codes:
            return True
        
        # Check content for blocking patterns
        try:
            content_lower = response.text.lower()
            for pattern in self.block_patterns:
                if pattern in content_lower:
                    return True
        except:
            pass
        
        # Check headers for rate limiting
        if 'retry-after' in response.headers:
            return True
            
        if 'x-ratelimit-remaining' in response.headers:
            try:
                remaining = int(response.headers['x-ratelimit-remaining'])
                if remaining <= 0:
                    return True
            except:
                pass
        
        return False
    
    def _calculate_delay(self, attempt, is_blocked=False):
        """
        Calculate delay for retry with exponential backoff
        """
        if is_blocked:
            # Longer delay if blocking detected
            base = self.base_delay * 3
        else:
            base = self.base_delay
        
        # Exponential backoff with jitter
        delay = base * (2 ** attempt) + random.uniform(0, 1)
        
        # Cap maximum delay
        return min(delay, 60.0)
    
    def _get_request_headers(self, user_agent=None, additional_headers=None):
        """
        Generate headers for request
        """
        if not user_agent:
            user_agent = self.ua_manager.get_prioritized_user_agent()
        
        headers = {
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,id;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            # Additional to avoid bot detection
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Cache-Control": "max-age=0"
        }
        
        if additional_headers:
            headers.update(additional_headers)
        
        return headers
    
    def make_request(self, url, method="GET", headers=None, timeout=15, **kwargs):
        """
        Make request with automatic retry and user agent rotation
        
        Args:
            url (str): Target URL
            method (str): HTTP method
            headers (dict): Additional headers
            timeout (int): Request timeout
            **kwargs: Additional arguments for requests
            
        Returns:
            requests.Response or None if failed
        """
        last_user_agent = None
        last_error = None
        
        for attempt in range(self.max_retries):
            try:
                # Get new user agent for each attempt
                current_ua = self.ua_manager.get_prioritized_user_agent()
                request_headers = self._get_request_headers(current_ua, headers)
                
                # Log attempt
                if attempt > 0:
                    print(f"🔄 Retry attempt {attempt + 1}/{self.max_retries} for {url[:50]}...")
                    print(f"   Using UA: {current_ua[:50]}...")
                
                # Make request
                response = self.session.request(
                    method=method,
                    url=url,
                    headers=request_headers,
                    timeout=timeout,
                    **kwargs
                )
                
                # Check if response is successful
                if response.status_code == 200 and not self._is_blocked_response(response):
                    # Record success
                    self.ua_manager.record_success(current_ua)
                    return response
                
                # Check if response is blocked
                elif self._is_blocked_response(response):
                    print(f"🚫 Blocked response detected (Status: {response.status_code})")
                    self.ua_manager.record_block(current_ua)
                    last_user_agent = current_ua
                    
                    # Longer delay for blocking
                    if attempt < self.max_retries - 1:
                        delay = self._calculate_delay(attempt, is_blocked=True)
                        print(f"⏳ Waiting {delay:.1f}s before retry with different UA...")
                        time.sleep(delay)
                        continue
                
                else:
                    # Other status codes (404, 500, etc)
                    # print(f"❌ HTTP {response.status_code} for {url[:50]}")
                    if response.status_code < 500:
                        # Client error, no need to retry
                        return response
                    
                    # Server error, try retry
                    if attempt < self.max_retries - 1:
                        delay = self._calculate_delay(attempt, is_blocked=False)
                        time.sleep(delay)
                        continue
                
            except requests.exceptions.Timeout:
                print(f"⏰ Timeout for {url[:50]}")
                last_error = "Timeout"
                if attempt < self.max_retries - 1:
                    delay = self._calculate_delay(attempt, is_blocked=False)
                    time.sleep(delay)
                    continue
                    
            except requests.exceptions.ConnectionError:
                print(f"🌐 Connection error for {url[:50]}")
                last_error = "Connection error"
                if attempt < self.max_retries - 1:
                    delay = self._calculate_delay(attempt, is_blocked=False)
                    time.sleep(delay)
                    continue
                    
            except Exception as e:
                print(f"❌ Unexpected error for {url[:50]}: {str(e)}")
                last_error = str(e)
                if attempt < self.max_retries - 1:
                    delay = self._calculate_delay(attempt, is_blocked=False)
                    time.sleep(delay)
                    continue
        
        # All attempts failed
        print(f"💥 All {self.max_retries} attempts failed for {url[:50]}")
        if last_user_agent:
            print(f"   Last blocked UA: {last_user_agent[:50]}...")
        if last_error:
            print(f"   Last error: {last_error}")
        
        return None
    
    def get_stats(self):
        """Get request handler statistics"""
        return self.ua_manager.get_stats_summary()
    
    def close(self):
        """Close session"""
        if self.session:
            self.session.close()

def get_request_handler(language=None):
    """
    Get global request handler instance
    """
    global _request_handler
    if _request_handler is None:
        _request_handler = EnhancedRequestHandler(language)
    return _request_handler

def cleanup_request_handler():
    """
    Cleanup global request handler
    """
    global _request_handler
    if _request_handler:
        _request_handler.close()
        _request_handler = None

def setup_logging(log_dir=None, language=None):
    """
    Setup logging to file and console
    
    Args:
        log_dir (str): Directory for log files
        language (str): Language to use for logs
        
    Returns:
        logging.Logger: Logger object
    """    
    if log_dir is None:
        log_dir = get_keywords_logs_path(language)
    
    os.makedirs(log_dir, exist_ok=True)
    
    log_file = os.path.join(log_dir, f"kw_search_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    
    # Configure logging
    logger = logging.getLogger('keyword_search')
    logger.setLevel(logging.INFO)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_format = logging.Formatter('%(message)s')
    console_handler.setFormatter(console_format)
    
    # File handler
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_format)
    
    # Add handlers to logger
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    
    logger.info(f"Log file created at: {log_file}")
    return logger

def get_active_language():
    """
    Get the active language from language_default.txt or default to 'english'
    
    Returns:
        str: Language name
    """
    global _language_message_shown
    
    # Check if language is already cached
    if hasattr(get_active_language, 'cached_language'):
        return get_active_language.cached_language

    # Default language
    active_language = "english"

    try:
        # Get base directory path
        base_dir = get_base_dir()
        
        # Path to language.txt in config folder
        lang_file = os.path.join(base_dir, "config", "language.txt")
        
        if os.path.exists(lang_file):
            with open(lang_file, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    active_language = content.strip('" ,\n\t')
    except Exception as e:
        print(f"Error reading language file: {e}")
    
    # Validate the language value (fallback to default if invalid)
    if not active_language or not re.match(r"^[a-zA-Z\-]+$", active_language):
        print(f"Invalid language format in language_default.txt. Falling back to default: 'english'")
        active_language = "english"

    # Cache the value
    get_active_language.cached_language = active_language

    # Show message only once
    if not _language_message_shown:
        print(f"Active language set to: {active_language}")
        _language_message_shown = True

    return active_language

def set_active_language(language):
    """
    Set the active language
    
    Args:
        language (str): Language name
    """
    global _language_message_shown
    
    # Update cache directly
    get_active_language.cached_language = language
    
    # Reset the message shown flag if language changes
    _language_message_shown = False
    
    # Now get_active_language() will show the message once
    get_active_language()
    
    # Update language_default.txt
    try:
        kw_path = get_kw_path()
        os.makedirs(kw_path, exist_ok=True)
        lang_file = os.path.join(kw_path, "language_default.txt")
        with open(lang_file, "w", encoding="utf-8") as f:
            f.write(f'"language": "{language}"')
    except Exception as e:
        print(f"Error saving language setting: {e}")

def get_language_path(language=None):
    """
    Get path to language directory
    
    Args:
        language (str): Language name, or None to use active language
        
    Returns:
        str: Path to language directory
    """
    if language is None:
        language = get_active_language()
    
    base_dir = get_base_dir()
    language_path = os.path.join(base_dir, "languages", language)
    
    # Check if language path exists, fallback to default if not
    if not os.path.exists(language_path):
        language_path = os.path.join(base_dir, "languages", "default")
        if not os.path.exists(language_path):
            os.makedirs(language_path)
    
    return language_path

def get_kw_path(language=None):
    """Get path to kw directory"""
    language_path = get_language_path(language)
    return os.path.join(language_path, "kw")

def get_keywords_path(language=None):
    """Get path to keywords directory"""
    language_path = get_language_path(language)
    return os.path.join(language_path, "keywords")

def get_keywords_niche_path(niche=None, language=None):
    """Get path to keywords/niche directory"""
    if niche is None:
        # Read niche from file
        niche_file = os.path.join(get_kw_path(language), "niche.txt")
        if os.path.exists(niche_file):
            with open(niche_file, "r", encoding="utf-8") as f:
                niche = f.read().strip()
        else:
            niche = "general"  # Default niche if niche.txt doesn't exist
    
    return os.path.join(get_keywords_path(language), niche)

def clear_removed_keywords_files(language=None):
    """
    Clear all removed_keywords.txt files for all niches at the start of script execution
    """
    try:
        keywords_base_path = get_keywords_path(language)
        if not os.path.exists(keywords_base_path):
            return
        
        niches = get_active_niches(language)
        cleared_count = 0
        
        for niche in niches:
            niche_dir = os.path.join(keywords_base_path, niche)
            removed_file = os.path.join(niche_dir, "removed_keywords.txt")
            
            if os.path.exists(removed_file):
                # Clear the file by writing empty content
                with open(removed_file, 'w', encoding='utf-8') as f:
                    f.write("")
                cleared_count += 1
                print(f"🧹 Cleared removed_keywords.txt for niche: {niche}")
        
        if cleared_count > 0:
            print(f"✅ Cleared {cleared_count} removed_keywords.txt files")
        else:
            print("ℹ️ No removed_keywords.txt files found to clear")
            
    except Exception as e:
        print(f"⚠️ Error clearing removed_keywords.txt files: {e}")

def force_inject_niche_into_keywords(keywords, current_niche, niche_terms, language):
    """
    Force inject niche terms into keywords that don't contain them using AI
    This ensures we always have keywords with niche relevance
    
    Args:
        keywords (list): List of keywords to process
        current_niche (str): Current active niche
        niche_terms (list): List of niche terms
        language (str): Target language
        
    Returns:
        list: Keywords with niche terms injected
    """
    if not keywords or not current_niche:
        return keywords
    
    # Separate keywords that already have niche and those that don't
    with_niche = []
    without_niche = []
    
    for kw in keywords:
        if any(term.lower() in kw.lower() for term in niche_terms):
            with_niche.append(kw)
        else:
            without_niche.append(kw)
    
    print(f"📊 Keywords analysis: {len(with_niche)} already have niche, {len(without_niche)} need injection")
    
    if not without_niche:
        print("✅ All keywords already contain niche terms")
        return keywords
    
    # Use AI to inject niche naturally
    manager = AITokenManager()
    if not manager.authenticate():
        print("⚠️ AI authentication failed. Using manual injection.")
        # Manual fallback: inject niche at the beginning
        injected = []
        for kw in without_niche:
            injected.append(f"{current_niche} {kw}")
        return with_niche + injected
    
    client = manager.client
    
    # Process in batches to avoid token limits
    batch_size = 20
    all_injected = []
    
    for i in range(0, len(without_niche), batch_size):
        batch = without_niche[i:i+batch_size]
        
        prompt = f"""You are an expert SEO keyword researcher. Your task is to naturally incorporate the niche term "{current_niche}" into each keyword while maintaining search intent and readability.

CRITICAL RULES:
1. EVERY keyword MUST contain "{current_niche}" after modification
2. Place the niche term in the most natural position for {language} language
3. Maintain the original search intent of each keyword
4. Keep keywords between 3-6 words
5. Make it sound natural for human searchers

Keywords to modify:
{json.dumps(batch, ensure_ascii=False)}

Respond with a JSON array of modified keywords in the same order. Each keyword MUST contain "{current_niche}".
Example format: ["modified keyword 1", "modified keyword 2"]"""

        try:
            response = client.chat.completions.create(
                model=manager.model_name,
                messages=[
                    {"role": "system", "content": "You are an expert SEO and language assistant. Always ensure niche terms are naturally incorporated."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=600,
                response_format={"type": "json_object"}
            )
            
            ai_reply = response.choices[0].message.content.strip()
            
            # Extract JSON array
            json_start = ai_reply.find('[')
            json_end = ai_reply.rfind(']') + 1
            
            if json_start >= 0 and json_end > json_start:
                injected_batch = json.loads(ai_reply[json_start:json_end])
                
                # Validate each keyword contains the niche
                validated_batch = []
                for orig, injected in zip(batch, injected_batch):
                    if current_niche.lower() in injected.lower():
                        validated_batch.append(injected)
                        print(f"✅ Injected: '{orig}' → '{injected}'")
                    else:
                        # Manual fallback if AI failed
                        manual_inject = f"{current_niche} {orig}"
                        validated_batch.append(manual_inject)
                        print(f"🔧 Manual injection: '{orig}' → '{manual_inject}'")
                
                all_injected.extend(validated_batch)
            else:
                print(f"⚠️ AI returned invalid JSON for batch {i//batch_size + 1}")
                # Manual fallback for entire batch
                manual_batch = [f"{current_niche} {kw}" for kw in batch]
                all_injected.extend(manual_batch)
                
        except Exception as e:
            print(f"❌ AI injection failed for batch {i//batch_size + 1}: {e}")
            # Manual fallback for entire batch
            manual_batch = [f"{current_niche} {kw}" for kw in batch]
            all_injected.extend(manual_batch)
    
    print(f"✅ Niche injection complete: {len(all_injected)} keywords processed")
    return with_niche + all_injected

def get_active_niches(language=None):
    """Get all active niches from niche.txt file"""
    niche_file = os.path.join(get_kw_path(language), "niche.txt")
    niches = []
    
    if os.path.exists(niche_file):
        with open(niche_file, "r", encoding="utf-8") as f:
            for line in f:
                niche = line.strip()
                if niche:  # Only add non-empty niches
                    niches.append(niche)
    
    if not niches:
        # Default niche if file is empty or doesn't exist
        niches = ["general"]
    
    return niches

def get_keywords_cache_path(language=None):
    """Get path to keywords/_cache directory"""
    return os.path.join(get_keywords_path(language), "_cache")

def get_keywords_logs_path(language=None):
    """Get path to keywords/logs directory"""
    return os.path.join(get_keywords_path(language), "logs")

def ensure_directory_structure(language=None):
    """Ensure all required directories exist"""
    if language is None:
        language = get_active_language()
    
    base_dir = get_base_dir()
    
    # Create common directories
    dirs_to_create = [
        os.path.join(base_dir, "languages", language, "kw"),
        os.path.join(base_dir, "languages", language, "keywords", "_cache"),
        os.path.join(base_dir, "languages", language, "keywords", "logs")
    ]
    
    # Add niche directories
    niches = get_active_niches(language)
    for niche in niches:
        dirs_to_create.append(os.path.join(base_dir, "languages", language, "keywords", niche))
    
    for directory in dirs_to_create:
        try:
            os.makedirs(directory, exist_ok=True)
        except Exception as e:
            print(f"Error creating directory {directory}: {e}")

def remove_deleted_niche_folders(language=None):
        """
        Remove niche folders in keywords/ that are no longer listed in niche.txt
        """
        keywords_base = get_keywords_path(language)
        if not os.path.exists(keywords_base):
            return
    
        # Get the list of niches from niche.txt
        active_niches = set(get_active_niches(language))
        # Get all folders in keywords/
        for folder in os.listdir(keywords_base):
            folder_path = os.path.join(keywords_base, folder)
            if os.path.isdir(folder_path) and folder not in active_niches and not folder.startswith("_"):
                try:
                    shutil.rmtree(folder_path)
                    print(f"🗑️ Niche folder '{folder}' deleted because it is not in niche.txt")
                except Exception as e:
                    print(f"⚠️ Failed to delete niche folder '{folder}': {e}")

def get_last_processed_niche(language=None):
    """Get the last processed niche from tracking file"""
    tracking_file = os.path.join(get_kw_path(language), "last_processed_niche.txt")
    if os.path.exists(tracking_file):
        with open(tracking_file, "r", encoding="utf-8") as f:
            return f.read().strip()
    return None

def update_last_processed_niche(niche, language=None):
    """Update the last processed niche in tracking file"""
    tracking_file = os.path.join(get_kw_path(language), "last_processed_niche.txt")
    with open(tracking_file, "w", encoding="utf-8") as f:
        f.write(niche)

def robust_request(url, headers=None, timeout=10, max_retries=3, backoff_factor=0.5):
    """
    Enhanced HTTP request handler dengan anti-block features
    
    Args:
        url (str): URL to request
        headers (dict): HTTP headers
        timeout (int): Request timeout in seconds
        max_retries (int): Maximum retry attempts (akan diabaikan, menggunakan setting dari EnhancedRequestHandler)
        backoff_factor (float): Backoff factor (akan diabaikan)
        
    Returns:
        requests.Response or None if failed
    """
    if not validate_url(url):
        print(f"Invalid URL: {url}")
        return None
    
    handler = get_request_handler(language=get_active_language())
    
    try:
        # Merge additional headers if provided
        additional_headers = headers if headers else {}
        
        response = handler.make_request(
            url=url,
            headers=additional_headers,
            timeout=timeout
        )
        
        if response and response.status_code == 200:
            return response
        else:
            log_info(f"Request failed for {url[:50]}... Status: {response.status_code if response else 'None'}")
            return response  # Return response even if not 200 for error handling
            
    except Exception as e:
        log_info(f"Enhanced request error for {url[:50]}...: {str(e)}")
        return None

class RateLimiter:
    """
    Request rate regulator with adaptive backoff
    """
    def __init__(self, calls_limit=300, time_period=60, initial_backoff=0.3, max_backoff=10):
        self.calls_limit = calls_limit
        self.time_period = time_period
        self.timestamps = []
        self.initial_backoff = initial_backoff
        self.max_backoff = max_backoff
        self.current_backoff = initial_backoff
        self.consecutive_waits = 0
    
    def wait_if_needed(self):
        """
        Wait if necessary with adaptive backoff
        """
        now = time.time()
        # Remove old timestamps
        self.timestamps = [ts for ts in self.timestamps if now - ts < self.time_period]
        
        if len(self.timestamps) >= self.calls_limit:
            oldest = self.timestamps[0]
            sleep_time = self.time_period - (now - oldest) + self.current_backoff
            if sleep_time > 0:
                print(f"Rate limit reached. Waiting for {sleep_time:.2f} seconds...")
                time.sleep(sleep_time)
                # Increase backoff for consecutive waits
                self.consecutive_waits += 1
                if self.consecutive_waits > 3:
                    self.current_backoff = min(self.current_backoff * 1.5, self.max_backoff)
        else:
            # Reset backoff when not hitting limits
            self.consecutive_waits = 0
            self.current_backoff = self.initial_backoff
        
        self.timestamps.append(time.time())

class AITokenManager:
    def __init__(self, base_path=None, model_name="gpt-4o", endpoint="https://models.inference.ai.azure.com"):
        self.base_path = base_path or os.getcwd()
        self.token_rotation_threshold = 12
        self.tokens = []
        self.current_token_index = 0
        self.model_name = model_name
        self.endpoint = endpoint
        self.article_count = 0
        self.client = None
        self.tokens_loaded = False
        self.token_last_used_file = os.path.join(self.base_path, "token", "last_used.json")
        self.token_status_cache = {} 
        self.last_validation_time = 0
        self.validation_cache_duration = 36000
        self.failed_tokens = set()
        self._auth_notif_shown = False
        self.token_manager = TokenManager(self.base_path)

    def load_tokens(self):
        if self.tokens_loaded:
            return True

        token_file = os.path.join(self.base_path, "token", "tokens.txt")
        if not os.path.exists(token_file):
            print("❌ tokens.txt file not found.")
            return False

        with open(token_file, "r", encoding="utf-8") as f:
            tokens = []
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    decrypted = self.token_manager.encryptor.decrypt_token(line)
                    if decrypted and decrypted.startswith("ghp_"):
                        tokens.append(decrypted)

        if not tokens:
            print("⚠️ No valid tokens found.")
            return False

        if len(tokens) > 10:
            print(f"⚠️ {len(tokens)} tokens found. Only the first 10 will be used.")
            tokens = tokens[:10]

        self.tokens = tokens
        self.tokens_loaded = True
        
        # Initialize token status cache
        for i, token in enumerate(tokens):
            if i not in self.token_status_cache:
                self.token_status_cache[i] = {
                    'valid': None,  # None = unknown, True = valid, False = invalid
                    'last_check': 0,
                    'error_count': 0
                }
        
        return True

    def _is_token_cached_valid(self, token_index):
        """Check if token is cached as valid and cache is still fresh"""
        current_time = time.time()
        cache_info = self.token_status_cache.get(token_index, {})
        
        # Return cached status if it's fresh and valid
        if (cache_info.get('valid') is True and 
            current_time - cache_info.get('last_check', 0) < self.validation_cache_duration):
            return True
        return False

    def _mark_token_status(self, token_index, is_valid, error_msg=None):
        """Mark token status in cache"""
        current_time = time.time()
        if token_index not in self.token_status_cache:
            self.token_status_cache[token_index] = {}
            
        cache_info = self.token_status_cache[token_index]
        cache_info['valid'] = is_valid
        cache_info['last_check'] = current_time
        
        if not is_valid:
            cache_info['error_count'] = cache_info.get('error_count', 0) + 1
            self.failed_tokens.add(token_index)
            if error_msg:
                print(f"❌ Token #{token_index + 1} marked as invalid: {error_msg}")
        else:
            cache_info['error_count'] = 0
            self.failed_tokens.discard(token_index)

    def auto_encrypt_tokens_on_exit(self):
        """Automatically encrypt tokens when application exits"""
        try:
            # Ensure all tokens in file are encrypted
            self.token_manager.migrate_existing_tokens()
            print("✅ Auto-encryption completed on exit")
        except Exception as e:
            print(f"❌ Error during auto-encryption: {str(e)}")

    def get_current_token(self):
        # Increment article count and rotate if needed
        if self.article_count >= self.token_rotation_threshold:
            self.article_count = 0
            old_index = self.current_token_index
            
            # Find next valid token (skip known failed tokens)
            attempts = 0
            while attempts < len(self.tokens):
                next_index = (self.current_token_index + 1) % len(self.tokens)
                
                # Skip failed tokens unless all are failed
                if next_index not in self.failed_tokens or len(self.failed_tokens) >= len(self.tokens):
                    self.current_token_index = next_index
                    break
                else:
                    self.current_token_index = next_index
                    attempts += 1
            
            if self.current_token_index != old_index:
                print(f"🔄 Switching to token #{self.current_token_index + 1}")
                self.client = None  # Force re-authentication

        return self.tokens[self.current_token_index]

    def _quick_token_test(self, client):
        """Perform minimal token test to save quota"""
        try:
            # Use minimal token test with very short response
            response = client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "user", "content": "hi"}
                ],
                max_tokens=1,  # Minimal tokens
                temperature=0
            )
            return True
        except Exception as e:
            return False

    def authenticate(self):
        # Check if we have a cached valid authentication
        if (self.client and 
            self._is_token_cached_valid(self.current_token_index)):
            print(f"✅ Using cached authentication for token #{self.current_token_index + 1} (valid for {self.validation_cache_duration/3600:.1f} hours)")
            return True
    
        # Check last used file for recent authentication
        if os.path.exists(self.token_last_used_file):
            try:
                with open(self.token_last_used_file, "r", encoding="utf-8") as f:
                    last_used_data = json.load(f)
                    last_used_time = last_used_data.get("last_used_time", 0)
                    last_token_index = last_used_data.get("token_index", -1)
                    
                    # Calculate time since last authentication
                    time_since_auth = time.time() - last_used_time
                    hours_since_auth = time_since_auth / 3600
                    
                    # If recent (within 24 hours) and same token, reuse authentication
                    if (time_since_auth < 86400 and  # 24 hours
                        last_token_index == self.current_token_index):
                        
                        # Recreate client with cached token
                        if self.current_token_index < len(self.tokens):
                            token = self.tokens[self.current_token_index]
                            self.client = OpenAI(base_url=self.endpoint, api_key=token)
                            
                            # Mark as valid in cache
                            self._mark_token_status(self.current_token_index, True)
                            
                            print(f"✅ Reusing 24h authentication cache for token #{self.current_token_index + 1}")
                            print(f"   Last authenticated: {hours_since_auth:.1f} hours ago")
                            return True
                        else:
                            print(f"⚠️ Cached token index {last_token_index} out of range, re-authenticating...")
                    else:
                        if time_since_auth >= 86400:
                            print(f"ℹ️ Authentication cache expired ({hours_since_auth:.1f} hours old), re-authenticating...")
                        elif last_token_index != self.current_token_index:
                            print(f"ℹ️ Token changed from #{last_token_index + 1} to #{self.current_token_index + 1}, re-authenticating...")
            except Exception as e:
                print(f"⚠️ Error reading authentication cache: {str(e)}")
    
        if not self.load_tokens():
            return False
    
        # Clear any stale cache entries
        current_time = time.time()
        for token_idx in list(self.token_status_cache.keys()):
            cache_info = self.token_status_cache[token_idx]
            if current_time - cache_info.get('last_check', 0) > self.validation_cache_duration:
                cache_info['valid'] = None  # Reset to unknown
                print(f"🔄 Reset stale cache for token #{token_idx + 1}")
    
        # Try current token first if it's cached as valid and not expired
        if self._is_token_cached_valid(self.current_token_index):
            try:
                token = self.tokens[self.current_token_index]
                self.client = OpenAI(base_url=self.endpoint, api_key=token)
                print(f"✅ Using memory-cached valid token #{self.current_token_index + 1}.")
                return True
            except Exception as e:
                self._mark_token_status(self.current_token_index, False, str(e))
    
        # Full authentication process (only when cache is invalid/expired)
        print("🔑 Starting fresh authentication process...")
        tried_tokens = 0
        max_tokens = len(self.tokens)
    
        # Sort tokens by preference (valid cached first, then unknown, then failed)
        token_priorities = []
        for i in range(len(self.tokens)):
            cache_info = self.token_status_cache.get(i, {})
            if cache_info.get('valid') is True:
                priority = 0  # Highest priority
            elif cache_info.get('valid') is None:
                priority = 1  # Medium priority
            else:
                priority = 2 + cache_info.get('error_count', 0)  # Lower priority based on error count
            token_priorities.append((priority, i))
        
        # Sort by priority
        token_priorities.sort()
    
        for priority, token_index in token_priorities:
            if tried_tokens >= max_tokens:
                break
                
            # Skip if we've tried too many failed tokens
            if priority > 5:  # Skip tokens with too many errors
                continue
                
            self.current_token_index = token_index
            token = self.tokens[token_index]
            
            try:
                print(f"🔍 Testing token #{token_index + 1}...")
                self.client = OpenAI(base_url=self.endpoint, api_key=token)
                
                # Quick validation test
                if self._quick_token_test(self.client):
                    if not self._auth_notif_shown:
                        print(f"✅ Authentication successful with token #{token_index + 1}.")
                        self._auth_notif_shown = True
                        
                    self._mark_token_status(token_index, True)
                    
                    # Save successful authentication with current timestamp
                    try:
                        auth_data = {
                            "last_used_time": time.time(),
                            "token_index": token_index,
                            "auth_timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                        }
                        
                        # Ensure directory exists
                        os.makedirs(os.path.dirname(self.token_last_used_file), exist_ok=True)
                        
                        with open(self.token_last_used_file, "w", encoding="utf-8") as f:
                            json.dump(auth_data, f, indent=2)
                        print(f"💾 Authentication cached for 24 hours")
                    except Exception as cache_error:
                        print(f"⚠️ Could not save auth cache: {str(cache_error)}")
                        
                    return True
                else:
                    raise Exception("Token validation failed")
                    
            except Exception as e:
                self._mark_token_status(token_index, False, str(e))
                self.client = None
                tried_tokens += 1
    
        print("❌ All available tokens failed authentication.")
        return False

    def increment_article_count(self):
        self.article_count += 1
        if self.article_count >= self.token_rotation_threshold:
            print(f"ℹ️ Article count reached {self.token_rotation_threshold}, preparing to rotate token.")

    def get_token_stats(self):
        """Get statistics about token usage"""
        stats = {
            'total_tokens': len(self.tokens),
            'current_token': self.current_token_index + 1,
            'failed_tokens': len(self.failed_tokens),
            'valid_cached_tokens': sum(1 for cache in self.token_status_cache.values() 
                                     if cache.get('valid') is True),
            'article_count': self.article_count,
            'threshold': self.token_rotation_threshold
        }
        return stats

class KeywordCache:
    """
    Stores keyword search results with LRU eviction and compression
    """
    def __init__(self, cache_dir=None, language=None, max_size_mb=500, compression_level=5):
        if cache_dir is None:
            self.cache_dir = get_keywords_cache_path(language)
        else:
            self.cache_dir = cache_dir
        os.makedirs(self.cache_dir, exist_ok=True)
        self.max_size_mb = max_size_mb
        self.compression_level = compression_level
        self.memory_cache = {}  # In-memory cache for faster access
        self.memory_cache_size = 100  # Maximum items in memory
    
    def _get_cache_key(self, params):
        """Generate hash key from search parameters"""
        param_str = json.dumps(params, sort_keys=True)
        return hashlib.md5(param_str.encode()).hexdigest()
    
    def get(self, params):
        """
        Get results from cache with in-memory first approach
        """
        cache_key = self._get_cache_key(params)
        
        # First check in-memory cache
        if cache_key in self.memory_cache:
            return self.memory_cache[cache_key]
        
        # Then check file cache
        cache_file = os.path.join(self.cache_dir, f"{cache_key}.pkl.gz")
        standard_cache_file = os.path.join(self.cache_dir, f"{cache_key}.pkl")
        
        # Try compressed cache first
        if os.path.exists(cache_file):
            if time.time() - os.path.getmtime(cache_file) < 60 * 60 * 24:
                try:
                    import gzip
                    with gzip.open(cache_file, 'rb') as f:
                        data = pickle.load(f)
                        # Update in-memory cache
                        if len(self.memory_cache) >= self.memory_cache_size:
                            # Remove oldest item if full
                            oldest_key = next(iter(self.memory_cache))
                            del self.memory_cache[oldest_key]
                        self.memory_cache[cache_key] = data
                        return data
                except Exception as e:
                    print(f"Error reading compressed cache: {e}")
        
        # Try standard cache as fallback
        elif os.path.exists(standard_cache_file):
            if time.time() - os.path.getmtime(standard_cache_file) < 60 * 60 * 24:
                try:
                    with open(standard_cache_file, 'rb') as f:
                        data = pickle.load(f)
                        # Update in-memory cache
                        if len(self.memory_cache) >= self.memory_cache_size:
                            oldest_key = next(iter(self.memory_cache))
                            del self.memory_cache[oldest_key]
                        self.memory_cache[cache_key] = data
                        return data
                except Exception as e:
                    print(f"Error reading standard cache: {e}")
        
        return None
    
    def set(self, params, data):
        """
        Save results to cache with compression
        """
        cache_key = self._get_cache_key(params)
        cache_file = os.path.join(self.cache_dir, f"{cache_key}.pkl.gz")
        
        try:
            # Add to memory cache first
            if len(self.memory_cache) >= self.memory_cache_size:
                oldest_key = next(iter(self.memory_cache))
                del self.memory_cache[oldest_key]
            self.memory_cache[cache_key] = data
            
            # Save to compressed file cache
            try:
                import gzip
                with gzip.open(cache_file, 'wb', compresslevel=self.compression_level) as f:
                    pickle.dump(data, f)
            except ImportError:
                # Fallback if gzip not available
                standard_cache_file = os.path.join(self.cache_dir, f"{cache_key}.pkl")
                with open(standard_cache_file, 'wb') as f:
                    pickle.dump(data, f)
            
            # Limit cache size after saving
            self._limit_cache_size()
        except Exception as e:
            print(f"Error saving cache: {e}")
    
    def _limit_cache_size(self):
        """
        Limit total cache size with LRU eviction policy
        """
        if not os.path.exists(self.cache_dir):
            return
            
        # Convert to bytes
        max_size_bytes = self.max_size_mb * 1024 * 1024
        
        # Get all files with their modification time
        files = []
        total_size = 0
        
        for filename in os.listdir(self.cache_dir):
            file_path = os.path.join(self.cache_dir, filename)
            if os.path.isfile(file_path):
                file_size = os.path.getsize(file_path)
                mod_time = os.path.getmtime(file_path)
                files.append((file_path, mod_time, file_size))
                total_size += file_size
        
        # Sort by modification time (oldest first)
        files.sort(key=lambda x: x[1])
        
        # Remove oldest files until under size limit
        removed_count = 0
        while total_size > max_size_bytes and files:
            oldest_file, _, file_size = files.pop(0)
            try:
                os.remove(oldest_file)
                total_size -= file_size
                removed_count += 1
            except Exception as e:
                print(f"Error removing {oldest_file}: {e}")
        
        if removed_count > 0:
            print(f"Removed {removed_count} oldest cache files to maintain size limit")

def fix_keyword_grammar_with_ai(keywords, language, niche_terms=None):
    """
    Fix keyword word order to match proper grammar and readability using AI (GPT-4o).
    """
    if not keywords:
        return []

    manager = AITokenManager()
    if not manager.authenticate():
        print("⚠️ AI authentication failed. Keyword grammar will not be fixed.") 
        return keywords

    client = manager.client

    # Construct niche instruction and validation rules
    if niche_terms:
        niche_str = ", ".join([f'"{term}"' for term in niche_terms])
        niche_instruction = f"""
        CRITICAL VALIDATION RULES:
        1. Keywords MUST contain at least one of these niche terms: {niche_str}
        2. Keep original niche terms unchanged (don't modify/translate them)
        3. Only fix word order if really needed
        4. Do not add or remove words except for natural grammar fixes
        5. Keep any technical terms related to the niche unchanged
        6. If a keyword doesn't contain niche terms, try to naturally incorporate one
        """
    else:
        niche_instruction = "Only fix word order if really needed, do not add or remove words."

    prompt = f"""Fix these keywords in {language} to be more natural while preserving meaning.
    {niche_instruction}
    
    Reply with JSON array of fixed keywords only.
    Input keywords: {json.dumps(keywords, ensure_ascii=False)}
    """

    try:
        response = client.chat.completions.create(
            model=manager.model_name,
            messages=[
                {"role": "system", "content": "You are a language expert who understands niche-specific terms must be preserved."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=400,
            response_format={"type": "json_object"}
        )

        ai_reply = response.choices[0].message.content.strip()
        
        # Extract JSON array from response
        json_start = ai_reply.find('[')
        json_end = ai_reply.rfind(']') + 1
        
        if json_start >= 0 and json_end > json_start:
            fixed_keywords = json.loads(ai_reply[json_start:json_end])
            
            # Validate niche relevance after AI processing
            result = []
            for orig, fixed in zip(keywords, fixed_keywords):
                # Check if required niche terms are present
                has_niche_terms = any(term.lower() in fixed.lower() for term in niche_terms) if niche_terms else True
                
                # Check if words are reasonable (not too different)
                orig_words = set(orig.lower().split())
                fixed_words = set(fixed.lower().split())
                
                # Validation criteria - prioritize niche relevance
                if has_niche_terms:
                    # If it has niche terms, be more lenient with other checks
                    if (
                        # Either words are exactly same
                        orig_words == fixed_words or
                        # Or at least 50% words match (more lenient for niche-relevant keywords)
                        len(orig_words & fixed_words) >= len(orig_words) * 0.5
                    ):
                        result.append(fixed)
                    else:
                        result.append(orig)  # Keep original if too different
                else:
                    # If no niche terms, reject entirely or keep original
                    print(f"⚠️ Fixed keyword '{fixed}' missing niche terms, keeping original: '{orig}'")
                    result.append(orig)
                    
            # Final filter: only return keywords with niche terms
            if niche_terms:
                final_result = []
                for kw in result:
                    if any(term.lower() in kw.lower() for term in niche_terms):
                        final_result.append(kw)
                    else:
                        print(f"❌ Dropping '{kw}' - missing niche terms after grammar fix")
                return final_result
            else:
                return result
        else:
            print("⚠️ AI did not return valid JSON array.")
            return keywords
            
    except Exception as e:
        print(f"❌ Failed to fix keyword grammar with AI: {e}")
        return keywords
    
def save_keywords(keywords, niche=None, output_dir=None, language=None):
    """
    Save list of keywords to txt file in the correct niche folder
    """
    if not keywords:
        print("⚠️ No keywords to save")
        return

    keywords = [kw for kw in keywords if kw.strip()]
    if not keywords:
        print("⚠️ No valid keywords after filtering")
        return

    # Ensure we have a niche - this is critical for organization
    if niche is None:
        # Get active niches and use the first one
        niches = get_active_niches(language)
        niche = niches[0] if niches else "general"
        print(f"⚠️ No niche specified, using: {niche}")
    
    # Get niche terms and validate keywords before saving
    niche_terms = expand_niche_terms(niche)
    if niche.lower() not in [term.lower() for term in niche_terms]:
        niche_terms.insert(0, niche)
    
    # Filter keywords to ensure they contain niche terms
    relevant_keywords = []
    for kw in keywords:
        if any(term.lower() in kw.lower() for term in niche_terms):
            relevant_keywords.append(kw)
        else:
            print(f"❌ Skipping '{kw}' - doesn't contain niche terms: {', '.join(niche_terms)}")
    
    if not relevant_keywords:
        print(f"❌ No keywords contain niche terms for '{niche}'. Nothing to save.")
        return
    
    # Create niche-specific directory
    if output_dir is None:
        output_dir = os.path.join(get_keywords_path(language), niche)
    
    os.makedirs(output_dir, exist_ok=True)
    
    filepath = os.path.join(output_dir, "keywords.txt")
    
    # Create file if it doesn't exist
    if not os.path.exists(filepath):
        with open(filepath, 'w', encoding='utf-8'):
            pass
    
    with open(filepath, 'a', encoding='utf-8') as f:
        for keyword in relevant_keywords:
            f.write(f"{keyword}\n")
    clean_keywords_file(filepath)
    
    print(f"✅ {len(relevant_keywords)} niche-relevant keywords saved to: {filepath}")
    print(f"📁 Niche folder: {niche}")
    print(f"🎯 Keywords saved: {', '.join(relevant_keywords[:3])}{'...' if len(relevant_keywords) > 3 else ''}")

def validate_url(url):
    """
    Validate URL with additional security and ensure it is safe for use.

    Args:
        url (str): URL to validate.

    Returns:
        bool: True if URL is valid, False otherwise.
    """
    try:
        # Parse the URL
        result = urlparse(url)

        # Ensure the scheme is either HTTP or HTTPS
        if result.scheme not in ('http', 'https'):
            return False

        # Ensure the netloc (domain) exists
        if not result.netloc:
            return False

        # Check for dangerous characters in the URL
        dangerous_chars = ['<', '>', '"', "'", ';', '(', ')', '{', '}']
        if any(char in url for char in dangerous_chars):
            return False

        # Ensure the URL does not contain double quotes or invalid formatting
        if '"' in url or "'" in url:
            return False

        # Ensure the URL length is reasonable
        if len(url) > 2048:  # Common maximum URL length
            return False

        # URL seems valid
        return True
    except Exception as e:
        print(f"Error validating URL: {e}")
        return False

def get_random_user_agent(language=None):
    """
    Return headers with a user agent prioritized by success rate

    Args:
        language (str): Language to use

    Returns:
        dict: HTTP headers with prioritized User-Agent
    """
    handler = get_request_handler(language=language or get_active_language())
    ua = handler.ua_manager.get_prioritized_user_agent()

    headers = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1"
    }

    return headers

def generate_fresh_user_agent_with_ai(language=None):
    """
    Generate a fresh user agent using AI and save to user-agent.txt
    """
    print("🤖 Generating fresh user agent with AI...")
    
    manager = AITokenManager()
    if not manager.authenticate():
        print("⚠️ AI not available for user agent generation")
        return False

    client = manager.client
    
    prompt = """Generate 1 realistic modern user agent string for web scraping that:
1. Uses recent Chrome or Firefox version
2. Common Windows or Mac OS
3. Looks natural and not suspicious
4. Different from typical automated browser signatures

Return only the user agent string, nothing else."""

    try:
        response = client.chat.completions.create(
            model=manager.model_name,
            messages=[
                {"role": "system", "content": "You are a web scraping expert. Generate realistic user agent strings."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=150
        )
        
        new_user_agent = response.choices[0].message.content.strip()
        
        # Basic validation
        if "Mozilla" in new_user_agent and ("Chrome" in new_user_agent or "Firefox" in new_user_agent):
            # Save to user-agent.txt
            user_agent_file = os.path.join(get_kw_path(language), "user-agent.txt")
            
            # Read existing user agents
            existing_agents = []
            if os.path.exists(user_agent_file):
                with open(user_agent_file, "r", encoding="utf-8") as f:
                    existing_agents = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            
            # Add new user agent at the beginning
            existing_agents.insert(0, new_user_agent)
            
            # Keep only last 10 user agents to avoid file bloat
            existing_agents = existing_agents[:10]
            
            # Write back to file
            with open(user_agent_file, "w", encoding="utf-8") as f:
                f.write("# Auto-generated user agents\n")
                for agent in existing_agents:
                    f.write(f"{agent}\n")
            
            print(f"✅ New user agent generated and saved")
            return True
        else:
            print("⚠️ Generated user agent seems invalid")
            return False
            
    except Exception as e:
        print(f"❌ Failed to generate user agent with AI: {e}")
        return False

def get_search_engine_suggestions(language, region, seed_keywords, niche_terms=None):
    """
    Get suggestions from multiple search engines with optimized parallel processing.
    Print raw suggestions for debugging
    """
    print(f"\nGetting suggestions from search engines...")
    print(f"Target niche terms: {', '.join(niche_terms) if niche_terms else 'None'}")

    # Initialize cache and rate limiter
    cache = KeywordCache()
    rate_limiter = RateLimiter(calls_limit=180, time_period=60,
                              initial_backoff=1, max_backoff=15)

    # Check if we have a previous run result in cache
    cache_params = {
        "method": "combined_suggestions",
        "seed_keywords": seed_keywords[:10],  # Use just first few to avoid too specific cache
        "language": language,
        "region": region,
        "niche_terms": niche_terms,  # Add niche_terms to cache key
        "timestamp": datetime.now().strftime("%Y-%m-%d")  # Daily cache
    }

    cached_results = cache.get(cache_params)
    if cached_results and len(cached_results) > len(seed_keywords):
        print(f"Using cached suggestions: {len(cached_results)} items")
        results = cached_results
    else:
        # Create thread pool with optimal concurrency
        import multiprocessing
        optimal_workers = min(10, multiprocessing.cpu_count() * 2)

        # Split keywords into primary and fallback sets
        primary_set = seed_keywords[:min(len(seed_keywords), 30)]  # First N keywords
        fallback_set = seed_keywords[len(primary_set):]  # Remaining keywords

        # Step 1: Get suggestions from Google for primary set
        google_suggestions = parallel_get_suggestions(primary_set, language, region,
                                                   rate_limiter, cache, max_workers=optimal_workers)

        # 2: Print raw suggestions before filtering
        print(f"\n🔍 RAW GOOGLE SUGGESTIONS ({len(google_suggestions)} total):")
        for i, suggestion in enumerate(google_suggestions[:10]):  # Show first 10
            print(f"  {i+1}. {suggestion}")
        if len(google_suggestions) > 10:
            print(f"  ... and {len(google_suggestions) - 10} more")

        # If Google results are sufficient, use them
        if len(google_suggestions) >= len(seed_keywords) * 3:
            print(f"Google suggestions retrieved: {len(google_suggestions)}")
            results = remove_duplicates(google_suggestions)
            cache.set(cache_params, results)
        else:
            print(f"Google suggestions limited ({len(google_suggestions)}). Getting more data...")

            # Step 2: Get additional Bing suggestions
            bing_suggestions = []
            with ThreadPoolExecutor(max_workers=optimal_workers) as executor:
                future_to_seed = {
                    executor.submit(get_bing_suggestions, seed, language, region, rate_limiter, cache): seed
                    for seed in primary_set
                }

                total = len(primary_set)
                completed = 0

                print(f"Getting Bing suggestions for {total} keywords:")
                for future in as_completed(future_to_seed):
                    seed = future_to_seed[future]
                    try:
                        suggestions = future.result()
                        bing_suggestions.extend(suggestions)
                        completed += 1
                        print_progress_bar(completed, total, prefix='Progress:', suffix='Complete', length=50)
                    except Exception as e:
                        print(f"\nError getting Bing suggestions for '{seed}': {e}")

            # 2: Print raw Bing suggestions
            if bing_suggestions:
                print(f"\n🔍 RAW BING SUGGESTIONS ({len(bing_suggestions)} total):")
                for i, suggestion in enumerate(bing_suggestions[:5]):  # Show first 5
                    print(f"  {i+1}. {suggestion}")
                if len(bing_suggestions) > 5:
                    print(f"  ... and {len(bing_suggestions) - 5} more")

            # Combine and deduplicate results
            all_suggestions = google_suggestions + bing_suggestions

            # If still insufficient, process fallback set
            if len(all_suggestions) < len(seed_keywords) * 8 and fallback_set:
                print(f"\nGetting suggestions for fallback keyword set ({len(fallback_set)} keywords)...")
                fallback_suggestions = parallel_get_suggestions(
                    fallback_set[:20],  # Limit to first 20 fallback keywords
                    language,
                    region,
                    rate_limiter,
                    cache,
                    max_workers=optimal_workers
                )
                all_suggestions.extend(fallback_suggestions)

            results = remove_duplicates(all_suggestions)
            cache.set(cache_params, results)
        
        print(f"\n🔍 TOTAL RAW SUGGESTIONS BEFORE FILTERING: {len(results)}")
        
    print(f"\nSuggestion retrieval complete. Retrieved {len(results)} unique suggestions.")

    if niche_terms:
        before_filter = len(results)
        results = [
            kw for kw in results
            if any(term.lower() in kw.lower() for term in niche_terms)
        ]
        after_filter = len(results)
        print(f"🎯 Niche filtering: {before_filter} → {after_filter} keywords (removed {before_filter - after_filter} non-relevant)")
    else:
        print("⚠️ No niche terms provided for filtering - this may result in irrelevant keywords")
    
    return results

def setup_global_connection_pool():
    """
    Setup global connection pool for better HTTP performance
    """
    import requests
    from urllib3 import PoolManager
    from requests.adapters import HTTPAdapter
    
    class PooledAdapter(HTTPAdapter):
        def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
            self.poolmanager = PoolManager(
                num_pools=connections,
                maxsize=maxsize,
                block=block,
                timeout=15.0,
                retries=3,
                **pool_kwargs
            )
    
    # Create session with connection pooling
    session = requests.Session()
    adapter = PooledAdapter(pool_connections=20, pool_maxsize=100)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    
    # Replace requests.get globally with session.get
    original_get = requests.get
    
    def pooled_get(*args, **kwargs):
        return session.get(*args, **kwargs)
    
    requests.get = pooled_get
    
    return original_get  # Return original to restore if needed

setup_global_connection_pool()

def get_suggestions_for_seed(seed, language, region, rate_limiter, cache):
    """
    Get Google suggestions for a seed keyword dengan enhanced request handling
    """
    # Check cache
    cache_params = {
        "method": "suggestions",
        "seed": seed,
        "language": language,
        "region": region
    }
    cached_result = cache.get(cache_params)
    if cached_result:
        print(f"Using cached data for '{seed}'")
        return cached_result
    
    # Set rate limiting
    rate_limiter.wait_if_needed()
    
    # Try Google Autocomplete API
    try:
        encoded_seed = requests.utils.quote(seed)
        url = f"http://suggestqueries.google.com/complete/search?client=firefox&hl={language}&gl={region}&q={encoded_seed}"
        
        # Use robust_request instead of direct handler call
        response = robust_request(url, timeout=10)
        
        if response and response.status_code == 200:
            try:
                suggestions = json.loads(response.text)[1]
                # Filter out suspicious queries
                suggestions = [suggestion for suggestion in suggestions if not is_suspicious_query(suggestion)]
                # Save to cache
                cache.set(cache_params, suggestions)
                return suggestions
            except (json.JSONDecodeError, IndexError, KeyError):
                log_info("Failed to parse Google suggestions response")
        else:
            log_info(f"Google suggestions request failed - Status: {response.status_code if response else 'None'}")
            
    except Exception as e:
        log_info(f"Error getting Google suggestions for keyword: {str(e)}")
    
    # Fallback to seed-based predictions if API fails
    print(f"Using fallback for '{seed}'")
    if language == "en":
        fallback_suggestions = [
            f"{seed} is",
            f"{seed} for",
            f"{seed} how",
            f"{seed} best",
            f"why {seed}",
            f"how {seed}",
            f"{seed} online",
            f"{seed} cheap",
        ]
    else:
        fallback_suggestions = [seed]
    return fallback_suggestions

def get_bing_suggestions(seed, language, region, rate_limiter, cache):
    """
    Get Bing suggestions dengan enhanced request handling
    """
    # Check cache
    cache_params = {
        "method": "bing_suggestions",
        "seed": seed,
        "language": language,
        "region": region
    }
    cached_result = cache.get(cache_params)
    if cached_result:
        print(f"Using cached Bing data for '{seed}'")
        return cached_result
    
    # Set rate limiting
    rate_limiter.wait_if_needed()
    
    try:
        # Using a simpler, more stable URL format for Bing Suggestions
        encoded_query = requests.utils.quote(seed)
        url = f"https://www.bing.com/search?q={encoded_query}"
        
        # Additional headers for Bing
        additional_headers = {
            "Accept-Language": f"{language}-{region},{language};q=0.9",
            "Referer": "https://www.bing.com/"
        }
        
        # Use robust_request instead of direct handler call
        response = robust_request(url, headers=additional_headers, timeout=15)
        
        if response and response.status_code == 200:
            # Parse HTML to find related searches
            soup = BeautifulSoup(response.text, 'html.parser')
            suggestions = []
            
            # Find related suggestions in Bing search results
            related_searches = soup.select('.b_rs a')
            for item in related_searches:
                if item.text.strip():
                    suggestions.append(item.text.strip())
            
            # Also look for suggestions at the bottom of the search results
            bottom_searches = soup.select('.b_expansion_text a')
            for item in bottom_searches:
                if item.text.strip():
                    suggestions.append(item.text.strip())
            
            # Deduplication
            suggestions = list(dict.fromkeys(suggestions))
            
            # Save to cache
            cache.set(cache_params, suggestions)
            return suggestions
        else:
            print(f"Bing request failed for '{seed}' - Status: {response.status_code if response else 'None'}")
            
    except Exception as e:
        print(f"Error getting suggestions from Bing for '{seed}': {e}")
    
    # Return empty list on error
    return []

def parallel_get_suggestions(seed_keywords, language, region, rate_limiter, cache, max_workers=10):
    """
    Get keyword suggestions in parallel with optimized thread management
    """
    all_suggestions = []
    batch_size = min(len(seed_keywords), 100)  # Process in smaller batches
    
    for batch_start in range(0, len(seed_keywords), batch_size):
        batch_end = min(batch_start + batch_size, len(seed_keywords))
        batch = seed_keywords[batch_start:batch_end]
        
        # Create work queue and result collector
        from queue import Queue
        work_queue = Queue()
        result_queue = Queue()
        
        # Add all jobs to queue
        for seed in batch:
            work_queue.put(seed)
        
        # Progress tracking
        total = len(batch)
        completed = 0
        
        def worker():
            while not work_queue.empty():
                try:
                    seed = work_queue.get(block=False)
                    suggestions = get_suggestions_for_seed(seed, language, region, rate_limiter, cache)
                    result_queue.put((True, suggestions))
                except Exception as e:
                    # Put failed item back with lower priority for retry
                    result_queue.put((False, f"Error for '{seed}': {str(e)}"))
                finally:
                    work_queue.task_done()
        
        # Start worker threads
        active_workers = min(max_workers, total)
        threads = []
        for _ in range(active_workers):
            thread = threading.Thread(target=worker, daemon=True)
            thread.start()
            threads.append(thread)
        
        # Process results as they come
        print(f"\nGetting suggestions for {total} keywords in batch {batch_start//batch_size + 1}:")
        while completed < total:
            success, result = result_queue.get()
            completed += 1
            
            if success:
                all_suggestions.extend(result)
                print_progress_bar(completed, total, prefix='Progress:', suffix='Complete', length=50)
            else:
                print(f"\n{result}")
                print_progress_bar(completed, total, prefix='Progress:', suffix='Complete', length=50)
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join(timeout=1.0)
    
    print("\nSuggestion retrieval complete.")
    return all_suggestions

def is_similar(keyword1, keyword2, threshold=0.8):
    """
    Check if two keywords are similar using sequence matcher
    
    Args:
        keyword1 (str): First keyword
        keyword2 (str): Second keyword
        threshold (float): Similarity threshold (0-1)
        
    Returns:
        bool: True if similar, False if not
    """
    # Normalize strings
    s1 = keyword1.lower()
    s2 = keyword2.lower()
    
    # Calculate similarity
    similarity = difflib.SequenceMatcher(None, s1, s2).ratio()
    
    return similarity >= threshold

def count_common_words(keyword1, keyword2):
    """
    Counting the number of common words between two keywords
    
    Args:
        keyword1 (str): First keyword
        keyword2 (str): Second keyword
        
    Returns:
        int: Same word count
    """
    # Normalization and breaking into words
    words1 = set(keyword1.lower().split())
    words2 = set(keyword2.lower().split())
    
    # Count the same words
    common_words = words1.intersection(words2)
    
    return len(common_words)

def generate_niche_clue_pairs(niche_terms, clue_terms):
    """
    Generate combinations that MUST contain both niche and clue terms.
    Limit combinations and make them more natural
    """
    pairs = []
    # Normalize terms
    niche_terms = [term.strip().lower() for term in niche_terms]
    clue_terms = [term.strip().lower() for term in clue_terms]
    
    for niche in niche_terms:
        for clue in clue_terms:
            # Basic combinations: niche + clue in different orders
            pairs.append(f"{niche} {clue}")
            pairs.append(f"{clue} {niche}")
            
            # IMPROVED: Only add middle insertion for very short clues (avoid long seeds)
            if ' ' in clue and len(clue.split()) == 2 and len(niche.split()) == 1:
                clue_parts = clue.split()
                pairs.append(f"{clue_parts[0]} {niche} {clue_parts[1]}")
    
    # Remove duplicates while preserving order
    pairs = list(dict.fromkeys(pairs))
    
    # Limit total pairs to avoid overwhelming search engines
    MAX_PAIRS = 50
    if len(pairs) > MAX_PAIRS:
        pairs = pairs[:MAX_PAIRS]
        print(f"🎯 Limited to {MAX_PAIRS} niche-clue pairs to avoid overwhelming search engines")
    
    print(f"🎯 Generated {len(pairs)} niche-clue pairs containing niche terms: {', '.join(niche_terms)}")
    return pairs

def is_niche_relevant(keyword, niche_terms):
    """
    Check whether the keywords are relevant to the specified niche
    ENHANCED: More flexible niche matching
    """
    keyword_lower = keyword.lower()
    
    # Check if at least one niche term is present in the keyword (substring match)
    for term in niche_terms:
        term_lower = term.lower().strip()
        if term_lower in keyword_lower:
            return True
    
    return False

def expand_niche_terms(niche):
    """
    Expand the niche term with various variations including dynamic tokens
    
    Args:
        niche (str): Key niche terms
        
    Returns:
        list: List of niche terms and their variations
    """
    niche = niche.strip().lower()
    variations = [niche]
    
    # Get niche synonyms from configuration
    configs = get_default_configurations()
    niche_synonyms = configs["niche_synonyms"]
    
    # Add specific synonyms if available
    if niche in niche_synonyms:
        variations.extend(niche_synonyms[niche])
    
    # Add variations from general categories
    for category in ['general', 'comparison', 'price', 'location', 'quality', 'brand']:
        if category in niche_synonyms:
            variations.extend([term for term in niche_synonyms[category]])
    
    # Add dynamic product variations
    if 'product' in niche_synonyms:
        dynamic_terms = [term.replace('{niche}', niche) for term in niche_synonyms['product']]
        variations.extend(dynamic_terms)
    
    # Remove duplicates while preserving order
    return list(dict.fromkeys(variations))

def remove_duplicates(keywords):
    """
    Remove duplicate keywords while maintaining order
    
    Args:
        keywords (list): List of keywords that may have duplicates
        
    Returns:
        list: List of keywords without duplicates
    """
    seen = set()
    unique = []
    for item in keywords:
        normalized = item.strip().lower()
        if normalized not in seen:
            seen.add(normalized)
            unique.append(item)
    return unique

def filter_badwords(keywords, badwords_file=None, language=None):
    """
    Filter out keywords that contain any badwords defined in badwords.txt

    Args:
        keywords (list): List of keyword strings
        badwords_file (str): Path to the badwords file
        language (str): Language to use

    Returns:
        list: Filtered keywords without badwords
    """
    if badwords_file is None:
        badwords_file = os.path.join(get_kw_path(language), "badwords.txt")
        
    if not os.path.exists(badwords_file):
        print("⚠️ Badwords.txt file not found.")
        # Fall back to default badwords
        configs = get_default_configurations()
        badwords = configs["default_badwords"]
    else:
        with open(badwords_file, "r", encoding="utf-8") as f:
            badwords = [line.strip().lower() for line in f if line.strip()]

    filtered = []
    for kw in keywords:
        if not any(badword in kw.lower() for badword in badwords):
            filtered.append(kw)

    removed = len(keywords) - len(filtered)
    if removed > 0:
        print(f"🚫 {removed} keyword{'s' if removed > 1 else ''} removed because {'they contain' if removed > 1 else 'it contains'} bad words.")
    return filtered

def clean_and_organize_niche_keywords(niche, language=None):
    """
    Clean and organize keywords for a specific niche, removing irrelevant ones
    
    Args:
        niche (str): Target niche
        language (str): Language to use
    """
    keyword_file = os.path.join(get_keywords_path(language), niche, "keywords.txt")
    
    if not os.path.exists(keyword_file):
        print(f"⚠️ No keywords file found for niche: {niche}")
        return
    
    with open(keyword_file, "r", encoding="utf-8") as f:
        keywords = [line.strip() for line in f if line.strip()]
    
    if not keywords:
        print(f"⚠️ Keywords file is empty for niche: {niche}")
        return
    
    print(f"🧹 Cleaning {len(keywords)} keywords for niche '{niche}'...")
    
    # Validate niche consistency
    valid_keywords, invalid_keywords = validate_niche_consistency(keywords, niche)
    
    if invalid_keywords:
        # Move invalid keywords to removed file
        removed_file = os.path.join(get_keywords_path(language), niche, "removed_keywords.txt")
        with open(removed_file, "a", encoding="utf-8") as f:
            f.write(f"\n--- Cleaned on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---\n")
            for kw in invalid_keywords:
                f.write(f"{kw}\n")
        
        # Update keywords file with only valid keywords
        with open(keyword_file, "w", encoding="utf-8") as f:
            for kw in valid_keywords:
                f.write(f"{kw}\n")
        
        print(f"✅ Cleaned: {len(valid_keywords)} valid, {len(invalid_keywords)} moved to removed_keywords.txt")
    else:
        print(f"✅ All {len(keywords)} keywords are already consistent with niche '{niche}'")
    
    return valid_keywords

def print_progress_bar(iteration, total, prefix='', suffix='', decimals=1, length=100, fill='█'):
    """
    Display progress bar in terminal
    
    Args:
        iteration (int): Current iteration
        total (int): Total iterations
        prefix (str): Text before progress bar
        suffix (str): Text after progress bar
        decimals (int): Number of decimals for percentage
        length (int): Character length of progress bar
        fill (str): Character to fill progress bar
    """
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end='\r')
    # Print new line on complete
    if iteration == total: 
        print()

def check_internet_connection():
    """
    Check internet connection by trying to access Google
    
    Returns:
        bool: True if internet connection is working, False if not
    """
    try:
        # Try to access Google with 5 second timeout
        requests.get('https://www.google.com', timeout=5)
        return True
    except requests.ConnectionError:
        return False
    except:
        return False

def cleanup_old_files(directory, max_age_hours=24):
    """
    Remove files older than specified age
    
    Args:
        directory (str): Directory to clean
        max_age_hours (int): Maximum age in hours
    """
    if not os.path.exists(directory):
        return
        
    now = time.time()
    max_age_seconds = max_age_hours * 3600
    
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        if os.path.isfile(file_path):
            if now - os.path.getmtime(file_path) > max_age_seconds:
                try:
                    os.remove(file_path)
                    print(f"Removed old file: {file_path}")
                except Exception as e:
                    print(f"Error removing {file_path}: {e}")

def clear_logs(language=None):
    """
    Clear all log files in the logs directory at the start of the script.
    """
    logs_dir = get_keywords_logs_path(language)
    if not os.path.exists(logs_dir):
        return
    cleared_count = 0
    for filename in os.listdir(logs_dir):
        file_path = os.path.join(logs_dir, filename)
        if os.path.isfile(file_path):
            try:
                os.remove(file_path)
                cleared_count += 1
            except Exception as e:
                print(f"Error removing log file {file_path}: {e}")
    if cleared_count > 0:
        print(f"🧹 Cleared {cleared_count} log files in logs directory.")
    else:
        print("ℹ️ No log files found to clear.")

def limit_cache_size(cache_dir, max_size_mb=500):
    """
    Limit total cache size by removing oldest files when exceeded
    
    Args:
        cache_dir (str): Cache directory
        max_size_mb (int): Maximum size in MB
    """
    if not os.path.exists(cache_dir):
        return
        
    # Convert to bytes
    max_size_bytes = max_size_mb * 1024 * 1024
    
    # Get all files with their modification time
    files = []
    total_size = 0
    
    for filename in os.listdir(cache_dir):
        file_path = os.path.join(cache_dir, filename)
        if os.path.isfile(file_path):
            file_size = os.path.getsize(file_path)
            mod_time = os.path.getmtime(file_path)
            files.append((file_path, mod_time, file_size))
            total_size += file_size
    
    # Sort by modification time (oldest first)
    files.sort(key=lambda x: x[1])
    
    # Remove oldest files until under size limit
    removed_count = 0
    while total_size > max_size_bytes and files:
        oldest_file, _, file_size = files.pop(0)
        try:
            os.remove(oldest_file)
            total_size -= file_size
            removed_count += 1
        except Exception as e:
            print(f"Error removing {oldest_file}: {e}")
    
    if removed_count > 0:
        print(f"Removed {removed_count} oldest cache files to maintain size limit")

def count_non_connecting_words(text, language="en"):
    """
    Count words in text excluding connecting words/stopwords
    
    Args:
        text (str): Text to analyze
        language (str): Language code
        
    Returns:
        int: Count of non-connecting words
    """
    # Get stopwords from central configuration
    configs = get_default_configurations()
    stopwords = configs["stopwords"]
    
    # Default to English if language not defined
    if language not in stopwords:
        language = "en"
    
    # Split text into words and convert to lowercase
    words = text.lower().split()
    
    # Count words that are not in stopwords list
    non_connecting_words = [word for word in words if word not in stopwords[language]]
    
    return len(non_connecting_words)

def get_region_name(region_code):
    """
    Get full region name from region code
    
    Args:
        region_code (str): ISO region code
        
    Returns:
        str: Region name or None if not found
    """
    region_names = {
        'za': 'South Africa',
        'us': 'United States'
    }
    
    return region_names.get(region_code.lower())

def validate_language(text, target_language, target_region, niche_terms=None):
    """
    Validate if text is primarily in the target language and relevant to target region
    """
    # Get configurations
    configs = get_default_configurations()
    region_terms = configs["region_terms"]
    language_markers = configs["language_markers"]

    # PRIORITY: If keyword contains niche terms, be more lenient
    if niche_terms:
        if any(term.lower() in text.lower() for term in niche_terms):
            # For niche-relevant keywords, only basic validation
            words = text.lower().split()
            if len(words) <= 3:
                return True  # Always accept short niche-relevant keywords
            
            # Check if it has some language markers (more lenient threshold)
            if target_language in language_markers:
                language_markers_set = set(language_markers[target_language])
                marker_count = sum(1 for word in words if word in language_markers_set)
                # Much lower threshold for niche keywords
                if marker_count >= 1:
                    return True
    
    # Skip validation for very short texts
    if len(text.split()) <= 3:
        return True
        
    # Check if any region terms are in the text
    if target_region in region_terms:
        text_lower = text.lower()
        if any(term in text_lower for term in region_terms[target_region]):
            return True
    
    # Try language detection with more lenient threshold
    langdetect_available = False
    try:
        from langdetect import detect, LangDetectException, DetectorFactory
        DetectorFactory.seed = 0
        langdetect_available = True
    except ImportError:
        pass
        
    if langdetect_available:
        try:
            from langdetect import detect_langs
            lang_probabilities = detect_langs(text)
            
            # LOWERED threshold for more flexibility
            threshold = 0.4 if target_language == 'id' else 0.2
            
            for lang in lang_probabilities:
                if lang.lang == target_language and lang.prob >= threshold:
                    return True
            
            # If niche terms present, accept even with low confidence
            if niche_terms and any(term.lower() in text.lower() for term in niche_terms):
                return True
                
            return False
        except LangDetectException:
            pass
    
    # Fallback to language markers with relaxed requirements
    if target_language not in language_markers:
        return True
        
    words = text.lower().split()
    target_markers = set(language_markers[target_language])
    
    marker_count = sum(1 for word in words if word in target_markers)
    
    # RELAXED: Require fewer markers, especially for Indonesian
    min_markers = 1 if target_language == 'id' else 1
    
    return marker_count >= min_markers

def is_suspicious_query(query: str) -> bool:
    """
    Detect suspicious queries from multilingual Google Suggest results.
    Supported languages: en, id, ar, ru, fr, es, pt, bn
    """
    # Get patterns from configuration
    patterns = get_default_configurations()["suspicious_query_patterns"]
    query_lower = query.lower()
    return any(re.match(p, query_lower) for p in patterns)

def expand_seed_keywords(seed_keywords, language, region):
    """
    Expand seed keywords with language and region specific variations
    
    Args:
        seed_keywords (list): Original seed keywords
        language (str): Language code
        region (str): Region code
        
    Returns:
        list: Expanded seed keywords
    """
    expanded = []
    configs = get_default_configurations()
    expanded.extend(seed_keywords)
    region_name = get_region_name(region)
    if region_name:
        for seed in seed_keywords:
            expanded.append(f"{region_name} {seed}")
            expanded.append(f"{seed} {region_name}")
            expanded.append(f"{seed} in {region_name}")

    prefixes = configs["keyword_prefixes"]
    suffixes = configs["keyword_suffixes"]

    if language != "en":
        prefixes = [p for p in prefixes if not re.match(r"^[a-zA-Z]+$", p)]
        suffixes = [s for s in suffixes if not re.match(r"^[a-zA-Z]+$", s)]

    for seed in seed_keywords:
        for prefix in prefixes:
            expanded.append(f"{prefix} {seed}")
        for suffix in suffixes:
            expanded.append(f"{seed} {suffix}")

    expanded = [kw for kw in expanded if kw.strip()]
    expanded = list(dict.fromkeys(expanded))
    return expanded

def get_default_configurations():
    """
    Return a dictionary containing all static configurations used throughout the application.
    All configurations are now loaded from external files instead of hardcoded values.
    
    Returns:
        dict: Dictionary containing all configuration dictionaries and lists
    """
    # Get active language
    active_language = get_active_language()
    
    # Base paths
    kw_path = get_kw_path(active_language)
    
    # Helper function to read key-value file (format "key:value" or "key": "value")
    def read_kv_file(file_path, default_path=None):
        result = {}
        path_to_use = file_path if os.path.exists(file_path) else default_path
        
        if path_to_use and os.path.exists(path_to_use):
            try:
                with open(path_to_use, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        
                        if ":" in line:
                            if '"' in line:  # Format: "key": "value"
                                parts = line.split(":", 1)
                                key = parts[0].strip().strip('"')
                                value = parts[1].strip().strip('"').strip(',')
                                result[key] = value
                            else:  # Format: key:value
                                key, value = line.split(":", 1)
                                result[key.strip()] = value.strip()
            except Exception as e:
                print(f"Error reading file {path_to_use}: {str(e)}")
        
        return result
    
    # Helper function to read list file (one item per line)
    def read_list_file(file_path, default_path=None):
        result = []
        path_to_use = file_path if os.path.exists(file_path) else default_path
        
        if path_to_use and os.path.exists(path_to_use):
            try:
                with open(path_to_use, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            result.append(line)
            except Exception as e:
                print(f"Error reading file {path_to_use}: {str(e)}")
        
        return result
    
    # Helper function to read nested dictionary file (json-like format)
    def read_nested_dict_file(file_path, default_path=None):
        result = {}
        path_to_use = file_path if os.path.exists(file_path) else default_path
        
        if path_to_use and os.path.exists(path_to_use):
            try:
                current_key = None
                values = []
                
                with open(path_to_use, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        
                        if line.startswith('[') and line.endswith(']:'):  # New section like [en]:
                            # Save previous section if any
                            if current_key is not None:
                                result[current_key] = values
                            
                            # Start new section
                            current_key = line[1:-2]  # Remove [ and ]:
                            values = []
                        else:
                            # Add value to current section
                            if current_key is not None:
                                values.append(line.strip('"').strip("'"))
                
                # Add the last section
                if current_key is not None:
                    result[current_key] = values
                    
            except Exception as e:
                print(f"Error reading nested dict file {path_to_use}: {str(e)}")
        
        return result
    
    # File paths
    language_default_file = os.path.join(kw_path, "language_default.txt")
    language_default_backup = os.path.join(kw_path, "language_default.default.txt")
    
    country_mapping_file = os.path.join(kw_path, "country_language_mapping.txt")
    country_mapping_backup = os.path.join(kw_path, "country_language_mapping.default.txt")
    
    region_options_file = os.path.join(kw_path, "region_options.txt")
    region_options_backup = os.path.join(kw_path, "region_options.default.txt")
    
    region_default_file = os.path.join(kw_path, "region.txt")
    region_default_backup = os.path.join(kw_path, "region.default.txt")
    
    user_agents_file = os.path.join(kw_path, "user-agent.txt")
    user_agents_backup = os.path.join(kw_path, "user-agent.default.txt")
    
    stopwords_file = os.path.join(kw_path, "stopwords.txt")
    stopwords_backup = os.path.join(kw_path, "stopwords.default.txt")
    
    language_markers_file = os.path.join(kw_path, "language_markers.txt")
    language_markers_backup = os.path.join(kw_path, "language_markers.default.txt")
    
    region_terms_file = os.path.join(kw_path, "region_terms.txt")
    region_terms_backup = os.path.join(kw_path, "region_terms.default.txt")
    
    clues_file = os.path.join(kw_path, "clue.txt")
    clues_backup = os.path.join(kw_path, "clue.default.txt")
    
    badwords_file = os.path.join(kw_path, "badwords.txt")
    badwords_backup = os.path.join(kw_path, "badwords.default.txt")
    
    niche_file = os.path.join(kw_path, "niche.txt")
    niche_backup = os.path.join(kw_path, "niche.default.txt")
    
    # Get active niches 
    niches = get_active_niches(active_language)
    primary_niche = niches[0] if niches else "general"
    
    keywords_file = os.path.join(get_keywords_niche_path(primary_niche, active_language), "keywords.txt")
    keywords_backup = os.path.join(get_keywords_niche_path(primary_niche, active_language), "keywords.default.txt")
    
    clue_prompt_file = os.path.join(kw_path, "clue_prompt_template.txt")
    clue_prompt_backup = os.path.join(kw_path, "clue_prompt_template.default.txt")
    
    language_validation_file = os.path.join(kw_path, "language_validation_prompt.txt")
    language_validation_backup = os.path.join(kw_path, "language_validation_prompt.default.txt")
    
    related_languages_file = os.path.join(kw_path, "related_languages.txt")
    related_languages_backup = os.path.join(kw_path, "related_languages.default.txt")
    
    prefixes_file = os.path.join(kw_path, "prefixes.txt")
    prefixes_backup = os.path.join(kw_path, "prefixes.default.txt")
    
    suffixes_file = os.path.join(kw_path, "suffixes.txt")
    suffixes_backup = os.path.join(kw_path, "suffixes.default.txt")
    
    patterns_file = os.path.join(kw_path, "patterns.txt")
    patterns_backup = os.path.join(kw_path, "patterns.default.txt")
    
    niche_synonyms_file = os.path.join(kw_path, "niche_synonyms.txt")
    niche_synonyms_backup = os.path.join(kw_path, "niche_synonyms.default.txt")
    
    # Read configuration data from files
    language_default = read_kv_file(language_default_file, language_default_backup)
    country_language_mapping = read_kv_file(country_mapping_file, country_mapping_backup)
    region_options = read_list_file(region_options_file, region_options_backup)
    region_default = read_list_file(region_default_file, region_default_backup)
    default_user_agents = read_list_file(user_agents_file, user_agents_backup)
    stopwords = read_nested_dict_file(stopwords_file, stopwords_backup)
    language_markers = read_nested_dict_file(language_markers_file, language_markers_backup)
    region_terms = read_nested_dict_file(region_terms_file, region_terms_backup)
    default_clues = read_list_file(clues_file, clues_backup)
    default_badwords = read_list_file(badwords_file, badwords_backup)
    default_niche = read_list_file(niche_file, niche_backup)[0] if read_list_file(niche_file, niche_backup) else "history"
    default_keywords = read_list_file(keywords_file, keywords_backup)
    
    # Read template strings
    try:
        with open(clue_prompt_file if os.path.exists(clue_prompt_file) else clue_prompt_backup, "r", encoding="utf-8") as f:
            clue_prompt_template = f.read().strip()
    except Exception as e:
        print(f"Error reading clue prompt template: {str(e)}")
        clue_prompt_template = ""
    
    try:
        with open(language_validation_file if os.path.exists(language_validation_file) else language_validation_backup, "r", encoding="utf-8") as f:
            language_validation_prompt = f.read().strip()
    except Exception as e:
        print(f"Error reading language validation prompt: {str(e)}")
        language_validation_prompt = ""
    
    related_languages = read_nested_dict_file(related_languages_file, related_languages_backup)
    keyword_prefixes = read_list_file(prefixes_file, prefixes_backup)
    keyword_suffixes = read_list_file(suffixes_file, suffixes_backup)
    suspicious_query_patterns = read_list_file(patterns_file, patterns_backup)
    niche_synonyms = read_nested_dict_file(niche_synonyms_file, niche_synonyms_backup)
    
    # Return all configurations as a dictionary
    return {
        "language_default": language_default,
        "country_language_mapping": country_language_mapping,
        "region_options": region_options,
        "region_default": region_default,
        "default_user_agents": default_user_agents,
        "stopwords": stopwords,
        "language_markers": language_markers,
        "region_terms": region_terms,
        "default_clues": default_clues,
        "default_badwords": default_badwords,
        "default_keywords": default_keywords,
        "default_niche": default_niche,
        "clue_prompt_template": clue_prompt_template,
        "language_validation_prompt": language_validation_prompt,
        "related_languages": related_languages,
        "keyword_prefixes": keyword_prefixes,
        "keyword_suffixes": keyword_suffixes,
        "suspicious_query_patterns": suspicious_query_patterns,
        "niche_synonyms": niche_synonyms
    }

def ensure_default_config(language=None):
    """
    Ensure default configuration files exist along with their default versions
    This centralized function handles creation of all .default.txt files
    
    Args:
        language (str): Language to use for config files
    """
    if language is None:
        language = get_active_language()
        
    # Get all configurations
    configs = get_default_configurations()
    
    # Ensure directories exist
    kw_dir = get_kw_path(language)
    os.makedirs(kw_dir, exist_ok=True)
    
    # Create cache and logs directories
    cache_dir = get_keywords_cache_path(language)
    logs_dir = get_keywords_logs_path(language)
    os.makedirs(cache_dir, exist_ok=True)
    os.makedirs(logs_dir, exist_ok=True)
    
    # Ensure niche directories exist
    niches = get_active_niches(language)
    for niche in niches:
        niche_dir = os.path.join(get_keywords_path(language), niche)
        os.makedirs(niche_dir, exist_ok=True)
    
    # Define functions to format different types of data for writing to files
    def format_kv_content(content):
        """Format dictionary as key:value pairs for writing to file"""
        if isinstance(content, dict):
            return '\n'.join([f'"{k}": "{v}"' for k, v in content.items()])
        elif isinstance(content, list):
            return '\n'.join(content)
        else:
            return str(content)
    
    def format_list_content(content):
        """Format list content for writing to file"""
        if isinstance(content, list):
            return '\n'.join(content)
        elif isinstance(content, str):
            return content
        else:
            return str(content)
    
    def format_nested_dict_content(content):
        """Format nested dictionary content with sections [key]: values for writing to file"""
        if not isinstance(content, dict):
            return str(content)
        
        lines = []
        for key, values in content.items():
            lines.append(f"[{key}]:")
            if isinstance(values, list):
                lines.extend(values)
            else:
                lines.append(str(values))
            lines.append("")  # Empty line between sections
        return '\n'.join(lines)
    
    # Define configuration files and their content formatters
    config_files = [
        # Simple key-value files
        {
            "file": os.path.join(kw_dir, "language_default.txt"),
            "default_file": os.path.join(kw_dir, "language_default.default.txt"),
            "content_key": "language_default",
            "formatter": format_kv_content
        },
        {
            "file": os.path.join(kw_dir, "country_language_mapping.txt"),
            "default_file": os.path.join(kw_dir, "country_language_mapping.default.txt"),
            "content_key": "country_language_mapping",
            "formatter": format_kv_content
        },
        # List files
        {
            "file": os.path.join(kw_dir, "region_options.txt"),
            "default_file": os.path.join(kw_dir, "region_options.default.txt"),
            "content_key": "region_options",
            "formatter": format_list_content
        },
        {
            "file": os.path.join(kw_dir, "region.txt"),
            "default_file": os.path.join(kw_dir, "region.default.txt"),
            "content_key": "region_default",
            "formatter": format_list_content
        },
        {
            "file": os.path.join(kw_dir, "user-agent.txt"),
            "default_file": os.path.join(kw_dir, "user-agent.default.txt"),
            "content_key": "default_user_agents",
            "formatter": format_list_content
        },
        {
            "file": os.path.join(kw_dir, "clue.txt"),
            "default_file": os.path.join(kw_dir, "clue.default.txt"),
            "content_key": "default_clues",
            "formatter": format_list_content
        },
        {
            "file": os.path.join(kw_dir, "badwords.txt"),
            "default_file": os.path.join(kw_dir, "badwords.default.txt"),
            "content_key": "default_badwords",
            "formatter": format_list_content
        },
        {
            "file": os.path.join(kw_dir, "prefixes.txt"),
            "default_file": os.path.join(kw_dir, "prefixes.default.txt"),
            "content_key": "keyword_prefixes",
            "formatter": format_list_content
        },
        {
            "file": os.path.join(kw_dir, "suffixes.txt"),
            "default_file": os.path.join(kw_dir, "suffixes.default.txt"),
            "content_key": "keyword_suffixes",
            "formatter": format_list_content
        },
        {
            "file": os.path.join(kw_dir, "patterns.txt"),
            "default_file": os.path.join(kw_dir, "patterns.default.txt"),
            "content_key": "suspicious_query_patterns",
            "formatter": format_list_content
        },
        # Special case for niche.txt which contains a single value
        {
            "file": os.path.join(kw_dir, "niche.txt"),
            "default_file": os.path.join(kw_dir, "niche.default.txt"),
            "content_key": "default_niche",
            "formatter": lambda x: x  # Just use the string directly
        },
        # Nested dictionary files
        {
            "file": os.path.join(kw_dir, "stopwords.txt"),
            "default_file": os.path.join(kw_dir, "stopwords.default.txt"),
            "content_key": "stopwords",
            "formatter": format_nested_dict_content
        },
        {
            "file": os.path.join(kw_dir, "language_markers.txt"),
            "default_file": os.path.join(kw_dir, "language_markers.default.txt"),
            "content_key": "language_markers",
            "formatter": format_nested_dict_content
        },
        {
            "file": os.path.join(kw_dir, "region_terms.txt"),
            "default_file": os.path.join(kw_dir, "region_terms.default.txt"),
            "content_key": "region_terms",
            "formatter": format_nested_dict_content
        },
        {
            "file": os.path.join(kw_dir, "related_languages.txt"),
            "default_file": os.path.join(kw_dir, "related_languages.default.txt"),
            "content_key": "related_languages",
            "formatter": format_nested_dict_content
        },
        {
            "file": os.path.join(kw_dir, "niche_synonyms.txt"),
            "default_file": os.path.join(kw_dir, "niche_synonyms.default.txt"),
            "content_key": "niche_synonyms",
            "formatter": format_nested_dict_content
        },
        # Template files
        {
            "file": os.path.join(kw_dir, "clue_prompt_template.txt"),
            "default_file": os.path.join(kw_dir, "clue_prompt_template.default.txt"),
            "content_key": "clue_prompt_template",
            "formatter": lambda x: x  # Use the template string directly
        },
        {
            "file": os.path.join(kw_dir, "language_validation_prompt.txt"),
            "default_file": os.path.join(kw_dir, "language_validation_prompt.default.txt"),
            "content_key": "language_validation_prompt",
            "formatter": lambda x: x  # Use the template string directly
        }
    ]
    
    # Process each configuration file
    for config_file in config_files:
        file_path = config_file["file"]
        default_file_path = config_file["default_file"]
        content_key = config_file["content_key"]
        formatter = config_file["formatter"]
        
        # Get content from the configurations
        content = configs.get(content_key, "")
        formatted_content = formatter(content)
        
        # Create the main file if it does not exist
        if not os.path.exists(file_path):
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(formatted_content)
            except Exception as e:
                print(f"Error creating file {file_path}: {str(e)}")
        
        # Always create or update the default file
        try:
            with open(default_file_path, "w", encoding="utf-8") as f:
                f.write(formatted_content)
        except Exception as e:
            print(f"Error creating default file {default_file_path}: {str(e)}")
    
    # Create keywords files for each niche
    for niche in niches:
        keywords_dir = os.path.join(get_keywords_path(language), niche)
        keywords_file = os.path.join(keywords_dir, "keywords.txt")
        keywords_default_file = os.path.join(keywords_dir, "keywords.default.txt")
        
        # Create the keywords file if it does not exist
        if not os.path.exists(keywords_file):
            try:
                with open(keywords_file, "w", encoding="utf-8") as f:
                    f.write("")  # Create empty file
            except Exception as e:
                print(f"Error creating keywords file for niche {niche}: {str(e)}")
        
        # Always create or update the default keywords file
        try:
            with open(keywords_default_file, "w", encoding="utf-8") as f:
                f.write("")  # Create empty default file
        except Exception as e:
            print(f"Error creating default keywords file for niche {niche}: {str(e)}")
    
    # Create a regions list file for reference (special case)
    regions_list_file = os.path.join(kw_dir, "regions_list.txt")
    if not os.path.exists(regions_list_file):
        try:
            with open(regions_list_file, "w", encoding="utf-8") as f:
                for region_code in configs["region_options"]:
                    f.write(f"{region_code}\n")
        except Exception as e:
            print(f"Error creating regions list file: {str(e)}")

def manage_clue_processing(clue_lines, niche, output_dir=None, language=None):
    """
    Improved clue processing management with niche-specific tracking
    """
    if output_dir is None:
        output_dir = get_kw_path(language)
    
    # Use niche-specific used clues primarily
    niche_dir = get_keywords_niche_path(niche, language)
    used_clue_file = os.path.join(niche_dir, "used_clue.txt")
    
    # Legacy processed clues file
    processed_file = os.path.join(output_dir, "processed_clue.txt")
    
    # Get all used clues for this niche
    niche_used_clues = set()
    if os.path.exists(used_clue_file):
        with open(used_clue_file, "r", encoding="utf-8") as f:
            niche_used_clues = set(line.strip().lower() for line in f if line.strip())
    
    # Also check legacy processed clues
    if os.path.exists(processed_file):
        with open(processed_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    niche_used_clues.add(line.lower())
    
    # Filter unused clues for this niche
    unused_clues = []
    for clue in clue_lines:
        if clue.lower() not in niche_used_clues:
            unused_clues.append(clue)
    
    print(f"📊 Clue status for niche '{niche}': {len(unused_clues)} unused / {len(clue_lines)} total")
    
    if not unused_clues:
        print(f"⚠️ All clues have been processed for niche '{niche}', but will continue with available clues")
        # This allows the system to try again with different combinations
        return clue_lines[:2] if clue_lines else [], True
    
    # Return next 2 clues to process
    next_clues = unused_clues[:2]
    print(f"▶️ Next 2 clues for '{niche}': {', '.join(next_clues)}")
    
    return next_clues, len(unused_clues) > 2

def check_if_clue_used_by_all_niches(clue, language=None):
    """
    Check if a clue has been used by all niches
    """
    niches = get_active_niches(language)
    
    for niche in niches:
        niche_dir = get_keywords_niche_path(niche, language)
        used_clue_file = os.path.join(niche_dir, "used_clue.txt")
        
        if not os.path.exists(used_clue_file):
            return False
        
        with open(used_clue_file, "r", encoding="utf-8") as f:
            used_clues = set(line.strip() for line in f if line.strip())
            if clue not in used_clues:
                return False
    
    return True

def mark_clues_as_processed(clues, output_dir=None, language=None):
    """
    Mark clues that have been processed
    
    Args:
        clues (list): List of processed clues
        output_dir (str): Directory to store processed clues
        language (str): Language to use
    """
    if not clues:
        return
    
    if output_dir is None:
        output_dir = get_kw_path(language)
    
    # File to store processed clues
    processed_file = os.path.join(output_dir, "processed_clue.txt")
    
    # Add clue to processed_clue.txt file
    with open(processed_file, "a", encoding="utf-8") as f:
        for clue in clues:
            f.write(f"{clue}\n")
    
    print(f"{len(clues)} clue marked as processed.")

def move_clues_to_used(clues, niche, language=None):
    """
    Move processed clues to used_clue.txt in the niche directory
    """
    if not clues:
        return
    
    niche_dir = get_keywords_niche_path(niche, language)
    used_clue_file = os.path.join(niche_dir, "used_clue.txt")
    
    # Read existing used clues
    existing_used = set()
    if os.path.exists(used_clue_file):
        with open(used_clue_file, "r", encoding="utf-8") as f:
            existing_used = set(line.strip() for line in f if line.strip())
    
    # Add new clues to used_clue.txt
    new_used_clues = []
    for clue in clues:
        if clue not in existing_used:
            new_used_clues.append(clue)
            existing_used.add(clue)
    
    if new_used_clues:
        with open(used_clue_file, "a", encoding="utf-8") as f:
            for clue in new_used_clues:
                f.write(f"{clue}\n")
        
        print(f"📝 Moved {len(new_used_clues)} clues to used_clue.txt for niche '{niche}'")

def get_popular_search_terms(niche_term, language, region, rate_limiter, cache):
    """
    Get popular search terms dengan enhanced request handling
    """
    # Check cache
    cache_params = {
        "method": "popular_search",
        "niche_term": niche_term,
        "language": language,
        "region": region
    }
    cached_result = cache.get(cache_params)
    if cached_result:
        print(f"Using cache data for popular search terms '{niche_term}'")
        return cached_result
    
    # Set rate limiting
    rate_limiter.wait_if_needed()
    
    try:
        # Google search format for popular search terms
        search_query = f"*+{niche_term}"
        encoded_query = requests.utils.quote(search_query)
        url = f"https://www.google.com/search?q={encoded_query}&hl={language}&gl={region}"
        
        # Additional headers for Google
        additional_headers = {
            "Referer": "https://www.google.com/"
        }
        
        # Use robust_request instead of direct handler call
        response = robust_request(url, headers=additional_headers, timeout=15)
        
        if response and response.status_code == 200:
            popular_terms = []
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for element in soup.select('.card-section li'):
                term_text = element.get_text().strip()
                if term_text and niche_term.lower() in term_text.lower():
                    popular_terms.append(term_text)
            
            # Alternative selection if HTML format changes
            for element in soup.select('div.BNeawe'):
                term_text = element.get_text().strip()
                if term_text and niche_term.lower() in term_text.lower() and ' ' in term_text:
                    popular_terms.append(term_text)
                    
            # Also search in "related searches"
            for element in soup.select('.ULSxyf'):
                term_text = element.get_text().strip()
                if term_text and ' ' in term_text:
                    popular_terms.append(term_text)
            
            # Deduplication of results
            popular_terms = remove_duplicates(popular_terms)
            
            # Save to cache
            cache.set(cache_params, popular_terms)
            
            return popular_terms
        else:
            print(f"Popular search terms request failed for '{niche_term}' - Status: {response.status_code if response else 'None'}")
            
    except Exception as e:
        print(f"Error getting popular search terms for '{niche_term}': {e}")
    
    return []

def get_available_relevant_clues(niche, clue_file_path, language, max_clues=5):
    """
    Get available clues that are relevant to the current niche
    Priority: unused relevant clues > unused generic clues > generate new
    
    Args:
        niche (str): Current niche being processed
        clue_file_path (str): Path to clue.txt file
        language (str): Language code
        max_clues (int): Maximum number of clues to return
        
    Returns:
        tuple: (list of relevant clues, bool indicating if generation needed)
    """
    print(f"🔍 Searching for relevant clues for niche: '{niche}'")
    
    # Read existing clues from clue.txt
    existing_clues = []
    if os.path.exists(clue_file_path):
        with open(clue_file_path, "r", encoding="utf-8") as f:
            existing_clues = [line.strip() for line in f if line.strip()]
    
    if not existing_clues:
        print("📝 No existing clues found in clue.txt")
        return [], True
    
    # Read all used clues to filter them out
    used_clues = get_all_used_clues(language)
    print(f"🚫 Found {len(used_clues)} total used clues to avoid")
    
    # Filter unused clues
    unused_clues = [clue for clue in existing_clues if clue.lower() not in used_clues]
    print(f"✅ Found {len(unused_clues)} unused clues from {len(existing_clues)} total clues")
    
    if not unused_clues:
        print("⚠️ All existing clues have been used")
        return [], True
    
    # Expand niche terms for better matching
    niche_terms = expand_niche_terms(niche)
    niche_words = set()
    for term in niche_terms:
        niche_words.update(term.lower().split())
    
    print(f"🎯 Niche matching words: {', '.join(sorted(niche_words))}")
    
    # Categorize clues by relevance
    highly_relevant_clues = []
    moderately_relevant_clues = []
    generic_clues = []
    
    for clue in unused_clues:
        clue_words = set(clue.lower().split())
        
        # Check for direct niche term matches
        if any(term.lower() in clue.lower() for term in niche_terms):
            highly_relevant_clues.append(clue)
        # Check for word overlap with niche
        elif niche_words.intersection(clue_words):
            moderately_relevant_clues.append(clue)
        else:
            generic_clues.append(clue)
    
    print(f"📊 Clue categorization:")
    print(f"   - Highly relevant: {len(highly_relevant_clues)}")
    print(f"   - Moderately relevant: {len(moderately_relevant_clues)}")
    print(f"   - Generic: {len(generic_clues)}")
    
    # Select clues with priority
    selected_clues = []
    
    # Priority 1: Highly relevant clues
    selected_clues.extend(highly_relevant_clues[:max_clues])
    
    # Priority 2: Moderately relevant clues if needed
    remaining_slots = max_clues - len(selected_clues)
    if remaining_slots > 0:
        selected_clues.extend(moderately_relevant_clues[:remaining_slots])
    
    # Priority 3: Generic clues if still needed
    remaining_slots = max_clues - len(selected_clues)
    if remaining_slots > 0:
        selected_clues.extend(generic_clues[:remaining_slots])
    
    if selected_clues:
        print(f"✅ Selected {len(selected_clues)} relevant clues: {', '.join(selected_clues)}")
        return selected_clues, False
    else:
        print("⚠️ No relevant unused clues found")
        return [], True

def get_all_used_clues(language):
    """
    Get all used clues from all sources
    
    Args:
        language (str): Language code
        
    Returns:
        set: Set of all used clues (lowercase)
    """
    used_clues = set()
    
    # Read global used_clue.txt
    global_used_file = os.path.join(get_kw_path(language), "used_clue.txt")
    if os.path.exists(global_used_file):
        with open(global_used_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("---"):
                    used_clues.add(line.lower())
    
    # Read used_clue.txt from all niche directories
    niches = get_active_niches(language)
    for niche_name in niches:
        niche_dir = get_keywords_niche_path(niche_name, language)
        niche_used_file = os.path.join(niche_dir, "used_clue.txt")
        if os.path.exists(niche_used_file):
            with open(niche_used_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        used_clues.add(line.lower())
    
    # Read legacy processed_clue.txt
    processed_file = os.path.join(get_kw_path(language), "processed_clue.txt")
    if os.path.exists(processed_file):
        with open(processed_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    used_clues.add(line.lower())
    
    return used_clues

def validate_clues_relevance_with_ai(clues, niche, language, max_batch_size=5):
    """
    Validate clue relevance using AI in batches to optimize token usage
    Single authentication, batch processing
    
    Args:
        clues (list): List of clues to validate
        niche (str): Current niche
        language (str): Language code
        max_batch_size (int): Maximum clues per batch
        
    Returns:
        list: List of validated relevant clues
    """
    if not clues:
        return []
    
    print(f"🤖 Validating {len(clues)} clues for niche '{niche}' using AI...")
    
    # Single authentication
    manager = AITokenManager()
    if not manager.authenticate():
        print("❌ AI authentication failed, returning original clues")
        return clues
    
    client = manager.client
    validated_clues = []
    
    # Process in batches
    for i in range(0, len(clues), max_batch_size):
        batch = clues[i:i+max_batch_size]
        batch_str = ', '.join(batch)
        
        print(f"🔍 Validating batch {i//max_batch_size + 1}: {batch_str}")
        
        configs = get_default_configurations()
        prompt = f"""Analyze these clues for relevance to the niche '{niche}' in {language}:
        
Clues to validate: {batch_str}

TASK: Return only the clues that are relevant or could be useful for finding keywords in the '{niche}' niche.

RULES:
1. Return only relevant clues, one per line
2. No explanations, quotes, or formatting
3. If a clue could help find '{niche}' related keywords, include it
4. Generic clues that work with any niche are acceptable
5. Language: {language}

Return format:
clue1
clue2
clue3"""

        try:
            response = client.chat.completions.create(
                model=manager.model_name,
                messages=[
                    {"role": "system", "content": f"You are a multilingual SEO expert. Analyze clue relevance for niche '{niche}' in {language}."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=150
            )
            
            ai_reply = response.choices[0].message.content.strip()
            
            # Parse AI response
            batch_validated = []
            for line in ai_reply.splitlines():
                line = line.strip().strip('•-*#→⇒•●■◆○').strip().strip('"\'<>[](){}').strip()
                if line and line.lower() in [clue.lower() for clue in batch]:
                    batch_validated.append(line)
            
            validated_clues.extend(batch_validated)
            print(f"✅ Batch validation: {len(batch_validated)}/{len(batch)} clues approved")
            
        except Exception as e:
            print(f"⚠️ AI validation failed for batch, keeping original: {str(e)}")
            validated_clues.extend(batch)
    
    print(f"🎯 Final validation result: {len(validated_clues)}/{len(clues)} clues validated")
    return validated_clues

def generate_clue_keywords_with_ai(niche, clue_file_path, language, max_clues=5):
    """
    Optimized clue generation with priority system:
    1. Check for relevant unused clues first
    2. Validate relevance with AI if needed
    3. Generate new clues only if insufficient relevant clues found
    """
    print(f"🎯 Starting clue management for niche: '{niche}'")
    
    # Step 1: Get available relevant clues
    available_clues, need_generation = get_available_relevant_clues(
        niche, clue_file_path, language, max_clues
    )
    
    # Step 2: If we have clues, validate their relevance with AI
    if available_clues:
        print(f"🤖 Validating {len(available_clues)} available clues with AI...")
        validated_clues = validate_clues_relevance_with_ai(
            available_clues, niche, language, max_batch_size=5
        )
        
        if len(validated_clues) >= 2:  # Minimum acceptable number
            print(f"✅ Using {len(validated_clues)} validated existing clues")
            return validated_clues
        else:
            print(f"⚠️ Only {len(validated_clues)} clues validated, need to generate more")
            need_generation = True
            max_clues = max_clues - len(validated_clues)  # Generate remaining needed
    else:
        validated_clues = []
    
    # Step 3: Generate new clues if needed
    if need_generation and max_clues > 0:
        print(f"🔧 Generating {max_clues} new clues for niche '{niche}'...")
        new_clues = generate_new_clues_with_ai(niche, clue_file_path, language, max_clues)
        validated_clues.extend(new_clues)
    
    # Step 4: Clean and update clue.txt file
    if validated_clues:
        update_clue_file(validated_clues, clue_file_path)
        print(f"✅ Clue management complete: {len(validated_clues)} clues ready for use")
    else:
        print("⚠️ No clues available after all processing")
        if os.path.exists(clue_file_path):
            with open(clue_file_path, "r", encoding="utf-8") as f:
                fallback_clues = [line.strip() for line in f if line.strip()][:3]
            if fallback_clues:
                print(f"🔄 Using fallback clues from file: {', '.join(fallback_clues)}")
                validated_clues = fallback_clues
    
    return validated_clues

def generate_new_clues_with_ai(niche, clue_file_path, language, max_clues):
    """
    Generate new clues using AI (single authentication)
    """
    # Single authentication for generation
    manager = AITokenManager()
    if not manager.authenticate():
        print("❌ AI authentication failed for clue generation")
        return []
    
    client = manager.client
    
    # Get used clues sample for avoidance
    used_clues = get_all_used_clues(language)
    used_clues_sample = list(used_clues)[:20]
    
    configs = get_default_configurations()
    prompt = configs["clue_prompt_template"].format(niche=niche, language=language)
    prompt += f"\n\nRULES:\n1. Generate {max_clues} new clues\n2. Each clue must be 1-2 words maximum\n3. Focus on '{niche}' niche relevance\n4. Avoid these used clues: {', '.join(used_clues_sample)}\n5. Return only clean words, no formatting"
    
    try:
        response = client.chat.completions.create(
            model=manager.model_name,
            messages=[
                {"role": "system", "content": f"You are a multilingual SEO assistant. Generate clean, niche-relevant clue words for '{niche}' in {language}."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=200
        )
        
        ai_reply = response.choices[0].message.content
        
        # Clean up response
        new_clues = []
        for line in ai_reply.splitlines():
            line = line.strip("•-*#→⇒•●■◆○").strip().strip('"\'<>[](){}').strip().lower().strip()
            
            if line and len(line.split()) <= 2 and line not in used_clues:
                new_clues.append(line)
                if len(new_clues) >= max_clues:
                    break
        
        print(f"🆕 Generated {len(new_clues)} new clues: {', '.join(new_clues)}")
        return new_clues
        
    except Exception as e:
        print(f"❌ Failed to generate new clues: {str(e)}")
        return []

def update_clue_file(new_clues, clue_file_path):
    """
    Update clue.txt file with new clues at the top, removing duplicates
    """
    if not new_clues:
        return
    
    # Read existing clues
    existing_clues = []
    if os.path.exists(clue_file_path):
        with open(clue_file_path, "r", encoding="utf-8") as f:
            existing_clues = [line.strip() for line in f if line.strip()]
    
    # Combine with new clues at top, remove duplicates
    all_clues = new_clues + existing_clues
    unique_clues = []
    seen = set()
    
    for clue in all_clues:
        clue_lower = clue.lower()
        if clue_lower not in seen:
            unique_clues.append(clue)
            seen.add(clue_lower)
    
    # Write back to file
    with open(clue_file_path, "w", encoding="utf-8") as f:
        for i, clue in enumerate(unique_clues):
            f.write(clue)
            if i < len(unique_clues) - 1:
                f.write("\n")
    
    print(f"📝 Updated clue.txt: {len(unique_clues)} total unique clues")

def cleanup_fully_used_clues(language=None):
    """
    Move clues that have been used by all niches to a global used_clue.txt
    """
    clue_file = os.path.join(get_kw_path(language), "clue.txt")
    global_used_file = os.path.join(get_kw_path(language), "used_clue.txt")
    
    if not os.path.exists(clue_file):
        return
    
    with open(clue_file, "r", encoding="utf-8") as f:
        all_clues = [line.strip() for line in f if line.strip()]
    
    fully_used_clues = []
    remaining_clues = []
    
    for clue in all_clues:
        if check_if_clue_used_by_all_niches(clue, language):
            fully_used_clues.append(clue)
        else:
            remaining_clues.append(clue)
    
    if fully_used_clues:
        # Move fully used clues to global used_clue.txt
        with open(global_used_file, "a", encoding="utf-8") as f:
            f.write(f"\n--- Moved on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---\n")
            for clue in fully_used_clues:
                f.write(f"{clue}\n")
        
        # Update clue.txt with remaining clues
        with open(clue_file, "w", encoding="utf-8") as f:
            for clue in remaining_clues:
                f.write(f"{clue}\n")
        
        print(f"🧹 Moved {len(fully_used_clues)} fully used clues to global used_clue.txt")
        print(f"📋 {len(remaining_clues)} clues remaining in clue.txt")

def generate_emergency_niche_keywords(current_niche, language):
    """
    Generate emergency niche-relevant keywords using AI when no valid keywords found
    
    Args:
        current_niche (str): Current active niche
        language (str): Target language
        
    Returns:
        list: Emergency generated keywords (2-3 keywords)
    """
    manager = AITokenManager()
    if not manager.authenticate():
        print("⚠️ AI not available for emergency keyword generation")
        return []
    
    client = manager.client
    
    prompt = f"""Generate 3 high-quality search keywords for the niche "{current_niche}" in {language} language.

REQUIREMENTS:
1. Each keyword MUST contain "{current_niche}"
2. Keywords should be 3-5 words long
3. Focus on commercial/buyer intent
4. Natural and commonly searched terms
5. Suitable for {language} speakers

Respond with a JSON array of exactly 3 keywords.
Example: ["keyword 1", "keyword 2", "keyword 3"]"""

    try:
        response = client.chat.completions.create(
            model=manager.model_name,
            messages=[
                {"role": "system", "content": f"You are an expert SEO researcher specializing in {language} keywords."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.5,
            max_tokens=200,
            response_format={"type": "json_object"}
        )
        
        ai_reply = response.choices[0].message.content.strip()
        
        # Extract JSON array
        json_start = ai_reply.find('[')
        json_end = ai_reply.rfind(']') + 1
        
        if json_start >= 0 and json_end > json_start:
            emergency_keywords = json.loads(ai_reply[json_start:json_end])
            
            # Validate each keyword
            validated = []
            for kw in emergency_keywords:
                if (current_niche.lower() in kw.lower() and 
                    3 <= len(kw.split()) <= 5):
                    validated.append(kw)
            
            if validated:
                print(f"🚑 Emergency keywords generated: {', '.join(validated)}")
                return validated
        
        print("⚠️ AI emergency generation returned invalid format")
        return []
        
    except Exception as e:
        print(f"❌ Emergency keyword generation failed: {e}")
        return []

def ensure_niche_in_keywords_with_ai(keywords, niche_terms, language):
    """
    Ensure each keyword contains at least one of the niche_terms.
    """
    if not keywords or not niche_terms:
        return keywords
    
    # Get primary niche term (first one is usually the current niche)
    primary_niche = niche_terms[0] if niche_terms else ""
    
    # Separate keywords that already contain niche_terms and those that do not
    already_ok = []
    need_fix = []
    for kw in keywords:
        if any(term.lower() in kw.lower() for term in niche_terms):
            already_ok.append(kw)
        else:
            need_fix.append(kw)
    
    print(f"✅ {len(already_ok)} keywords already contain niche terms")
    print(f"🔧 {len(need_fix)} keywords need niche term insertion")
    
    if not need_fix:
        return keywords

    # Prompt AI to fix keywords so they contain niche_terms naturally
    manager = AITokenManager()
    if not manager.authenticate():
        print("⚠️ AI authentication failed. Skipping niche fix.")
        return already_ok  # Return only the keywords that already have niche terms

    client = manager.client
    niche_str = ", ".join([f'"{term}"' for term in niche_terms])
    prompt = (
        f"Edit the following keywords so that each contains the primary niche term '{primary_niche}' "
        f"or one of these alternatives: {niche_str}. "
        f"Place the niche term in the most natural position for a human reader in {language}. "
        "Do not change the meaning of the keyword, only insert the niche term if missing. "
        "CRITICAL: The result must contain the niche term to be valid. "
        "Reply with a JSON array of the fixed keywords in the same order."
        f"\n\nKeywords to fix:\n{json.dumps(need_fix, ensure_ascii=False)}"
    )

    try:
        response = client.chat.completions.create(
            model=manager.model_name,
            messages=[
                {"role": "system", "content": "You are an expert SEO and language assistant. Always ensure niche terms are included."},
                {"role": "user", "content": prompt}
            ],
            temperature=0,
            max_tokens=200,
            response_format={"type": "json_object"}
        )
        ai_reply = response.choices[0].message.content.strip()
        json_start = ai_reply.find('[')
        json_end = ai_reply.rfind(']') + 1
        if json_start >= 0 and json_end > json_start:
            fixed = json.loads(ai_reply[json_start:json_end])
            
            # Validate that fixed keywords actually contain niche terms
            validated_fixed = []
            for orig, fix in zip(need_fix, fixed):
                if any(term.lower() in fix.lower() for term in niche_terms):
                    validated_fixed.append(fix)
                    print(f"✅ Fixed: '{orig}' → '{fix}'")
                else:
                    print(f"❌ AI failed to add niche term to: '{orig}' → '{fix}'")
                    # Try to manually add primary niche term
                    manual_fix = f"{primary_niche} {orig}"
                    validated_fixed.append(manual_fix)
                    print(f"🔧 Manual fix: '{orig}' → '{manual_fix}'")
            
            return already_ok + validated_fixed
        else:
            print("⚠️ AI did not return valid JSON array for niche fix.")
            # Manual fallback: add primary niche to each keyword
            manual_fixes = [f"{primary_niche} {kw}" for kw in need_fix]
            return already_ok + manual_fixes
    except Exception as e:
        print(f"❌ Failed to fix keywords with AI: {e}")
        # Manual fallback: add primary niche to each keyword
        manual_fixes = [f"{primary_niche} {kw}" for kw in need_fix]
        return already_ok + manual_fixes
    
def validate_niche_consistency(keywords, target_niche):
    """
    Validate that all keywords are consistent with the target niche
    
    Args:
        keywords (list): List of keywords to validate
        target_niche (str): The target niche they should belong to
        
    Returns:
        tuple: (valid_keywords, invalid_keywords)
    """
    valid = []
    invalid = []
    
    target_niche_lower = target_niche.lower()
    
    for kw in keywords:
        if target_niche_lower in kw.lower():
            valid.append(kw)
        else:
            invalid.append(kw)
    
    if invalid:
        print(f"⚠️ Found {len(invalid)} keywords not matching niche '{target_niche}': {', '.join(invalid[:3])}{'...' if len(invalid) > 3 else ''}")
    
    return valid, invalid

def validate_and_ensure_niche_keywords(keywords, current_niche, niche_terms, language):
    """
    Validate keywords and ensure at least one valid keyword with niche exists
    If no valid keywords found, force create some using AI
    
    Args:
        keywords (list): List of keywords to validate
        current_niche (str): Current active niche
        niche_terms (list): List of niche terms
        language (str): Target language
        
    Returns:
        list: At least 1 valid keyword guaranteed
    """
    if not keywords:
        print("⚠️ No keywords provided for validation")
        return generate_emergency_niche_keywords(current_niche, language)
    
    # Check for niche-relevant keywords
    valid_keywords = []
    for kw in keywords:
        if any(term.lower() in kw.lower() for term in niche_terms):
            # Additional validation: proper length and language
            if 3 <= count_total_words(kw) <= 6:
                valid_keywords.append(kw)
    
    print(f"📊 Validation result: {len(valid_keywords)} valid keywords from {len(keywords)} total")
    
    # If we have valid keywords, return them
    if valid_keywords:
        return valid_keywords
    
    print(f"⚠️ No valid keywords found! Generating emergency keywords for niche: {current_niche}")
    
    # Emergency: generate keywords using AI
    emergency_keywords = generate_emergency_niche_keywords(current_niche, language)
    
    # If emergency generation also fails, create basic keywords
    if not emergency_keywords:
        print("⚠️ Emergency generation failed. Creating basic keywords.")
        basic_keywords = [
            f"best {current_niche}",
            f"{current_niche} reviews",
            f"cheap {current_niche}",
            f"{current_niche} price",
            f"buy {current_niche}"
        ]
        return basic_keywords[:2]  # Return only 2 basic keywords
    
    return emergency_keywords

def validate_keywords_language(language_code, niche=None, use_ai=True, language=None, newly_added_keywords=None):
    """
    Re-validate all keywords in keywords.txt to match the target language.
    """
    # Setup validation cache to avoid rechecking same words
    validation_cache_dir = os.path.join(get_keywords_cache_path(language), "validation")
    os.makedirs(validation_cache_dir, exist_ok=True)
    
    # Cache key for this validation session
    validation_cache_key = f"{language_code}_validation.json"
    validation_cache_path = os.path.join(validation_cache_dir, validation_cache_key)
    
    # Load existing validation results
    validation_cache = {}
    if os.path.exists(validation_cache_path):
        try:
            with open(validation_cache_path, 'r', encoding='utf-8') as f:
                validation_cache = json.load(f)
        except:
            print("⚠️ Could not load validation cache. Starting fresh.")
    
    if niche is None:
        # Read niche from file
        niche_file = os.path.join(get_kw_path(language), "niche.txt")
        if os.path.exists(niche_file):
            with open(niche_file, "r", encoding="utf-8") as f:
                niche = f.read().strip().split('\n')[0]  # Use first niche if multiple
        else:
            niche = "general"  # Default niche if niche.txt doesn't exist
    
    # Get niche terms for this validation
    niche_terms = expand_niche_terms(niche)
    if niche.lower() not in [term.lower() for term in niche_terms]:
        niche_terms.insert(0, niche)
    
    print(f"🎯 Validating for niche: {niche}")
    print(f"🎯 Niche terms: {', '.join(niche_terms)}")
    
    keyword_file = os.path.join(get_keywords_path(language), niche, "keywords.txt")
    if not os.path.exists(keyword_file):
        print(f"⚠️ File keywords.txt not found for niche: {niche}")
        return

    with open(keyword_file, "r", encoding="utf-8") as f:
        keywords = [line.strip() for line in f if line.strip()]

    if not keywords:
        print(f"⚠️ File keywords.txt is empty for niche: {niche}")
        return

    print(f"\n🔍 Validating {len(keywords)} keywords for language: {language_code} and niche: {niche}...")

    # Store original keywords for comparison
    original_keywords = keywords.copy()
    
    # Track newly added keywords from current session
    session_new_keywords = newly_added_keywords or []

    # Separate keywords into cached and new
    cached_valid_keywords = []
    cached_invalid_keywords = []
    new_keywords = []
    
    for kw in keywords:
        if kw in validation_cache:
            if validation_cache[kw]:
                cached_valid_keywords.append(kw)
            else:
                cached_invalid_keywords.append(kw)
        else:
            new_keywords.append(kw)
    
    print(f"✅ {len(cached_valid_keywords)} keywords found valid in validation cache")
    print(f"❌ {len(cached_invalid_keywords)} keywords found invalid in validation cache")
    print(f"🔍 Validating {len(new_keywords)} new keywords...")
    
    # Track validation results for new keywords
    newly_valid_keywords = []
    newly_invalid_keywords = []
    configs = get_default_configurations()

    if use_ai and new_keywords:
        manager = AITokenManager()
        if not manager.authenticate():
            print("⚠️ AI authentication failed. Continuing with standard method.")
            return validate_keywords_language(language_code, niche, use_ai=False)

        client = manager.client
        # Increase batch size for more efficiency
        chunk_size = 50  # Increased from 20
        
        for i in range(0, len(new_keywords), chunk_size):
            batch = new_keywords[i:i+chunk_size]
            
            # Include niche validation in AI prompt
            niche_instruction = f"Keywords MUST contain at least one of these niche terms: {', '.join(niche_terms)}"
            
            prompt = configs["language_validation_prompt"].format(
                language_code=language_code,
                keywords="\n".join(f"- {kw}" for kw in batch)
            )
            prompt += (
                f"\n\nIMPORTANT VALIDATION RULES (in order of priority):\n"
                f"1. MUST contain niche terms: {', '.join(niche_terms)} (HIGHEST PRIORITY)\n"
                f"2. Should be in {language_code.upper()} language (but flexible for niche-relevant keywords)\n"
                f"3. Should be 3-6 words long (but flexible for niche-relevant keywords)\n"
                f"4. If keyword contains main niche '{niche_terms[0]}', be more lenient with other rules\n"
                f"5. Accept keywords that are commercially relevant for '{niche_terms[0]}' niche\n"
                "Format your response as a valid JSON array containing only the valid keywords. Example: [\"keyword one\", \"keyword two\"]"
            )
            
            try:
                response = client.chat.completions.create(
                    model=manager.model_name,
                    messages=[
                        {"role": "system", "content": "You are a highly accurate language assistant that responds with properly formatted JSON arrays."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.3,
                    max_tokens=800,  # Increased for larger batches
                    response_format={"type": "json_object"}
                )
                ai_reply = response.choices[0].message.content.strip()
                
                try:
                    json_start = ai_reply.find('[')
                    json_end = ai_reply.rfind(']') + 1
                    
                    if json_start >= 0 and json_end > json_start:
                        json_text = ai_reply[json_start:json_end]
                        ai_keywords = json.loads(json_text)
                    else:
                        parsed = json.loads(ai_reply)
                        if isinstance(parsed, dict) and "keywords" in parsed:
                            ai_keywords = parsed["keywords"]
                        elif isinstance(parsed, list):
                            ai_keywords = parsed
                        else:
                            raise ValueError("No valid keyword list found in response")
                    
                    for kw in batch:
                        # Primary validation: niche relevance and length
                        has_niche = any(term.lower() in kw.lower() for term in niche_terms)
                        is_valid_length = 3 <= count_total_words(kw) <= 6
                        
                        # If passes primary validation, accept regardless of AI result
                        if has_niche and is_valid_length:
                            # Secondary check: AI validation (less strict)
                            is_in_ai_result = kw in ai_keywords
                            
                            # Accept if either passes AI validation OR has strong niche relevance
                            main_niche = niche_terms[0] if niche_terms else ""
                            has_strong_niche = main_niche.lower() in kw.lower()
                            
                            if is_in_ai_result or has_strong_niche:
                                validation_cache[kw] = True
                                newly_valid_keywords.append(kw)
                            else:
                                # Give benefit of doubt for niche-relevant keywords
                                print(f"⚠️ Accepting '{kw}' despite AI validation - strong niche relevance")
                                validation_cache[kw] = True
                                newly_valid_keywords.append(kw)
                        else:
                            validation_cache[kw] = False
                            newly_invalid_keywords.append(kw)
                            # Log why it was removed
                            if not has_niche:
                                print(f"❌ Removed '{kw}' - missing niche terms")
                            elif not is_valid_length:
                                print(f"❌ Removed '{kw}' - invalid length")
                            
                except (json.JSONDecodeError, ValueError) as json_err:
                    print(f"❌ Failed to parse AI response as JSON: {json_err}")
                    print("⏩ Using fallback validation for this batch.")
                    for kw in batch:
                        # Fallback: prioritize niche relevance over strict AI validation
                        has_niche = any(term.lower() in kw.lower() for term in niche_terms)
                        is_valid_length = 3 <= count_total_words(kw) <= 6
                        is_valid_lang = validate_language(kw, language_code, '', niche_terms)
                        
                        # Accept if has niche relevance and basic validation
                        is_valid = has_niche and is_valid_length and is_valid_lang
                        
                        validation_cache[kw] = is_valid
                        if is_valid:
                            newly_valid_keywords.append(kw)
                        else:
                            newly_invalid_keywords.append(kw)
                            
            except Exception as e:
                print(f"❌ Failed to process AI batch: {e}")
                print("⏩ Continuing with standard method for this batch.")
                for kw in batch:
                    # Always check niche relevance first
                    has_niche = any(term.lower() in kw.lower() for term in niche_terms)
                    is_valid_lang = validate_language(kw, language_code, '', niche_terms)
                    is_valid = has_niche and is_valid_lang and 3 <= count_total_words(kw) <= 6
                    
                    validation_cache[kw] = is_valid
                    if is_valid:
                        newly_valid_keywords.append(kw)
                    else:
                        newly_invalid_keywords.append(kw)
    
    elif new_keywords:
        # Fast check for individual keywords without AI
        for kw in new_keywords:
            # Check niche relevance first (most important)
            has_niche = any(term.lower() in kw.lower() for term in niche_terms)
            is_valid_length = 3 <= count_total_words(kw) <= 6
            is_valid_lang = validate_language(kw, language_code, '', niche_terms)
            
            # Prioritize niche relevance - more lenient for niche-relevant keywords
            if has_niche and is_valid_length:
                # For niche-relevant keywords, be more lenient with language validation
                validation_cache[kw] = True
                newly_valid_keywords.append(kw)
            elif has_niche and is_valid_lang:
                # Accept if has niche even with borderline length
                print(f"⚠️ Accepting '{kw}' - strong niche relevance despite length")
                validation_cache[kw] = True
                newly_valid_keywords.append(kw)
            else:
                validation_cache[kw] = False
                newly_invalid_keywords.append(kw)

    # Save updated validation cache
    try:
        with open(validation_cache_path, 'w', encoding='utf-8') as f:
            json.dump(validation_cache, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"⚠️ Failed to save validation cache: {e}")

    # Calculate final results
    all_valid_keywords = cached_valid_keywords + newly_valid_keywords
    all_invalid_keywords = cached_invalid_keywords + newly_invalid_keywords
    
    # Print accurate validation summary
    print(f"\n📊 VALIDATION SUMMARY:")
    print(f"   • Total keywords processed: {len(keywords)}")
    print(f"   • From cache - Valid: {len(cached_valid_keywords)}, Invalid: {len(cached_invalid_keywords)}")
    print(f"   • Newly validated - Valid: {len(newly_valid_keywords)}, Invalid: {len(newly_invalid_keywords)}")
    print(f"   • Final result - Valid: {len(all_valid_keywords)}, Invalid: {len(all_invalid_keywords)}")

    # Ensure at least 1 valid keyword exists
    if not all_valid_keywords:
        print(f"🚑 CRITICAL: No valid keywords found after validation for niche '{niche}'!")
        print(f"🚑 Attempting to inject niche terms into removed keywords...")
        
        # Try to salvage some keywords by injecting niche
        if all_invalid_keywords:
            # Take first few invalid keywords and inject niche
            salvage_candidates = all_invalid_keywords[:5]
            injected_keywords = force_inject_niche_into_keywords(
                salvage_candidates, niche, niche_terms, language_code
            )
            
            # Validate injected keywords
            for kw in injected_keywords:
                if (any(term.lower() in kw.lower() for term in niche_terms) and 
                    3 <= count_total_words(kw) <= 6):
                    all_valid_keywords.append(kw)
                    print(f"✅ Salvaged keyword: '{kw}'")
                    if len(all_valid_keywords) >= 2:  # Limit to 2 salvaged keywords
                        break
        
        # If still no valid keywords, generate emergency ones
        if not all_valid_keywords:
            print(f"🚑 Generating emergency keywords for niche '{niche}'...")
            emergency_keywords = generate_emergency_niche_keywords(niche, language_code)
            all_valid_keywords.extend(emergency_keywords)

    # Ensure we have at least 1 keyword
    if not all_valid_keywords:
        print(f"🚑 FINAL FALLBACK: Creating basic keyword for niche '{niche}'")
        all_valid_keywords = [f"best {niche}"]

    # Determine what changed - FIXED LOGIC
    original_keyword_set = set(original_keywords)
    final_keyword_set = set(all_valid_keywords)
    
    # Calculate actual changes
    new_keywords_added = final_keyword_set - original_keyword_set
    removed_keywords = original_keyword_set - final_keyword_set
    unchanged_keywords = original_keyword_set & final_keyword_set
    
    # Include session new keywords in calculation
    if session_new_keywords:
        session_new_set = set(session_new_keywords)
        # Keywords that were added in this session and are still valid
        session_valid_new = session_new_set & final_keyword_set
        new_keywords_added = new_keywords_added | session_valid_new
    
    # Debug information
    print(f"🔍 DEBUG - Change Analysis:")
    print(f"   Original keywords: {len(original_keyword_set)}")
    print(f"   Final keywords: {len(final_keyword_set)}")
    print(f"   Session new keywords: {len(session_new_keywords) if session_new_keywords else 0}")
    print(f"   New keywords added: {len(new_keywords_added)}")
    print(f"   Removed keywords: {len(removed_keywords)}")
    print(f"   Unchanged keywords: {len(unchanged_keywords)}")
    if new_keywords_added:
        print(f"   Added: {', '.join(list(new_keywords_added))}")
    if removed_keywords:
        print(f"   Removed: {', '.join(list(removed_keywords))}")
    
    # Determine if there are actual changes
    has_changes = (len(all_valid_keywords) != len(original_keywords) or 
                   new_keywords_added or 
                   removed_keywords or
                   set(all_valid_keywords) != set(original_keywords) or
                   all_valid_keywords != original_keywords or
                   bool(session_new_keywords))
    
    print(f"🔍 Content change detection: {has_changes}")
    
    # Save results if there are changes
    if has_changes:
        with open(keyword_file, "w", encoding="utf-8") as f:
            for keyword in all_valid_keywords:
                f.write(f"{keyword}\n")

        # Save removed keywords if any
        if removed_keywords:
            removed_file = os.path.join(get_keywords_path(language), niche, "removed_keywords.txt")
            with open(removed_file, "a", encoding="utf-8") as f:
                f.write(f"\n--- Removed on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---\n")
                for keyword in removed_keywords:
                    f.write(f"{keyword}\n")
            print(f"📝 Removed keywords saved in: {removed_file}")

        print(f"\n✅ VALIDATION COMPLETE:")
        added_count = len(new_keywords_added)
        removed_count = len(removed_keywords)
        
        if added_count > 0:
            print(f"   • {added_count} new keywords added: {', '.join(list(new_keywords_added)[:3])}{'...' if added_count > 3 else ''}")
        if removed_count > 0:
            print(f"   • {removed_count} keywords removed")
        print(f"   • {len(all_valid_keywords)} total valid keywords remain")
        
        # Accurate process completion message - prioritize session new keywords
        if session_new_keywords and len(session_new_keywords) > 0:
            session_valid_count = len(set(session_new_keywords) & set(all_valid_keywords))
            print(f"Process complete! {session_valid_count} new keywords from current session added, {removed_count} removed, {len(all_valid_keywords)} total keywords.")
        else:
            print(f"Process complete! {added_count} new keywords added, {removed_count} removed, {len(all_valid_keywords)} total keywords.")
        
    else:
        # Double check - maybe keywords were reordered or had subtle formatting changes
        content_actually_changed = (set(all_valid_keywords) != set(original_keywords) or 
                                  all_valid_keywords != original_keywords)
        
        if content_actually_changed:
            print(f"✅ Keywords reformatted/reordered - subtle content changes detected")
            added_count = len(new_keywords_added)
            removed_count = len(removed_keywords)
            print(f"Process complete! {added_count} new keywords added, {removed_count} removed, {len(all_valid_keywords)} total keywords.")
        else:
            print(f"✅ All {len(original_keywords)} keywords are valid - no changes needed")
            print(f"Process complete! 0 new keywords added, 0 removed, {len(original_keywords)} total keywords.")

    return all_valid_keywords

def clean_keywords_file(filepath):
    """
    Ensure keywords.txt contains only valid keywords, no empty lines in the middle,
    and only 1 blank line at the end of the file.
    """
    if not os.path.exists(filepath):
        return
    with open(filepath, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]
    if not lines:
        return
    with open(filepath, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(f"{line}\n")
        f.write("\n")  # Only 1 blank line at the end

def count_total_words(text):
    """
    Counts the total number of words in a text.
    """
    return len(text.strip().split())

def show_request_stats():
    """
    Show statistik request handler
    """
    try:
        handler = get_request_handler()
        stats = handler.get_stats()
        
        print("\n" + "="*50)
        print("🔍 REQUEST HANDLER STATISTICS")
        print("="*50)
        print(f"Total User Agents: {stats['total_user_agents']}")
        print(f"Blocked User Agents: {stats['blocked_user_agents']}")
        print(f"Global Success Rate: {stats['global_success_rate']:.1f}%")
        print(f"Total Requests: {stats['total_requests']}")
        print(f"Total Blocks: {stats['total_blocks']}")
        print("="*50)
        
    except Exception as e:
        print(f"Could not display request stats: {e}")

def main():
    # Setup UTF-8 encoding first before any output
    if sys.stdout.encoding.lower() != 'utf-8':
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    if sys.stderr.encoding.lower() != 'utf-8':
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

    def cleanup_on_exit():
        cleanup_request_handler()
        
    atexit.register(cleanup_on_exit)
    
    def signal_handler(sig, frame):
        print("\n🛑 Process interrupted by user. Cleaning up...")
        cleanup_request_handler()
        sys.exit(0)
        
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Get active language
    active_language = get_active_language()
    remove_deleted_niche_folders(language=active_language)
    
    # Ensure dependencies are installed
    ensure_dependencies()
    ensure_directory_structure(active_language)
    
    # Clear all removed_keywords.txt files at start
    print("\n🧹 Clearing previous removed_keywords.txt files and logs...")
    clear_removed_keywords_files(active_language)
    clear_logs(active_language)
    
    # Initialize logger
    logger = setup_logging(language=active_language)
    logger.info("=" * 60)
    logger.info("AUTOMATIC KEYWORD RESEARCH TOOL")
    logger.info("=" * 60)
    
    # Ensure default configuration
    ensure_default_config(language=active_language)
    
    # Clean up old files
    cache_dir = get_keywords_cache_path(active_language)
    logs_dir = get_keywords_logs_path(active_language)
    cleanup_old_files(cache_dir)
    limit_cache_size(cache_dir)
    
    # Check internet connection
    if not check_internet_connection():
        logger.error("ERROR: Cannot connect to internet. Please ensure an active internet connection.")
        return

    # Get active niches
    niches = get_active_niches(active_language)
    if not niches:
        logger.error("No niches defined in niche.txt file.")
        return

    logger.info("=" * 40)
    logger.info(f"Found {len(niches)} niches to process: {', '.join(niches)}")
    logger.info("=" * 40)

    last_niche = get_last_processed_niche(active_language)
    
    # Determine which niche to process
    if last_niche is None:
        current_niche = niches[0]
        logger.info("Starting with first niche")
    else:
        try:
            last_index = niches.index(last_niche)
            if last_index + 1 < len(niches):
                current_niche = niches[last_index + 1]
                logger.info(f"Continuing from last processed niche: {last_niche}")
            else:
                current_niche = niches[0]
                logger.info("All niches completed, starting over")
        except ValueError:
            current_niche = niches[0]
            logger.info("Last processed niche not found, starting with first")

    logger.info("=" * 40)
    logger.info(f"🎯 PROCESSING NICHE {niches.index(current_niche) + 1}/{len(niches)}: '{current_niche}'")
    logger.info("=" * 40)

    try:
        # Ensure niche directory exists
        niche_dir = os.path.join(get_keywords_path(active_language), current_niche)
        os.makedirs(niche_dir, exist_ok=True)
        logger.info(f"📁 Niche directory: {niche_dir}")
        
        # Read supported languages and regions
        language_file = os.path.join(get_kw_path(active_language), "language.txt")
        supported_language_regions = []
        language_code_map = {}
        
        if os.path.exists(language_file):
            with open(language_file, "r", encoding="utf-8") as f:
                supported_language_regions = [line.strip().lower() for line in f if line.strip()]
                # Create mapping of country codes to language codes
                for entry in supported_language_regions:
                    if ":" in entry:
                        country_code, lang_code = entry.split(":", 1)
                        language_code_map[country_code.strip()] = lang_code.strip()
        else:
            configs = get_default_configurations()
            language_code_map = configs["country_language_mapping"]
            supported_language_regions = [f"{k}:{v}" for k, v in language_code_map.items()]
        
        # Read region/country code
        region_file = os.path.join(get_kw_path(active_language), "region.txt")
        if os.path.exists(region_file):
            with open(region_file, "r", encoding="utf-8") as f:
                region = f.read().strip().lower()
        else:
            region = "za"  # Default to South Africa
        
        # Get language code based on region
        if region in language_code_map:
            language = language_code_map[region]
        else:
            language = "en"  # Default to English if region not in mapping
            
        logger.info(f"Selected region: {region}")
        logger.info(f"Selected language: {language}")
        logger.info(f"🎯 Current niche: {current_niche}")

        # Initialize AITokenManager and setup auto encryption
        manager = AITokenManager()
        setup_auto_encryption(manager)

        # Generate fresh user agent before scraping
        generate_fresh_user_agent_with_ai(active_language)

        # Single AI authentication for entire clue process
        clue_file = os.path.join(get_kw_path(active_language), "clue.txt")
        print(f"\n🎯 Starting optimized clue management for niche: '{current_niche}'")
        
        # This function now handles: checking existing relevant clues, AI validation, and generation if needed
        available_clues = generate_clue_keywords_with_ai(current_niche, clue_file, language)

        # DEBUG: Log available_clues result
        print(f"🔍 DEBUG: available_clues result: {available_clues}")
        print(f"🔍 DEBUG: available_clues count: {len(available_clues) if available_clues else 0}")
        print(f"🔍 DEBUG: available_clues type: {type(available_clues)}")
        
        if not available_clues:
            print("❌ DEBUG: No clues available from generate_clue_keywords_with_ai()")
            # Coba baca langsung dari file clue.txt sebagai fallback
            if os.path.exists(clue_file):
                with open(clue_file, "r", encoding="utf-8") as f:
                    fallback_clues = [line.strip() for line in f if line.strip()][:5]
                if fallback_clues:
                    print(f"🔄 Using fallback clues from file: {', '.join(fallback_clues)}")
                    available_clues = fallback_clues
                else:
                    print("❌ No fallback clues available in clue.txt")
            else:
                print("❌ clue.txt file does not exist")
        
        # Cleanup fully used clues before processing
        cleanup_fully_used_clues(active_language)
            
        # Always include the current niche name
        niche_terms = expand_niche_terms(current_niche)
        # Ensure current niche is always included in niche_terms
        if current_niche.lower() not in [term.lower() for term in niche_terms]:
            niche_terms.insert(0, current_niche)
        
        logger.info(f"🎯 Niche terms for filtering: {', '.join(niche_terms)}")
        
        # Use the optimized clue management result
        if not available_clues:
            logger.error(f"No clues available for niche '{current_niche}'. Skipping.")
            return
        
        # ONLY use paired seeds from niche_terms and available_clues (instead of all_clues)
        paired_seeds = generate_niche_clue_pairs(niche_terms, available_clues)
        logger.info(f"Generated {len(paired_seeds)} niche-clue pairs for '{current_niche}'.")

        MAX_SEEDS = 200
        if len(paired_seeds) > MAX_SEEDS:
            paired_seeds = paired_seeds[:MAX_SEEDS]
            logger.info(f"Limited paired seeds to {MAX_SEEDS} for performance.")
    
        # Expand paired seeds for more variations (optional, or just use paired_seeds directly)
        expanded_seeds = expand_seed_keywords(paired_seeds, language, region)
        logger.info(f"Expanded {len(paired_seeds)} seed keywords to {len(expanded_seeds)} variations")

        MAX_EXPANDED = 1000
        if len(expanded_seeds) > MAX_EXPANDED:
            expanded_seeds = expanded_seeds[:MAX_EXPANDED]
            logger.info(f"Limited expanded seeds to {MAX_EXPANDED} for performance.")
        
        # Cache initialization and rate limiter
        cache = KeywordCache(language=active_language)
        rate_limiter = RateLimiter()
        
        handler = get_request_handler(active_language)
        initial_stats = handler.get_stats()
        logger.info(f"🔧 Request Handler initialized - Success rate: {initial_stats['global_success_rate']:.1f}%")
        
        # Get popular search terms for each niche term
        popular_terms = []
        for term in niche_terms:
            terms = get_popular_search_terms(term, language, region, rate_limiter, cache)
            popular_terms.extend(terms)
        
        # Process clues with improved management
        current_clues, has_more_clues = manage_clue_processing(available_clues, current_niche, language=active_language)
        
        keywords_found = False
        clue_attempt_count = 0
        max_clue_attempts = 3
        if not current_clues and available_clues:
            print(f"⚠️ No unused clues found, using first 2 available clues as fallback")
            current_clues = available_clues[:2]
            has_more_clues = True
        
        print(f"🔍 Starting keyword processing with clues: {', '.join(current_clues) if current_clues else 'None'}")

        while (current_clues or available_clues) and clue_attempt_count < max_clue_attempts:
            clue_attempt_count += 1
            print(f"🔄 Clue processing attempt {clue_attempt_count}/{max_clue_attempts}")
            
            if not current_clues and available_clues:
                current_clues = available_clues[:2]
                print(f"📝 Using available clues: {', '.join(current_clues)}")
            
            if not current_clues:
                print("❌ No clues available for processing")
                break
                
            seed_keywords = current_clues.copy()

            # Add popular terms to seed keywords
            seed_keywords.extend(popular_terms)
        
            # Combine clue keywords with niche to ensure relevance
            niche_focused_seeds = []
            for seed in seed_keywords:
                if any(term in seed.lower() for term in niche_terms):
                    niche_focused_seeds.append(seed)
                else:
                    for term in niche_terms:
                        niche_focused_seeds.append(f"{seed} {term}")
                        niche_focused_seeds.append(f"{term} {seed}")
            niche_focused_seeds = list(dict.fromkeys(niche_focused_seeds))
            logger.info(f"Original clue keywords: {', '.join(seed_keywords)}")
            logger.info(f"Niche-focused seeds: {', '.join(niche_focused_seeds)}")
        
            # Expand seed keywords to get more variations
            expanded_seeds = expand_seed_keywords(niche_focused_seeds, language, region)
            logger.info(f"Expanded {len(niche_focused_seeds)} seed keywords to {len(expanded_seeds)} variations")
            
            logger.info(f"Language: {language}")
            logger.info(f"Region: {region}")
            
            # Minimum number of words in keyword
            min_words = 3
            
            # Get suggestions from Google using expanded seeds - PASS niche_terms for filtering
            all_suggestions = get_search_engine_suggestions(language, region, expanded_seeds, niche_terms=niche_terms)
            
            # Primary filter - MUST contain current niche
            niche_filtered_keywords = []
            for kw in all_suggestions:
                # Check if keyword contains ANY of the niche terms (more flexible)
                if any(term.lower() in kw.lower() for term in niche_terms):
                    niche_filtered_keywords.append(kw)
                # Also check for partial matches of main niche
                elif any(word in current_niche.lower().split() for word in kw.lower().split()):
                    niche_filtered_keywords.append(kw)
            
            print(f"✅ After niche filtering for '{current_niche}': {len(niche_filtered_keywords)} keywords")
            
            # Apply other filters while preserving niche relevance
            filtered_keywords = []
            for kw in niche_filtered_keywords:
                # Word count filter - more flexible range
                if 2 <= count_total_words(kw) <= 7:  # Expanded range
                    # More flexible non-connecting words check
                    non_connecting_count = count_non_connecting_words(kw, language)
                    
                    # Accept if has min_words OR is niche-relevant
                    has_enough_words = non_connecting_count >= min_words
                    is_niche_relevant = any(term.lower() in kw.lower() for term in niche_terms)
                    
                    if has_enough_words or is_niche_relevant:
                        # Validate language with niche_terms parameter
                        if validate_language(kw, language, region, niche_terms):
                            # More flexible niche check
                            if any(term.lower() in kw.lower() for term in niche_terms):
                                filtered_keywords.append(kw)
            
            # Remove duplicates and suspicious queries
            filtered_keywords = remove_duplicates(filtered_keywords)
            filtered_keywords = [kw for kw in filtered_keywords if not is_suspicious_query(kw)]
            
            # Filter badwords but preserve niche-relevant keywords
            pre_badword_count = len(filtered_keywords)
            filtered_keywords = filter_badwords(filtered_keywords)
            
            # If badword filter removed niche-relevant keywords, warn but continue
            if len(filtered_keywords) < pre_badword_count:
                removed_by_badwords = pre_badword_count - len(filtered_keywords)
                print(f"⚠️ {removed_by_badwords} keywords removed by badword filter")
            
            logger.info(f"🎯 After all filtering for '{current_niche}': {len(filtered_keywords)} relevant keywords")
            
            # Check duplicates with existing keywords
            existing_keywords = []
            try:
                existing_file = os.path.join(get_keywords_niche_path(current_niche, active_language), "keywords.txt")
                if os.path.exists(existing_file):
                    with open(existing_file, "r", encoding="utf-8") as f:
                        existing_keywords = [line.strip() for line in f if line.strip()]
            except Exception as e:
                logger.error(f"Error reading existing keywords file: {str(e)}")
            
            # Filter based on similarity and common words - but preserve niche relevance
            max_keywords_to_save = 5
            new_keywords = []
            
            for kw in filtered_keywords:
                # Skip similarity check if keyword is highly niche-relevant
                is_highly_relevant = current_niche.lower() in kw.lower()
                
                should_skip = False
                
                # Only apply strict similarity checks if not highly relevant
                if not is_highly_relevant:
                    for existing_kw in existing_keywords:
                        # Check for similarity
                        if is_similar(kw.lower(), existing_kw.lower()):
                            should_skip = True
                            break
                            
                        common_words = set(kw.lower().split()) & set(existing_kw.lower().split())
                        niche_words = set([term.lower() for term in niche_terms])
                        non_niche_common_words = common_words - niche_words
                        # Check if there are 2 or more common words that are not niche
                        if len(non_niche_common_words) >= 2:
                            should_skip = True
                            break
                            
                        # Check if it has 3 or more common words
                        if count_common_words(kw, existing_kw) >= 4:
                            should_skip = True
                            break
                
                # Also check against keywords we've already decided to keep
                for new_kw in new_keywords:
                    if count_common_words(kw, new_kw) >= 3:
                        should_skip = True
                        break
                
                if not should_skip:
                    new_keywords.append(kw)
                    if len(new_keywords) >= max_keywords_to_save:
                        break
            
            # If no keywords found, try to inject niche into filtered keywords
            if not new_keywords and filtered_keywords:
                print(f"⚠️ No new keywords passed similarity check. Attempting niche injection...")
                injection_candidates = filtered_keywords[:3]  # Take first 3 for injection
                injected_keywords = force_inject_niche_into_keywords(
                    injection_candidates, current_niche, niche_terms, language
                )
                
                # Validate injected keywords
                for kw in injected_keywords:
                    if current_niche.lower() in kw.lower() and kw not in existing_keywords:
                        new_keywords.append(kw)
                        if len(new_keywords) >= 2:  # Limit injected keywords
                            break
            
            # Check if we found new keywords
            if new_keywords:
                logger.info(f"🎯 Found {len(new_keywords)} new keywords for niche '{current_niche}': {', '.join(new_keywords)}")
                
                # Ensure niche terms are present before AI processing
                print(f"✅ Pre-AI processing: All keywords contain '{current_niche}': {all(current_niche.lower() in kw.lower() for kw in new_keywords)}")
                
                new_keywords = ensure_niche_in_keywords_with_ai(new_keywords, niche_terms, language)
                new_keywords = fix_keyword_grammar_with_ai(new_keywords, language, niche_terms)
                
                # Final validation: ensure they still contain the current niche
                final_keywords = []
                for kw in new_keywords:
                    if current_niche.lower() in kw.lower():
                        final_keywords.append(kw)
                    else:
                        print(f"❌ Dropping '{kw}' - lost niche relevance after AI processing")
                
                # Use validate_and_ensure_niche_keywords to guarantee at least 1 valid keyword
                final_keywords = validate_and_ensure_niche_keywords(
                    final_keywords, current_niche, niche_terms, language
                )
                
                if final_keywords:
                    # Save with explicit niche parameter
                    save_keywords(final_keywords, niche=current_niche, language=active_language)
                    move_clues_to_used(current_clues, current_niche, active_language)
                    mark_clues_as_processed(current_clues)
                    
                    print(f"\n✅ Recheck all final result keywords with GPT-4o for niche: {current_niche}...")
                    # PASS the newly added keywords to validation function
                    validate_keywords_language(language, niche=current_niche, use_ai=True, language=active_language, newly_added_keywords=final_keywords)
                    
                    keyword_file = os.path.join(get_keywords_niche_path(current_niche, active_language), "keywords.txt")
                    valid_count = 0
                    if os.path.exists(keyword_file):
                        with open(keyword_file, "r", encoding="utf-8") as f:
                            valid_count = len([line for line in f if line.strip()])
                    
                    if valid_count > 0:
                        logger.info(f"✅ Niche '{current_niche}' process complete! {valid_count} total keyword results.")
                        keywords_found = True
                        break  # Success! Exit the loop for this niche
                    else:
                        logger.info(f"⚠️ Niche '{current_niche}' process complete! 0 total keywords.")
                else:
                    logger.info("❌ All keywords lost niche relevance after AI processing. Trying next batch...")
            else:
                logger.info("No new keywords found with current clues. Trying next batch...")
                
            # Try next batch of clues if no keywords found
            if not keywords_found:
                current_clues, has_more_clues = manage_clue_processing(available_clues, current_niche, language=active_language)

        # Final guarantee - ensure at least 1 keyword exists
        if not keywords_found:
            print(f"🚑 FINAL SAFETY CHECK: Ensuring at least 1 keyword exists for niche '{current_niche}'")
            keyword_file = os.path.join(get_keywords_niche_path(current_niche, active_language), "keywords.txt")
            
            existing_count = 0
            if os.path.exists(keyword_file):
                with open(keyword_file, "r", encoding="utf-8") as f:
                    existing_count = len([line for line in f if line.strip()])
            
            if existing_count == 0:
                print(f"🚑 No keywords found! Generating emergency keywords for '{current_niche}'")
                emergency_keywords = generate_emergency_niche_keywords(current_niche, language)
                if emergency_keywords:
                    save_keywords(emergency_keywords, niche=current_niche, language=active_language)
                    logger.info(f"🚑 Emergency keywords saved: {', '.join(emergency_keywords)}")
                else:
                    # Final fallback - create basic keyword
                    fallback_keyword = [f"best {current_niche}"]
                    save_keywords(fallback_keyword, niche=current_niche, language=active_language)
                    logger.info(f"🚑 Fallback keyword saved: {fallback_keyword[0]}")

        # After successful processing, update tracking
        update_last_processed_niche(current_niche, active_language)
        logger.info(f"✅ Completed processing niche: '{current_niche}'")
        final_stats = handler.get_stats()
        logger.info(f"🔧 Request Handler final stats - Success rate: {final_stats['global_success_rate']:.1f}%")
        logger.info(f"   Total requests: {final_stats['total_requests']}, Blocks: {final_stats['total_blocks']}")

    except KeyboardInterrupt:
        logger.warning("\nProcess interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"❌ Error processing niche '{current_niche}': {str(e)}")
        logger.debug("Detailed error:", exc_info=True)
        # Don't update last_processed_niche on error
    finally:
        cleanup_request_handler()
        logger.info("\n" + "="*40)
        logger.info("Process Summary:")
        logger.info(f"- Current niche: '{current_niche}'")
        logger.info(f"- Next niche will be: '{niches[(niches.index(current_niche) + 1) % len(niches)]}'")
        logger.info(f"- Keywords saved in: languages/{active_language}/keywords/{current_niche}/")
        show_request_stats()
        logger.info("="*40)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nProgram terminated by user.")
    except Exception as e:
        print(f"\nAn error occurred: {e}")