import os
import json
import time
import random
import re
from openai import OpenAI
# ...existing imports...
from datetime import datetime, timezone
import sys
import io
import logging
import toml
import textwrap
from pathlib import Path
from collections import defaultdict
import hashlib
import base64
import uuid
import platform
import argparse
import requests
from cryptography.fernet import Fernet
import socket
import textstat
import nltk
import shutil
from nltk.tokenize.punkt import PunktSentenceTokenizer
from collections import Counter
import signal
import atexit
from token_encryption import TokenManager

def get_base_dir():
    """Get base directory (parent of core folder)"""
    current_dir = os.path.dirname(os.path.abspath(__file__))  # Get tools dir
    core_dir = os.path.dirname(current_dir)  # Get core dir
    return os.path.dirname(core_dir)  # Get project root dir

try:
    nltk.data.find('tokenizers/punkt')
except LookupError:
    nltk.download('punkt', quiet=True)

try:
    nltk.data.find('taggers/averaged_perceptron_tagger')
except LookupError:
    nltk.download('averaged_perceptron_tagger', quiet=True)

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

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

class LicenseChecker:
    def __init__(self):
        if getattr(sys, 'frozen', False):
            application_path = os.path.dirname(sys.executable)
        else:
            application_path = os.path.dirname(os.path.abspath(__file__))
            
        self.license_file = os.path.abspath(
            os.path.join(application_path, "..", "config", ".license_data")
        )
        # Customize the server URL to the same format
        self.license_server = "https://license.gosite.or.id/api/license"
        self.is_activated = False
        self.encryption_key = self.generate_encryption_key()
        self.client_id = self.get_client_id()
        self.hardware_id = self.get_hardware_id()
        
    def generate_encryption_key(self):
        """Generate a stable encryption key based on hardware info"""
        machine_info = f"{platform.node()}-{platform.machine()}-{platform.processor()}"
        return base64.urlsafe_b64encode(hashlib.sha256(machine_info.encode()).digest()[:32])
    
    def get_client_id(self):
        """Get a unique client ID based on hardware information"""
        try:
            mac = uuid.getnode()
            processor = platform.processor()
            computer_name = platform.node()
            
            client_data = f"{mac}-{processor}-{computer_name}"
            client_id = hashlib.md5(client_data.encode()).hexdigest()
            
            return client_id
        except:
           return str(uuid.uuid4())
    
    def get_hardware_id(self):
        """Generate hardware ID for machine identification using the same algorithm as LicenseManager"""
        try:
            # Collect hardware information
            system_info = {
                'platform': platform.system(),
                'node': platform.node(),
                'machine': platform.machine(),
                'processor': platform.processor()
            }
            
            # Get MAC address if possible
            mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff)
                        for elements in range(0, 2*6, 8)][::-1])
            system_info['mac'] = mac
            
            # Generate a unique hash from system info
            hw_id_str = json.dumps(system_info, sort_keys=True)
            return hashlib.sha256(hw_id_str.encode()).hexdigest()
        except:
            # Fallback to client_id if hardware identification fails
            return self.client_id
    
    def verify_license(self, license_key=None):
        """Verify license validity from file or parameter"""
        try:
            if license_key:
                return self.verify_license_online(license_key)
            
            if not os.path.exists(self.license_file):
                print("License file not found")
                return False
            
            with open(self.license_file, "rb") as f:
                encrypted_data = f.read()
            
            fernet = Fernet(self.encryption_key)
            decrypted_data = fernet.decrypt(encrypted_data)
            license_data = json.loads(decrypted_data.decode())
            
            license_key = license_data.get("license_key", "")
            stored_client_id = license_data.get("client_id", "")
            stored_hardware_id = license_data.get("hardware_id", "")
            
            # Verify both client_id and hardware_id to maintain consistency with LicenseManager
            if stored_client_id != self.client_id:
                print("Client ID mismatch - license transfer not allowed")
                return False
                
            if stored_hardware_id and stored_hardware_id != self.hardware_id:
                print("Hardware ID mismatch - license transfer not allowed")
                return False
                
            # Check if license has expired
            if "expires_at" in license_data:
                try:
                    expires_date = datetime.fromisoformat(license_data["expires_at"].replace('Z', '+00:00'))
                    if expires_date < datetime.now(timezone.utc):
                        print("License has expired")
                        return False
                except (ValueError, TypeError):
                    pass
            
            return self.verify_license_online(license_key)
            
        except Exception as e:
            print(f"Error verifying license: {str(e)}")
            return False
    
    def verify_license_online(self, license_key):
        """License verification with server"""
        try:
            verification_data = {
                "license_key": license_key,
                "client_id": self.client_id,
                "hardware_id": self.hardware_id,
                "product": "AGCHugo"
            }
            
            response = requests.post(
                f"{self.license_server}/verify",
                json=verification_data,
                timeout=5
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get("status") == "success":
                    self.is_activated = True
                    return True
                else:
                    print(f"License invalid: {result.get('message', 'Unknown error')}")
                    self.is_activated = False
                    return False
            else:
                print(f"Server error: {response.status_code}. Trying offline verification...")
                return self.verify_license_offline(license_key)
        except requests.RequestException:
            # Offline fallback
            print("Cannot reach license server. Trying offline verification...")
            return self.verify_license_offline(license_key)
        except Exception as e:
            print(f"Error during online verification: {str(e)}")
            return False
    
    def verify_license_offline(self, license_key):
        """Offline license verification (fallback)"""
        try:
            if not os.path.exists(self.license_file):
                return False
                
            with open(self.license_file, "rb") as f:
                encrypted_data = f.read()
            
            try:
                fernet = Fernet(self.encryption_key)
                decrypted_data = fernet.decrypt(encrypted_data)
                license_data = json.loads(decrypted_data.decode())
                
                stored_license = license_data.get("license_key", "")
                stored_client_id = license_data.get("client_id", "")
                stored_hardware_id = license_data.get("hardware_id", "")
                
                # Verify license, client_id, and hardware_id
                if (stored_license == license_key and 
                    stored_client_id == self.client_id and 
                    (not stored_hardware_id or stored_hardware_id == self.hardware_id)):
                    
                    # Check the expiration date
                    if "expires_at" in license_data:
                        try:
                            expires_date = datetime.fromisoformat(license_data["expires_at"].replace('Z', '+00:00'))
                            if expires_date < datetime.now(timezone.utc):
                                print("License has expired")
                                return False
                        except (ValueError, TypeError):
                            pass
                    
                    print("License verified offline")
                    self.is_activated = True
                    return True
                else:
                    print("License mismatch in offline verification")
                    return False
            except Exception as e:
                print(f"Error decrypting license data: {str(e)}")
                return False
        except Exception as e:
            print(f"Error during offline verification: {str(e)}")
            return False

def parse_args():
    parser = argparse.ArgumentParser(description='Article Generator with license verification')
    parser.add_argument('--license', type=str, help='License key for verification')
    parser.add_argument('--watch', action='store_true', help='Run in watch mode (polling)')
    return parser.parse_args()

def check_license(args):
    license_checker = LicenseChecker()

    license_key = args.license if hasattr(args, 'license') else None

    if license_checker.verify_license(license_key):
        print("License valid - proceeding with execution")
        return True
    else:
        print("ERROR: Valid license required to run this script")
        print("Please activate your license through GOHugoGUI application")
        sys.exit(1)

class AGCArticleReviser:
    def __init__(self):
        # Setup logging
        self.setup_logging()
    
        # Base path for GitHub repository
        self.base_path = get_base_dir()
        self.token_manager = TokenManager(self.base_path)

        migrated_files = self.token_manager.migrate_existing_tokens()
        if migrated_files:
            self.logger.info(f"Migrated {len(migrated_files)} token files to encrypted format")
    
        # Token management
        self.tokens = []
        self.current_token_index = 0
        self.article_count = 0
    
        # Create config directory if not exists
        os.makedirs(os.path.join(self.base_path, "config"), exist_ok=True)
        
        # Load active language from config first
        self.active_language = self.load_active_language()
        
        # Path to the active language location
        self.lang_path = self.get_language_path()
        
        # Find all available niches from the directory structure
        self.available_niches = self.get_all_niches()
        
        # Set the first active niche (if any)
        if self.available_niches:
            self.active_niche = self.available_niches[0]
        else:
            # Default fallback if no niches found
            self.active_niche = "blog"
            
        # Adjust the path for keywords based on active_niche
        self.update_niche_paths()
        
        # Then load language details
        self.language = self.load_language()
    
        # Load website name from config.toml
        self.website_name = self.load_website_name()
        
        # Load cultural elements with simplified approach
        self.cultural_references = self.load_cultural_references()
        self.idioms_and_phrases = self.load_idioms_and_phrases()
        self.user_behavior = self.load_user_behavior()
        
        # Ensure prompt files exist
        self.load_custom_prompt("profile")
        self.load_custom_prompt("about-us")
        self.load_custom_prompt("privacy-policy")
        
        # Fixed categories for prompt and template
        self.prompt_category = "blog"
        self.template_category = "blog"
        
        # Hugo content path
        self.hugo_content_path = os.path.join(self.base_path, "content")
        
        # Azure AI settings
        self.model_name = self.load_ai_model()
        self.endpoint = "https://models.github.ai/inference"
        
        # Initialize SDK type (will be set properly during authentication)
        self.sdk_type = None
        self.client = None
        
        # Token rotation settings
        self.token_rotation_threshold = 12  # Rotate tokens after 12 articles
        
        # Keyword tracking
        self.processed_keywords = defaultdict(bool)
        
        self.last_login_file = os.path.join(self.base_path, "token", "last_login.json")
        
        # Create directories if they don't exist
        self.ensure_directory_structure()
    
        # Reference style settings
        self.audience_reference = None
        self.author_reference = None
    
        # Clean up old logs files
        self.cleanup_old_files()

    def retry_with_token_rotation(self, func, *args, max_retries=None, **kwargs):
        """Helper method to retry API calls with automatic token rotation on rate limit"""
        if max_retries is None:
            max_retries = len(self.tokens) if self.tokens else 1
        
        tried_tokens = set()
        original_token_index = self.current_token_index
        
        for attempt in range(max_retries):
            try:
                # Get current token
                token = self.get_current_token()
                if not token:
                    self.logger.error("No valid token available")
                    return None
                    
                # Update client with current token
                if self.sdk_type == "openai":
                    from openai import OpenAI
                    self.client = OpenAI(
                        base_url=self.endpoint,
                        api_key=token,
                    )
                else:  # azure
                    from azure.ai.inference import ChatCompletionsClient
                    from azure.core.credentials import AzureKeyCredential
                    self.client = ChatCompletionsClient(
                        endpoint=self.endpoint,
                        credential=AzureKeyCredential(token),
                    )
                
                # Try the API call
                result = func(*args, **kwargs)
                
                # If successful, return result
                if result:
                    return result
                    
            except Exception as e:
                error_msg = str(e).lower()
                
                # Check for rate limit errors
                if any(phrase in error_msg for phrase in ['429', 'rate limit', 'quota', 'too many requests']):
                    tried_tokens.add(token)
                    self.logger.warning(f"Token {self.current_token_index + 1} rate limited. Attempt {attempt + 1}/{max_retries}")
                    print(f"⚠️ Token {self.current_token_index + 1} rate limited. Trying next token...")
                    
                    # Rotate to next token
                    self.current_token_index = (self.current_token_index + 1) % len(self.tokens)
                    
                    # If we've tried all tokens, break
                    if len(tried_tokens) >= len(self.tokens):
                        self.logger.error("All tokens are rate limited")
                        print("❌ All tokens are rate limited. Cannot continue.")
                        return None
                        
                    # Continue to next attempt
                    continue
                else:
                    # Non rate-limit error, log and potentially retry once
                    self.logger.error(f"API call failed: {str(e)}")
                    if attempt == 0:  # Only retry once for non-rate-limit errors
                        continue
                    else:
                        return None
        
        return None
    
    def safe_api_call(self, messages, temperature=0.7, max_tokens=2000):
        """Safe API call wrapper that handles both OpenAI and Azure SDK"""
        try:
            if self.sdk_type == "openai":
                response = self.client.chat.completions.create(
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    model=self.model_name
                )
            else:  # azure
                from azure.ai.inference.models import SystemMessage, UserMessage
                # Convert message format for Azure
                azure_messages = []
                for msg in messages:
                    if msg["role"] == "system":
                        azure_messages.append(SystemMessage(msg["content"]))
                    elif msg["role"] == "user":
                        azure_messages.append(UserMessage(msg["content"]))
                
                response = self.client.complete(
                    messages=azure_messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    model=self.model_name
                )
            
            if response and response.choices and len(response.choices) > 0:
                return response.choices[0].message.content
            return None
            
        except Exception as e:
            raise e  # Re-raise untuk ditangani oleh retry_with_token_rotation

    def load_ai_model(self):
        """Load AI model configuration from config/model_ai.txt"""
        model_config_path = os.path.join(self.base_path, "config", "model_ai.txt")
        model_default_path = os.path.join(self.base_path, "config", "model_ai.default.txt")
        
        # Create default file if it doesn't exist
        if not os.path.exists(model_default_path):
            try:
                with open(model_default_path, "w", encoding="utf-8") as f:
                    f.write("gpt-4o")
                self.logger.info("Created default model_ai.default.txt")
            except Exception as e:
                self.logger.error(f"Error creating default model file: {str(e)}")
        
        # Copy default to main if main doesn't exist
        if not os.path.exists(model_config_path):
            try:
                shutil.copy2(model_default_path, model_config_path)
                self.logger.info("Created model_ai.txt from default")
            except Exception as e:
                self.logger.error(f"Error copying default model file: {str(e)}")
        
        try:
            with open(model_config_path, "r", encoding="utf-8") as f:
                model_name = f.read().strip()
            
            # Updated model mapping with better multi-language support
            model_mapping = {
                "DeepSeek-R1": "deepseek/DeepSeek-R1",     # Good multi-language support
                "gpt-4o": "openai/gpt-4o",                 # Excellent multi-language
                "gpt-4.1": "openai/gpt-4.1",              # Excellent multi-language
                "grok-3": "xai/grok-3",                    # Good multi-language
                "AI21-Jamba-1.5": "ai21-labs/AI21-Jamba-1.5-Large",  # Good multi-language
                "Mistral-Small-3.1": "mistral-ai/mistral-small-2503",    # Good multi-language support
                "Llama-4-Maverick-17B": "meta/Llama-4-Maverick-17B-128E-Instruct-FP8" # Good multi-language support
            }
            
            if model_name in model_mapping:
                full_model_name = model_mapping[model_name]
                self.logger.info(f"Loaded AI model: {model_name} -> {full_model_name}")
                return full_model_name
            else:
                self.logger.warning(f"Unknown model '{model_name}', using default openai/gpt-4o")
                return "openai/gpt-4o"
                
        except Exception as e:
            self.logger.error(f"Error loading AI model config: {str(e)}")
            return "openai/gpt-4o"

    def setup_language_directories(self):
        """Setup language directory structure based on active language with schema support"""
        # Read active language from config/language.txt
        config_lang_file = os.path.join(self.base_path, "config", "language.txt")
        if os.path.exists(config_lang_file):
            with open(config_lang_file, "r", encoding="utf-8") as f:
                active_language = f.read().strip()
        else:
            active_language = "english"  # Default fallback
    
        # Create base directories
        languages_base = os.path.join(self.base_path, "languages")
        os.makedirs(languages_base, exist_ok=True)
    
        # Define all schema types
        schema_types = ["blog", "local_business", "news", "person", "product", "service"]
    
        # Create structure for both active language and default
        for lang in [active_language, "default"]:
            lang_path = os.path.join(languages_base, lang)
            
            # Define all required directories
            directories = [
                "author",
                "prompt/blog",
                "prompt/page",
                "prompt/language",
                "prompt/models", 
                "prompt/system",
                "stats",
                "style/copywriting",
                "style/tone",
                "style/engagement",
                "keywords/_cache",
                "keywords/logs",
                "kw"
            ]
            
            # Add template directories for each schema type
            for schema_type in schema_types:
                directories.append(f"templates_md/{schema_type}")
    
            # Create all directories
            for dir_path in directories:
                os.makedirs(os.path.join(lang_path, dir_path), exist_ok=True)
    
            # Create niche directories file if it doesn't exist
            niche_file = os.path.join(lang_path, "kw", "niche.txt")
            niche_default_file = os.path.join(lang_path, "kw", "niche.default.txt")
            
            # Create default niche file if it doesn't exist
            if not os.path.exists(niche_default_file):
                with open(niche_default_file, "w", encoding="utf-8") as f:
                    f.write("blog")  # Default niche
                    
            # Create active niche file from default if it doesn't exist
            if not os.path.exists(niche_file) and os.path.exists(niche_default_file):
                shutil.copy(niche_default_file, niche_file)
                
            # Read active niche
            active_niche = "blog"  # Default fallback
            if os.path.exists(niche_file):
                with open(niche_file, "r", encoding="utf-8") as f:
                    niche_content = f.read().strip()
                    if niche_content:
                        active_niche = niche_content
            
            # Create niche directory structure for keywords
            os.makedirs(os.path.join(lang_path, "keywords", active_niche), exist_ok=True)
            
            # Define all required files with their default counterparts
            file_pairs = [
                # Author files
                ("author/authors-name.default.txt", "author/authors-name.txt"),
                ("author/author-persona.default.txt", "author/author-persona.txt"),
                ("author/audience-persona.default.txt", "author/audience-persona.txt"),
                
                # Prompt files - keep blog for prompts directory
                ("prompt/blog/articles.default.txt", "prompt/blog/articles.txt"),
                ("prompt/blog/description_prompt.default.txt", "prompt/blog/description_prompt.txt"),
                ("prompt/page/about-us.default.txt", "prompt/page/about-us.txt"),
                ("prompt/page/privacy-policy.default.txt", "prompt/page/privacy-policy.txt"),
                ("prompt/page/profile.default.txt", "prompt/page/profile.txt"),
                ("prompt/language/language.default.txt", "prompt/language/language.txt"),
                ("prompt/models/models.default.txt", "prompt/models/models.txt"),
                
                # System prompts
                ("prompt/system/author_profile_system.default.txt", "prompt/system/author_profile_system.txt"),
                ("prompt/system/cultural_context.default.txt", "prompt/system/cultural_context.txt"),
                ("prompt/system/description_writer.default.txt", "prompt/system/description_writer.txt"),
                ("prompt/system/page_article_system.default.txt", "prompt/system/page_article_system.txt"),
                ("prompt/system/title_generator.default.txt", "prompt/system/title_generator.txt"),
                ("prompt/system/title_system.default.txt", "prompt/system/title_system.txt"),
                ("prompt/system/validation_prompt.default.txt", "prompt/system/validation_prompt.txt"),
                ("prompt/system/validation_system.default.txt", "prompt/system/validation_system.txt"),
                ("prompt/system/article_generator.default.txt", "prompt/system/article_generator.txt"),
                
                # Stats
                ("stats/cultural_adaptation.json", "stats/cultural_adaptation.json"),
                ("stats/writing_stats.json", "stats/writing_stats.json"),
                
                # Style
                ("style/copywriting/copywriting.default.txt", "style/copywriting/copywriting.txt"),
                ("style/tone/tones.default.txt", "style/tone/tones.txt"),
                ("style/engagement/behavior_config.default.txt", "style/engagement/behavior_config.txt"),
                ("style/engagement/culture_config.default.txt", "style/engagement/culture_config.txt"),
                ("style/engagement/idioms_config.default.txt", "style/engagement/idioms_config.txt"),
                
                # Keywords for the active niche - use dynamic niche name
                (f"keywords/{active_niche}/keywords.default.txt", f"keywords/{active_niche}/keywords.txt"),
                (f"keywords/{active_niche}/processed_keywords.txt", f"keywords/{active_niche}/processed_keywords.txt"),
                (f"keywords/{active_niche}/removed_keywords.txt", f"keywords/{active_niche}/removed_keywords.txt"),
                
                # KW files
                ("kw/clue.default.txt", "kw/clue.txt"),
                ("kw/badwords.default.txt", "kw/badwords.txt"),
                ("kw/niche.default.txt", "kw/niche.txt"),
                ("kw/region.default.txt", "kw/region.txt"),
                ("kw/user-agent.default.txt", "kw/user-agent.txt"),
                ("kw/language.default.txt", "kw/language.txt"),
            ]
            
            # Add template files for each schema type
            for schema_type in schema_types:
                file_pairs.extend([
                    (f"templates_md/{schema_type}/template.default.md", f"templates_md/{schema_type}/template.md")
                ])
    
            # Create all files
            for default_file, active_file in file_pairs:
                default_path = os.path.join(lang_path, default_file)
                active_path = os.path.join(lang_path, active_file)
                
                # Create directory if it doesn't exist
                os.makedirs(os.path.dirname(default_path), exist_ok=True)
                os.makedirs(os.path.dirname(active_path), exist_ok=True)
                
                # Create default file if it doesn't exist
                if not os.path.exists(default_path):
                    with open(default_path, "w", encoding="utf-8") as f:
                        if default_file.endswith('.json'):
                            f.write('{}')  # Empty JSON object
                        else:
                            f.write("")  # Create empty default file
                        
                # Create active file from default if it doesn't exist
                if not os.path.exists(active_path) and os.path.exists(default_path):
                    shutil.copy(default_path, active_path)
    
        # Create config directory and language files
        config_dir = os.path.join(self.base_path, "config")
        os.makedirs(config_dir, exist_ok=True)
        
        # Create language config files
        default_lang_file = os.path.join(config_dir, "language.default.txt")
        active_lang_file = os.path.join(config_dir, "language.txt")
        
        if not os.path.exists(default_lang_file):
            with open(default_lang_file, "w", encoding="utf-8") as f:
                f.write("english")
                
        if not os.path.exists(active_lang_file):
            shutil.copy(default_lang_file, active_lang_file)
    
    def load_active_language(self):
        """Load active language from config file"""
        config_file = os.path.join(self.base_path, "config", "language.txt")
        config_default_file = os.path.join(self.base_path, "config", "language.default.txt")
        
        # Create config directory if not exists
        os.makedirs(os.path.dirname(config_file), exist_ok=True)
        
        # If config file doesn't exist, try to use default
        if not os.path.exists(config_file):
            if os.path.exists(config_default_file):
                try:
                    with open(config_default_file, "r", encoding="utf-8") as f:
                        language = f.read().strip().lower()
                    # Copy default to main config file
                    with open(config_file, "w", encoding="utf-8") as f:
                        f.write(language)
                    self.logger.info(f"Created language config file from default with '{language}'")
                    return language
                except Exception as e:
                    self.logger.error(f"Error reading default language config: {str(e)}")
            
            # If default doesn't exist or has error, create with default value
            with open(config_file, "w", encoding="utf-8") as f:
                f.write("english")
            self.logger.info("Created default language config file with 'english'")
            return "english"
        
        # Read active language from config file
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                language = f.read().strip().lower()
                
            if language:
                self.logger.info(f"Active language set to: {language}")
                return language
            else:
                self.logger.warning("Empty language config file, using 'english' as default")
                return "english"
        except Exception as e:
            self.logger.error(f"Error reading language config: {str(e)}")
            return "english"

    def load_active_niche(self):
        """Load the active niche from the niche.txt file"""
        lang_path = self.get_language_path()
        niche_file_path = os.path.join(lang_path, "kw", "niche.txt")
        default_niche_file_path = os.path.join(lang_path, "kw", "niche.default.txt")
        
        # Try to read from niche.txt file
        if os.path.exists(niche_file_path):
            try:
                with open(niche_file_path, "r", encoding="utf-8") as f:
                    niche = f.read().strip()
                    if niche:
                        self.logger.info(f"Loaded active niche: {niche}")
                        return niche
            except Exception as e:
                self.logger.error(f"Error reading niche from {niche_file_path}: {str(e)}")
        
        # If failed, try to read from default
        if os.path.exists(default_niche_file_path):
            try:
                with open(default_niche_file_path, "r", encoding="utf-8") as f:
                    niche = f.read().strip()
                    if niche:
                        self.logger.info(f"Using default niche: {niche}")
                        return niche
            except Exception as e:
                self.logger.error(f"Error reading niche from {default_niche_file_path}: {str(e)}")
        
        # If still failed, use a default value
        self.logger.warning("No niche found, using default 'blog'")
        return "blog"

    def analyze_articles_in_niche(self):
        """
        Analyze all articles in the folder content/{niche}
        Returns: (niche_name, article_paths) or (None, []) if no articles are found
        """
        print("\n--- Analyzing articles in all niches ---")
        
        for niche in self.available_niches:
            print(f"Checking niche: {niche}")
            
            # Get article paths in this niche
            niche_content_path = os.path.join(self.hugo_content_path, niche)
            if not os.path.exists(niche_content_path):
                print(f"❌ No content directory for niche: {niche}")
                continue
                
            # Get all markdown files
            article_paths = []
            for file in os.listdir(niche_content_path):
                if file.endswith('.md'):
                    article_path = os.path.join(niche_content_path, file)
                    article_paths.append(article_path)
                    
            if article_paths:
                print(f"✅ Found {len(article_paths)} articles in niche: {niche}")
                return niche, article_paths
            else:
                print(f"❌ No articles found in niche: {niche}")
                
        print("❌ No articles found in any niche")
        return None, []

    def cleanup_old_files(self):
        """Clean up old logs files, keeping only the 10 most recent"""
        folder_path = os.path.join(self.base_path, "logs")
        if os.path.exists(folder_path):
            files = []
            for file in os.listdir(folder_path):
                file_path = os.path.join(folder_path, file)
                if os.path.isfile(file_path):
                    files.append((file_path, os.path.getmtime(file_path)))
            
            # Sort by modification time (newest first)
            files.sort(key=lambda x: x[1], reverse=True)
            
            # Keep only the 10 most recent files
            if len(files) > 10:
                for file_path, _ in files[10:]:
                    try:
                        os.remove(file_path)
                        self.logger.info(f"Removed old file: {file_path}")
                    except Exception as e:
                        self.logger.error(f"Error removing file {file_path}: {str(e)}")

    def save_json_to_txt(self, json_data, file_path):
        """Save JSON data to a text file with proper formatting for easy editing"""
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json_str = json.dumps(json_data, indent=4, ensure_ascii=False)
                # Add helpful comments
                f.write("# Edit the configuration below in JSON format\n")
                f.write("# Make sure the JSON format remains valid when editing.\n")
                f.write("# An example of a correct format is:\n")
                f.write('# {"key": ["value1", "value2"]}\n\n')
                f.write(json_str)
            return True
        except Exception as e:
            self.logger.error(f"Error saving JSON to text file {file_path}: {str(e)}")
            return False
       
    def setup_logging(self):
        """Setup logging configuration"""
        os.makedirs("logs", exist_ok=True)
        log_stream = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(f"logs/agc_generator_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log", encoding="utf-8"),
                logging.StreamHandler(log_stream)
            ]
        )
        self.logger = logging.getLogger("GOHugoGenerator")
    
    def ensure_default_files_exist(self):
        """Ensure all default files exist in the default language directory including schema templates."""
        default_lang_path = os.path.join(self.base_path, "languages", "default")
        
        # Define all schema types
        schema_types = ["blog", "local_business", "news", "person", "product", "service"]
        
        file_pairs = [
            # Author files
            ("author/authors-name.default.txt", "author/authors-name.txt"),
            ("author/audience-persona.default.txt", "author/audience-persona.txt"),
            ("author/author-persona.default.txt", "author/author-persona.txt"),
            # Prompt files
            ("prompt/blog/articles.default.txt", "prompt/blog/articles.txt"),
            ("prompt/page/profile.default.txt", "prompt/page/profile.txt"),
            ("prompt/page/about-us.default.txt", "prompt/page/about-us.txt"),
            ("prompt/page/privacy-policy.default.txt", "prompt/page/privacy-policy.txt"),
            # Style files
            ("style/tone/tones.default.txt", "style/tone/tones.txt"),
            ("style/copywriting/copywriting.default.txt", "style/copywriting/copywriting.txt"),
            ("style/engagement/behavior_config.default.txt", "style/engagement/behavior_config.txt"),
            ("style/engagement/culture_config.default.txt", "style/engagement/culture_config.txt"),
            ("style/engagement/idioms_config.default.txt", "style/engagement/idioms_config.txt"),
            # Stats files
            ("stats/cultural_adaptation.json", "stats/cultural_adaptation.json"),
            ("stats/writing_stats.json", "stats/writing_stats.json"),
        ]
        
        # Add template files for each schema type
        for schema_type in schema_types:
            file_pairs.extend([
                (f"templates_md/{schema_type}/template.default.md", f"templates_md/{schema_type}/template.md")
            ])
    
        for default_file, active_file in file_pairs:
            default_path = os.path.join(default_lang_path, default_file)
            active_path = os.path.join(default_lang_path, active_file)
            
            # Check if default file exists, warn if missing
            if not os.path.exists(default_path):
                self.logger.warning(f"Default file missing: {default_path}")
                
            # Create active file from default if it doesn't exist and default exists
            if not os.path.exists(active_path) and os.path.exists(default_path):
                # Ensure directory exists
                os.makedirs(os.path.dirname(active_path), exist_ok=True)
                shutil.copy(default_path, active_path)
                self.logger.info(f"Created active file from default: {active_path}")
    
    def ensure_directories_exist(self):
        """Ensure all required directories exist including schema template directories."""
        lang_path = self.get_language_path()
        
        # Define all schema types
        schema_types = ["blog", "local_business", "news", "person", "product", "service"]
        
        directories = [
            "author",
            "prompt/blog",
            "prompt/page",
            "prompt/system",
            "style/copywriting",
            "style/tone",
            "style/engagement",
            f"keywords/{self.active_niche}",
            "keywords/_cache",
            "keywords/logs",
            "stats",
            "kw"
        ]
        
        # Add template directories for each schema type
        for schema_type in schema_types:
            directories.append(f"templates_md/{schema_type}")
    
        for directory in directories:
            dir_path = os.path.join(lang_path, directory)
            os.makedirs(dir_path, exist_ok=True)
            self.logger.info(f"Ensured directory exists: {dir_path}")
    
    def ensure_active_files_exist(self):
        """Ensure all active files exist by copying from default if necessary including schema templates."""
        lang_path = self.get_language_path()
        default_lang_path = os.path.join(self.base_path, "languages", "default")
        
        # Define all schema types
        schema_types = ["blog", "local_business", "news", "person", "product", "service"]
        
        file_pairs = [
            # Author files
            ("author/authors-name.default.txt", "author/authors-name.txt"),
            ("author/audience-persona.default.txt", "author/audience-persona.txt"),
            ("author/author-persona.default.txt", "author/author-persona.txt"),
            # Prompt files
            ("prompt/blog/articles.default.txt", "prompt/blog/articles.txt"),
            ("prompt/page/profile.default.txt", "prompt/page/profile.txt"),
            ("prompt/page/about-us.default.txt", "prompt/page/about-us.txt"),
            ("prompt/page/privacy-policy.default.txt", "prompt/page/privacy-policy.txt"),
        ]
        
        # Add template files for each schema type - Fixed to handle both .md and .default.md properly
        for schema_type in schema_types:
            file_pairs.extend([
                (f"templates_md/{schema_type}/template.default.md", f"templates_md/{schema_type}/template.md")
            ])
    
        for default_file, active_file in file_pairs:
            default_path = os.path.join(default_lang_path, default_file)
            active_path = os.path.join(lang_path, active_file)
            
            # Create active file from default if it doesn't exist
            if not os.path.exists(active_path) and os.path.exists(default_path):
                # Ensure directory exists
                os.makedirs(os.path.dirname(active_path), exist_ok=True)
                shutil.copy(default_path, active_path)
                self.logger.info(f"Created active file from default: {active_path}")
    
    def ensure_directory_structure(self):
        """Create required directories if they don't exist"""
        # Create main directories within the language path
        directories = [
            os.path.join(self.lang_path, "keywords", self.active_niche),
            os.path.join(self.lang_path, "prompt", "blog"),
            os.path.join(self.lang_path, "prompt", "models"),
            os.path.join(self.lang_path, "prompt", "language"),
            os.path.join(self.lang_path, "prompt", "page"),
            os.path.join(self.lang_path, "prompt", "system"),
            os.path.join(self.lang_path, "templates_md", "blog"),
            os.path.join(self.lang_path, "style", "tone"),
            os.path.join(self.lang_path, "style", "copywriting"),
            os.path.join(self.lang_path, "style", "engagement"),
            os.path.join(self.lang_path, "stats"),
            os.path.join(self.lang_path, "kw")
        ]
        
        # Create global directories
        global_directories = [
            os.path.join(self.base_path, "token"),
            os.path.join(self.base_path, "config"),
            self.hugo_content_path
        ]
        
        # Add each niche's content directory to ensure they exist
        for niche in self.available_niches:
            global_directories.append(os.path.join(self.hugo_content_path, niche))
        
        # Create language-specific directories
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
        
        # Create global directories
        for directory in global_directories:
            os.makedirs(directory, exist_ok=True)
        
        # Creating default files if they don't exist
        self.create_default_files()
    
    def create_default_files(self):
        """Create all default template and example files including .default versions with schema support"""
        
        # Define a helper function to create or update a file with its default version
        def create_file_with_default(path, default_path):
            # Create directories if they don't exist
            os.makedirs(os.path.dirname(path), exist_ok=True)
            
            # Create main file if it doesn't exist
            if not os.path.exists(path) and os.path.exists(default_path):
                try:
                    with open(default_path, "r", encoding="utf-8") as f_default:
                        default = f_default.read()
                    with open(path, "w", encoding="utf-8") as f:
                        f.write(default)
                    self.logger.info(f"Created file {path} from default template")
                except Exception as e:
                    self.logger.error(f"Error creating file {path}: {str(e)}")
        
        # Get path for current language
        lang_path = self.get_language_path()
        default_lang_path = os.path.join(self.base_path, "languages", "default")
        
        # Define all schema types
        schema_types = ["blog", "local_business", "news", "person", "product", "service"]
        
        # Make sure all needed directories exist
        for dir_path in [
            os.path.join(default_lang_path, "author"),
            os.path.join(default_lang_path, "prompt", "blog"),
            os.path.join(default_lang_path, "prompt", "page"),
            os.path.join(default_lang_path, "prompt", "language"),
            os.path.join(default_lang_path, "prompt", "system"),
            os.path.join(default_lang_path, "prompt", "models"),
            os.path.join(default_lang_path, "style", "copywriting"),
            os.path.join(default_lang_path, "style", "tone"),
            os.path.join(default_lang_path, "style", "engagement"),
            os.path.join(default_lang_path, "keywords", self.active_niche),
            os.path.join(default_lang_path, "stats"),
            os.path.join(default_lang_path, "kw")
        ]:
            os.makedirs(dir_path, exist_ok=True)
        
        # Create schema template directories
        for schema_type in schema_types:
            os.makedirs(os.path.join(default_lang_path, "templates_md", schema_type), exist_ok=True)
        
        # Create global directories
        for dir_path in [
            os.path.join(self.base_path, "token"),
            os.path.join(self.base_path, "config"),
        ]:
            os.makedirs(dir_path, exist_ok=True)
        
        # Pair the expected main files with their default versions
        file_pairs = [
            # 1. Author files
            (os.path.join(lang_path, "author", "authors-name.txt"), 
             os.path.join(default_lang_path, "author", "authors-name.default.txt")),
            (os.path.join(lang_path, "author", "audience-persona.txt"), 
             os.path.join(default_lang_path, "author", "audience-persona.default.txt")),
            (os.path.join(lang_path, "author", "author-persona.txt"), 
             os.path.join(default_lang_path, "author", "author-persona.default.txt")),
            
            # 2. Keyword files
            (os.path.join(lang_path, "keywords", self.active_niche, "keywords.txt"), 
             os.path.join(default_lang_path, "keywords", self.active_niche, "keywords.default.txt")),
            
            # 3. Prompt files
            (os.path.join(lang_path, "prompt", "blog", "articles.txt"), 
             os.path.join(default_lang_path, "prompt", "blog", "articles.default.txt")),
            (os.path.join(lang_path, "prompt", "page", "profile.txt"), 
             os.path.join(default_lang_path, "prompt", "page", "profile.default.txt")),
            (os.path.join(lang_path, "prompt", "page", "about-us.txt"), 
             os.path.join(default_lang_path, "prompt", "page", "about-us.default.txt")),
            (os.path.join(lang_path, "prompt", "page", "privacy-policy.txt"), 
             os.path.join(default_lang_path, "prompt", "page", "privacy-policy.default.txt")),
            (os.path.join(lang_path, "prompt", "blog", "description_prompt.txt"), 
             os.path.join(default_lang_path, "prompt", "blog", "description_prompt.default.txt")),
            (os.path.join(lang_path, "prompt", "system", "description_writer.txt"),
             os.path.join(default_lang_path, "prompt", "system", "description_writer.default.txt")),
            (os.path.join(lang_path, "prompt", "system", "cultural_context.txt"), 
             os.path.join(default_lang_path, "prompt", "system", "cultural_context.default.txt")),
            (os.path.join(lang_path, "prompt", "system", "article_generator.txt"), 
             os.path.join(default_lang_path, "prompt", "system", "article_generator.default.txt")),
            (os.path.join(lang_path, "prompt", "system", "title_generator.txt"), 
             os.path.join(default_lang_path, "prompt", "system", "title_generator.default.txt")),
            (os.path.join(lang_path, "prompt", "system", "title_system.txt"), 
             os.path.join(default_lang_path, "prompt", "system", "title_system.default.txt")),
            (os.path.join(lang_path, "prompt", "system", "validation_prompt.txt"), 
             os.path.join(default_lang_path, "prompt", "system", "validation_prompt.default.txt")),
            (os.path.join(lang_path, "prompt", "system", "validation_system.txt"), 
             os.path.join(default_lang_path, "prompt", "system", "validation_system.default.txt")),
            (os.path.join(lang_path, "prompt", "system", "author_profile_system.txt"), 
             os.path.join(default_lang_path, "prompt", "system", "author_profile_system.default.txt")),
            (os.path.join(lang_path, "prompt", "system", "page_article_system.txt"), 
             os.path.join(default_lang_path, "prompt", "system", "page_article_system.default.txt")),
            
            # 5. Token files
            (os.path.join(self.base_path, "token", "tokens.txt"), 
             os.path.join(self.base_path, "token", "tokens.default.txt")),
            
            # 6. Language files
            (os.path.join(lang_path, "prompt", "language", "language.txt"), 
             os.path.join(default_lang_path, "prompt", "language", "language.default.txt")),
            
            # 7. Writing model files
            (os.path.join(lang_path, "prompt", "models", "models.txt"), 
             os.path.join(default_lang_path, "prompt", "models", "models.default.txt")),
            
            # 8. Writing tone files
            (os.path.join(lang_path, "style", "tone", "tones.txt"), 
             os.path.join(default_lang_path, "style", "tone", "tones.default.txt")),
            
            # 9. Copywriting style files
            (os.path.join(lang_path, "style", "copywriting", "copywriting.txt"), 
             os.path.join(default_lang_path, "style", "copywriting", "copywriting.default.txt")),
            
            # 10. Engagement files
            (os.path.join(lang_path, "style", "engagement", "behavior_config.txt"), 
             os.path.join(default_lang_path, "style", "engagement", "behavior_config.default.txt")),
            (os.path.join(lang_path, "style", "engagement", "culture_config.txt"), 
             os.path.join(default_lang_path, "style", "engagement", "culture_config.default.txt")),
            (os.path.join(lang_path, "style", "engagement", "idioms_config.txt"), 
             os.path.join(default_lang_path, "style", "engagement", "idioms_config.default.txt")),
             
            # 11. KW files
            (os.path.join(lang_path, "kw", "clue.txt"), 
             os.path.join(default_lang_path, "kw", "clue.default.txt")),
            (os.path.join(lang_path, "kw", "badwords.txt"), 
             os.path.join(default_lang_path, "kw", "badwords.default.txt")),
            (os.path.join(lang_path, "kw", "niche.txt"), 
             os.path.join(default_lang_path, "kw", "niche.default.txt")),
            (os.path.join(lang_path, "kw", "region.txt"), 
             os.path.join(default_lang_path, "kw", "region.default.txt")),
            (os.path.join(lang_path, "kw", "user-agent.txt"), 
             os.path.join(default_lang_path, "kw", "user-agent.default.txt")),
            (os.path.join(lang_path, "kw", "language.txt"), 
             os.path.join(default_lang_path, "kw", "language.default.txt"))
        ]
        
        # 4. Add Template files for each schema type
        for schema_type in schema_types:
            file_pairs.append((
                os.path.join(lang_path, "templates_md", schema_type, "template.md"), 
                os.path.join(default_lang_path, "templates_md", schema_type, "template.default.md")
            ))
    
        file_pairs.extend([
            # Stats files
            (os.path.join(lang_path, "stats", "cultural_adaptation.json"), 
             os.path.join(default_lang_path, "stats", "cultural_adaptation.json")),
            (os.path.join(lang_path, "stats", "writing_stats.json"), 
             os.path.join(default_lang_path, "stats", "writing_stats.json")),
            
            # Additional keyword files
            (os.path.join(lang_path, "keywords", self.active_niche, "removed_keywords.txt"), 
             os.path.join(default_lang_path, "keywords", self.active_niche, "removed_keywords.txt")),
            
            # Config files
            (os.path.join(self.base_path, "config", "language.txt"), 
             os.path.join(self.base_path, "config", "language.default.txt"))
        ])
        
        # Create files from their default counterparts
        for target_file, default_file in file_pairs:
            create_file_with_default(target_file, default_file)
        
        # Create the _cache directory in keywords for each language
        os.makedirs(os.path.join(lang_path, "keywords", "_cache"), exist_ok=True)
    
    def load_system_prompt(self, prompt_name):
        """Load system prompt from file with proper fallback mechanism"""
        lang_path = self.get_language_path()
        default_lang_path = os.path.join(self.base_path, "languages", "default")
        
        # Define file paths with proper priority
        file_paths = [
            # 1. Active language normal file
            os.path.join(lang_path, "prompt", "system", f"{prompt_name}.txt"),
            
            # 2. Active language default file
            os.path.join(lang_path, "prompt", "system", f"{prompt_name}.default.txt"),
            
            # 3. Default language normal file
            os.path.join(default_lang_path, "prompt", "system", f"{prompt_name}.txt"),
            
            # 4. Default language default file
            os.path.join(default_lang_path, "prompt", "system", f"{prompt_name}.default.txt")
        ]
        
        # Try each file path in order
        for file_path in file_paths:
            try:
                if os.path.exists(file_path):
                    with open(file_path, "r", encoding="utf-8") as f:
                        content = f.read().strip()
                        if content:  # Only return if file has content
                            self.logger.info(f"Loaded system prompt from: {file_path}")
                            return content
            except Exception as e:
                self.logger.error(f"Error reading {file_path}: {str(e)}")
                continue
        
        # If no file found or all empty
        self.logger.error(f"No valid system prompt file found for: {prompt_name}")
        return ""
    
    def load_tokens(self):
        """Load API tokens from tokens.txt file with encryption support"""
        token_file = os.path.join(self.base_path, "token", "tokens.txt")
        token_default_file = os.path.join(self.base_path, "token", "tokens.default.txt")
        
        # Initialize tokens as empty list
        self.tokens = []
        
        # Check if token file exists
        if not os.path.exists(token_file):
            # Try to use default token file
            if os.path.exists(token_default_file):
                self.logger.warning("Using default token file as tokens.txt was not found")
                token_file = token_default_file
            else:
                self.logger.error("Token file not found. Please create token/tokens.txt with your API tokens.")
                print("Token file not found. Please create token/tokens.txt with your API tokens.")
                return False
        
        try:
            with open(token_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
            
            decrypted_lines = []
            for line in lines:
                line = line.strip()
                if line and not line.startswith("#"):
                    decrypted_token = self.token_manager.encryptor.decrypt_token(line)
                    if decrypted_token:
                        decrypted_lines.append(decrypted_token)
            
            if not decrypted_lines:
                self.logger.error("No valid tokens found in tokens.txt. Please add at least one token.")
                print("No valid tokens found in tokens.txt. Please add at least one token.")
                return False
            
            # Check if there are more than 10 tokens
            if len(decrypted_lines) > 10:
                self.logger.warning(f"Found {len(decrypted_lines)} tokens, but only the first 10 will be used.")
                decrypted_lines = decrypted_lines[:10]
            
            self.tokens = decrypted_lines
            self.logger.info(f"Successfully loaded {len(self.tokens)} tokens")
            print(f"Successfully loaded {len(self.tokens)} tokens")
            
            # Reset token index to be safe
            self.current_token_index = 0
            return True
        except Exception as e:
            self.logger.error(f"Error loading tokens: {str(e)}")
            print(f"Error loading tokens: {str(e)}")
            return False
    
    def save_new_token(self, token):
        """Save a new token to tokens.txt with encryption"""
        token_file = os.path.join(self.base_path, "token", "tokens.txt")
        
        try:
            # Encrypt token
            encrypted_token = self.token_manager.encryptor.encrypt_token(token)
            
            with open(token_file, "a", encoding="utf-8") as f:
                f.write(encrypted_token + "\n")
            
            self.logger.info("New token saved successfully")
            return True
        except Exception as e:
            self.logger.error(f"Error saving new token: {str(e)}")
            return False

    def auto_encrypt_tokens_on_exit(self):
        """Automatically encrypt tokens when application exits"""
        try:
            # Ensure all tokens in file are encrypted
            self.token_manager.migrate_existing_tokens()
            self.logger.info("Auto-encryption completed on exit")
        except Exception as e:
            self.logger.error(f"Error during auto-encryption: {str(e)}")

    def __del__(self):
        """Destructor to ensure tokens are encrypted when object is destroyed"""
        if hasattr(self, 'token_manager'):
            self.auto_encrypt_tokens_on_exit()

    def get_current_token(self):
        """Get the current token and rotate if needed"""
        # Check if tokens list is empty
        if not self.tokens:
            self.logger.error("No tokens available. Please add tokens to token/tokens.txt")
            return None
            
        if self.article_count >= self.token_rotation_threshold:
            # Reset counter and rotate to next token
            self.article_count = 0
            self.current_token_index = (self.current_token_index + 1) % len(self.tokens)
            self.logger.info(f"Rotated to token #{self.current_token_index + 1}")
            print(f"🔄 Rotated to token #{self.current_token_index + 1}")
        
        # Validate index before accessing tokens
        if 0 <= self.current_token_index < len(self.tokens):
            return self.tokens[self.current_token_index]
        else:
            self.logger.error(f"Token index {self.current_token_index} out of range (0-{len(self.tokens)-1})")
            # Reset index and try again
            self.current_token_index = 0
            if self.tokens:
                return self.tokens[0]
            return None
    
    def authenticate(self):
        """Authenticate with token from tokens.txt with improved token rotation"""
        self.logger.info("Starting authentication process")
    
        if os.path.exists(self.last_login_file):
            try:
                with open(self.last_login_file, "r", encoding="utf-8") as f:
                    last_login_data = json.load(f)
                    last_login_time = last_login_data.get("last_login_time", 0)
                    if time.time() - last_login_time < 86400:
                        self.logger.info("✅ Token is still valid. Skipping re-authentication.")
                        print("✅ Token is still valid. Skipping re-authentication.")
                        if not hasattr(self, 'tokens') or not self.tokens:
                            if not self.load_tokens():
                                return False
                        if not self.tokens:
                            self.logger.error("No tokens available despite having valid login")
                            print("❌ No tokens available despite having valid login")
                            return False
                        
                        # Initialize client with current token
                        token = self.get_current_token()
                        self._initialize_client(token)
                        return True
            except Exception as e:
                self.logger.error(f"Error reading last login file: {str(e)}")
    
        if not self.load_tokens():
            return False
    
        if not self.tokens:
            self.logger.error("No tokens available after loading")
            print("❌ No tokens available after loading")
            return False
    
        # Try each token until one works
        tried_tokens = set()
        for _ in range(len(self.tokens)):
            token = self.tokens[self.current_token_index]
            
            if token in tried_tokens:
                break
                
            tried_tokens.add(token)
            
            try:
                self._initialize_client(token)
                
                self.logger.info("Testing API connection...")
                
                # Test with a simple call
                test_messages = [
                    {"role": "system", "content": "You are a helpful assistant."},
                    {"role": "user", "content": "Test connection"}
                ]
                
                result = self.safe_api_call(test_messages, max_tokens=1)
                
                if result:
                    self.logger.info("Authentication successful!")
                    print("✅ Authentication successful!")
                    with open(self.last_login_file, "w", encoding="utf-8") as f:
                        json.dump({"last_login_time": time.time()}, f)
                    return True
                    
            except Exception as e:
                error_msg = str(e).lower()
                if any(phrase in error_msg for phrase in ['429', 'rate limit', 'quota', 'too many requests']):
                    self.logger.warning(f"Token {self.current_token_index + 1} rate limited during auth")
                    print(f"⚠️ Token {self.current_token_index + 1} rate limited. Trying next token...")
                    self.current_token_index = (self.current_token_index + 1) % len(self.tokens)
                else:
                    self.logger.error(f"Authentication failed: {str(e)}")
                    self.current_token_index = (self.current_token_index + 1) % len(self.tokens)
    
        print("❌ All tokens failed authentication or are rate limited.")
        return False

    def _initialize_client(self, token):
        """Initialize client based on model type"""
        if self.model_name.startswith(("openai/")):
            from openai import OpenAI
            self.client = OpenAI(
                base_url=self.endpoint,
                api_key=token,
            )
            self.sdk_type = "openai"
        else:
            from azure.ai.inference import ChatCompletionsClient
            from azure.core.credentials import AzureKeyCredential
            self.client = ChatCompletionsClient(
                endpoint=self.endpoint,
                credential=AzureKeyCredential(token),
            )
            self.sdk_type = "azure"

    def validate_prompt_variables(self, prompt):
        """Validate all required variables are available before processing"""
        required_vars = {
            'website_name': self.website_name,
            'language': self.language,
            'keyword': 'keyword',
            'title': 'title', 
            'audience_persona': self.audience_reference,
            'author_persona': self.author_reference,
            'writing_model_name': self.writing_model_name,
            'writing_tone_name': self.writing_tone_name,
            'copywriting_style_name': self.copywriting_style_name,
            # etc.
        }
        
        missing = []
        for var, value in required_vars.items():
            if f"{{{var}}}" in prompt and not value:
                missing.append(var)
                
        return len(missing) == 0, missing

    def load_prompts(self):
        """Load prompts from the predefined category"""
        lang_path = self.get_language_path()
        prompt_file = os.path.join(lang_path, "prompt", self.prompt_category, "articles.txt")
        prompt_default_file = os.path.join(lang_path, "prompt", self.prompt_category, "articles.default.txt")
        default_lang_path = os.path.join(self.base_path, "languages", "default") 
        default_prompt_file = os.path.join(default_lang_path, "prompt", self.prompt_category, "articles.default.txt")
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(prompt_file), exist_ok=True)
        
        # Try to load from active language first
        if os.path.exists(prompt_file):
            try:
                with open(prompt_file, "r", encoding="utf-8") as f:
                    prompts = f.readlines()
                    prompts = [p.strip() for p in prompts if p.strip()]
                    if prompts:
                        self.logger.info(f"Loaded prompts from {prompt_file}")
                        return prompts
            except Exception as e:
                self.logger.error(f"Error reading prompts from {prompt_file}: {str(e)}")
        
        # If no prompts loaded, try language-specific default file
        if os.path.exists(prompt_default_file):
            try:
                with open(prompt_default_file, "r", encoding="utf-8") as f:
                    prompts = f.readlines()
                    prompts = [p.strip() for p in prompts if p.strip()]
                    if prompts:
                        self.logger.info(f"Loaded prompts from language default {prompt_default_file}")
                        return prompts
            except Exception as e:
                self.logger.error(f"Error reading prompts from {prompt_default_file}: {str(e)}")
        
        # If still no prompts, try default language file
        if os.path.exists(default_prompt_file):
            try:
                with open(default_prompt_file, "r", encoding="utf-8") as f:
                    prompts = f.readlines()
                    prompts = [p.strip() for p in prompts if p.strip()]
                    if prompts:
                        self.logger.warning(f"Using default prompts from {default_prompt_file}")
                        return prompts
            except Exception as e:
                self.logger.error(f"Error reading default prompts: {str(e)}")
        
        self.logger.error("Could not load any prompts, using fallback")
        return ["Write an article about {keyword} with comprehensive information."]
    
    def load_custom_prompt(self, prompt_type):
        """Load custom prompt for profiles or pages"""
        lang_path = self.get_language_path()
        prompt_path = os.path.join(lang_path, "prompt", "page", f"{prompt_type}.txt")
        default_lang_path = os.path.join(self.base_path, "languages", "default")
        prompt_default_path = os.path.join(default_lang_path, "prompt", "page", f"{prompt_type}.default.txt")
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(prompt_path), exist_ok=True)
        
        # Load prompt from file
        try:
            if os.path.exists(prompt_path):
                with open(prompt_path, "r", encoding="utf-8") as f:
                    custom_prompt = f.read().strip()
                
                if custom_prompt:
                    self.logger.info(f"Loaded custom {prompt_type} prompt from {prompt_path}")
                    return custom_prompt
            
            # Try default path
            if os.path.exists(prompt_default_path):
                with open(prompt_default_path, "r", encoding="utf-8") as f:
                    custom_prompt = f.read().strip()
                self.logger.warning(f"Using default {prompt_type} prompt from {prompt_default_path}")
                return custom_prompt
            
            self.logger.error(f"Could not find {prompt_type} prompt in any location")
            return ""
        
        except Exception as e:
            self.logger.error(f"Error loading {prompt_type} prompt: {str(e)}")
            return ""
    
    def load_template(self):
        """Load template from the predefined category based on active language with schema fallback"""
        lang_path = self.get_language_path()
        template_file = os.path.join(lang_path, "templates_md", self.template_category, "template.md")
        template_default_file = os.path.join(lang_path, "templates_md", self.template_category, "template.default.md")
        default_lang_path = os.path.join(self.base_path, "languages", "default")
        default_template_file = os.path.join(default_lang_path, "templates_md", self.template_category, "template.md")
        default_template_default_file = os.path.join(default_lang_path, "templates_md", self.template_category, "template.default.md")
        
        # Try to load from regular template file first
        if os.path.exists(template_file):
            try:
                with open(template_file, "r", encoding="utf-8") as f:
                    template_content = f.read()
                    if template_content.strip():
                        self.logger.info(f"Loaded template from {template_file}")
                        return template_content
            except Exception as e:
                self.logger.error(f"Error reading template from {template_file}: {str(e)}")
        
        # If template not found or empty, try language-specific default file
        if os.path.exists(template_default_file):
            try:
                with open(template_default_file, "r", encoding="utf-8") as f:
                    template_content = f.read()
                    if template_content.strip():
                        self.logger.info(f"Loaded template from language default {template_default_file}")
                        return template_content
            except Exception as e:
                self.logger.error(f"Error reading template from {template_default_file}: {str(e)}")
        
        # If still no template, try default language template file
        if os.path.exists(default_template_file):
            try:
                with open(default_template_file, "r", encoding="utf-8") as f:
                    template_content = f.read()
                    if template_content.strip():
                        self.logger.warning(f"Using default template from {default_template_file}")
                        return template_content
            except Exception as e:
                self.logger.error(f"Error reading default template from {default_template_file}: {str(e)}")
        
        # Try default language default template file
        if os.path.exists(default_template_default_file):
            try:
                with open(default_template_default_file, "r", encoding="utf-8") as f:
                    template_content = f.read()
                    if template_content.strip():
                        self.logger.warning(f"Using default template default from {default_template_default_file}")
                        return template_content
            except Exception as e:
                self.logger.error(f"Error reading default template default from {default_template_default_file}: {str(e)}")
        
        # If current category template not found, fallback to blog template
        if self.template_category != "blog":
            self.logger.warning(f"Template for {self.template_category} not found, falling back to blog template")
            
            # Try blog template in current language
            blog_template_file = os.path.join(lang_path, "templates_md", "blog", "template.md")
            if os.path.exists(blog_template_file):
                try:
                    with open(blog_template_file, "r", encoding="utf-8") as f:
                        template_content = f.read()
                        if template_content.strip():
                            self.logger.info(f"Using blog template fallback from {blog_template_file}")
                            return template_content
                except Exception as e:
                    self.logger.error(f"Error reading blog template fallback: {str(e)}")
            
            # Try blog default template in current language
            blog_template_default_file = os.path.join(lang_path, "templates_md", "blog", "template.default.md")
            if os.path.exists(blog_template_default_file):
                try:
                    with open(blog_template_default_file, "r", encoding="utf-8") as f:
                        template_content = f.read()
                        if template_content.strip():
                            self.logger.info(f"Using blog default template fallback from {blog_template_default_file}")
                            return template_content
                except Exception as e:
                    self.logger.error(f"Error reading blog default template fallback: {str(e)}")
            
            # Try blog template in default language
            default_blog_template = os.path.join(default_lang_path, "templates_md", "blog", "template.md")
            if os.path.exists(default_blog_template):
                try:
                    with open(default_blog_template, "r", encoding="utf-8") as f:
                        template_content = f.read()
                        if template_content.strip():
                            self.logger.warning(f"Using default blog template fallback from {default_blog_template}")
                            return template_content
                except Exception as e:
                    self.logger.error(f"Error reading default blog template fallback: {str(e)}")
            
            # Try blog default template in default language
            default_blog_template_default = os.path.join(default_lang_path, "templates_md", "blog", "template.default.md")
            if os.path.exists(default_blog_template_default):
                try:
                    with open(default_blog_template_default, "r", encoding="utf-8") as f:
                        template_content = f.read()
                        if template_content.strip():
                            self.logger.warning(f"Using default blog template default fallback from {default_blog_template_default}")
                            return template_content
                except Exception as e:
                    self.logger.error(f"Error reading default blog template default fallback: {str(e)}")
        
        self.logger.error(f"No template available for category: {self.template_category}. Please add a template.")
        return ""
    
    def get_language_path(self):
        """Get path to current language directory, fallback to default if not found"""
        language_path = os.path.join(self.base_path, "languages", self.active_language)
        
        if os.path.exists(language_path):
            return language_path
        else:
            self.logger.warning(f"Language '{self.active_language}' directory not found, using default")
            return os.path.join(self.base_path, "languages", "default")
    
    def get_articles_to_revise(self):
        """Get articles that haven't been revised yet in current active niche"""
        niche_content_path = os.path.join(self.hugo_content_path, self.active_niche)
        if not os.path.exists(niche_content_path):
            self.logger.warning(f"No content directory for niche: {self.active_niche}")
            return []
    
        # Get all markdown files
        unrevised_articles = []
        for file in os.listdir(niche_content_path):
            if file.endswith('.md'):
                article_path = os.path.join(niche_content_path, file)
                
                # Check if article has been revised by looking for revision marker in frontmatter
                try:
                    with open(article_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if 'revised: false' in content.lower() or 'revised:' not in content.lower():
                            unrevised_articles.append(article_path)
                except Exception as e:
                    self.logger.error(f"Error reading file {file}: {str(e)}")
                    
        if unrevised_articles:
            self.logger.info(f"Found {len(unrevised_articles)} unrevised articles in niche: {self.active_niche}")
            print(f"Found {len(unrevised_articles)} unrevised articles in niche: {self.active_niche}")
        else:
            self.logger.info(f"No unrevised articles found in niche: {self.active_niche}")
            print(f"No unrevised articles found in niche: {self.active_niche}")
                
        return unrevised_articles
    
    def mark_article_as_revised(self, article_path):
        """Mark an article as revised by updating its frontmatter"""
        try:
            with open(article_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Extract frontmatter and content
            if content.startswith('---'):
                parts = content.split('---', 2)
                if len(parts) >= 3:
                    frontmatter = parts[1]
                    main_content = parts[2]
                    
                    # Update or add revised field
                    if 'revised:' in frontmatter.lower():
                        frontmatter = re.sub(
                            r'revised:\s*(false|true)',
                            'revised: true',
                            frontmatter,
                            flags=re.IGNORECASE
                        )
                    else:
                        frontmatter += '\nrevised: true'
                    
                    # Add revision date
                    if 'revision_date:' in frontmatter.lower():
                        frontmatter = re.sub(
                            r'revision_date:.*',
                            f'revision_date: {datetime.now().strftime("%Y-%m-%d")}',
                            frontmatter
                        )
                    else:
                        frontmatter += f'\nrevision_date: {datetime.now().strftime("%Y-%m-%d")}'
                    
                    # Reconstruct file content
                    updated_content = f'---\n{frontmatter}\n---{main_content}'
                    
                    # Save updated content
                    with open(article_path, 'w', encoding='utf-8') as f:
                        f.write(updated_content)
                        
                    self.logger.info(f"Marked article as revised: {article_path}")
                    return True
                    
            self.logger.error(f"Invalid frontmatter format in {article_path}")
            return False
            
        except Exception as e:
            self.logger.error(f"Error marking article as revised {article_path}: {str(e)}")
            return False

    def get_all_niches(self):
        """Get list of all available niches based on directory structure"""
        lang_path = self.get_language_path()
        keywords_dir = os.path.join(lang_path, "keywords")
        
        # Get subdirectories excluding _cache and logs
        niches = []
        if os.path.exists(keywords_dir):
            for item in os.listdir(keywords_dir):
                niche_path = os.path.join(keywords_dir, item)
                if os.path.isdir(niche_path) and item not in ['_cache', 'logs']:
                    niches.append(item)
        
        self.logger.info(f"Found {len(niches)} niches: {niches}")
        return niches
    
    def process_all_niches(self):
        """Process keywords from all niches, one by one"""
        total_articles = 0
        
        for niche in self.available_niches:
            self.logger.info(f"Processing niche: {niche}")
            print(f"\nProcessing niche: {niche}")
            
            # Switch to this niche
            self.switch_active_niche(niche)
            
            # Process this niche
            new_keywords = self.get_new_keywords()
            if not new_keywords:
                self.logger.info(f"No new keywords in niche {niche}, skipping...")
                print(f"No new keywords in niche {niche}, skipping...")
                continue
                
            # Process keywords for this niche
            articles_count = self.generate_articles_for_niche(new_keywords)
            total_articles += articles_count
            
            self.logger.info(f"Completed niche {niche}: generated {articles_count} articles")
            print(f"Completed niche {niche}: generated {articles_count} articles")
        
        return total_articles

    def sync_niche_content_folders(self):
        """
        Delete niche folders in content/ that no longer exist in languages/{language}/keywords/
        """
        keywords_dir = os.path.join(self.lang_path, "keywords")
        content_dir = self.hugo_content_path
    
        # Get a list of active niches from keywords/
        active_niches = set()
        if os.path.exists(keywords_dir):
            for item in os.listdir(keywords_dir):
                niche_path = os.path.join(keywords_dir, item)
                if os.path.isdir(niche_path) and item not in ['_cache', 'logs']:
                    active_niches.add(item)
    
        # Get all folders in content/
        if os.path.exists(content_dir):
            for folder in os.listdir(content_dir):
                folder_path = os.path.join(content_dir, folder)
                # Only delete folders that are not in keywords and not special folders (like 'profile', 'page', etc.)
                if (
                    os.path.isdir(folder_path)
                    and folder not in active_niches
                    and not folder.startswith("_")
                    and folder not in ['profile', 'page']
                ):
                    try:
                        shutil.rmtree(folder_path)
                        self.logger.info(f"🗑️ Folder content niche '{folder}' dihapus karena tidak ada di keywords/")
                        print(f"🗑️ Folder content niche '{folder}' dihapus karena tidak ada di keywords/")
                    except Exception as e:
                        self.logger.error(f"⚠️ Gagal menghapus folder content niche '{folder}': {e}")
                        print(f"⚠️ Gagal menghapus folder content niche '{folder}': {e}")

    def switch_active_niche(self, new_niche):
        """Switch to a different niche and update all related paths"""
        if new_niche not in self.available_niches:
            self.logger.error(f"Cannot switch to niche '{new_niche}' as it does not exist in available niches")
            return False
            
        self.logger.info(f"Switching from niche {self.active_niche} to {new_niche}")
        
        # Update active niche
        self.active_niche = new_niche
        
        # Update file paths for the new niche
        self.update_niche_paths()
        
        # Ensure directory structure for this niche exists
        self.ensure_directory_structure()
        
        return True

    def load_preference_persona(self):
        """Load audience and author reference persona from files with consistent fallback"""
        # Define file paths
        lang_path = self.get_language_path()
        default_lang_path = os.path.join(self.base_path, "languages", "default")
        
        # File paths with proper fallback priority
        file_paths = {
            'audience': [
                os.path.join(lang_path, "author", "audience-persona.txt"),
                os.path.join(lang_path, "author", "audience-persona.default.txt"), 
                os.path.join(default_lang_path, "author", "audience-persona.default.txt")
            ],
            'author': [
                os.path.join(lang_path, "author", "author-persona.txt"),
                os.path.join(lang_path, "author", "author-persona.default.txt"),
                os.path.join(default_lang_path, "author", "author-persona.default.txt")
            ]
        }
        
        # Create directories 
        os.makedirs(os.path.dirname(file_paths['audience'][0]), exist_ok=True)
        os.makedirs(os.path.dirname(file_paths['author'][0]), exist_ok=True)
        
        # Load personas with proper fallback chain
        audience_persona = []
        author_persona = []
        
        # Function to load from files with fallback
        def load_from_files(file_list, persona_type):
            for file_path in file_list:
                try:
                    if os.path.exists(file_path):
                        with open(file_path, "r", encoding="utf-8") as f:
                            content = [line.strip() for line in f if line.strip()]
                            if content:
                                self.logger.info(f"Loaded {persona_type} persona from: {file_path}")
                                return content
                except Exception as e:
                    self.logger.error(f"Error reading {persona_type} persona from {file_path}: {str(e)}")
                    continue
            return []
            
        # Load personas using fallback chain
        audience_persona = load_from_files(file_paths['audience'], 'audience')
        author_persona = load_from_files(file_paths['author'], 'author')
        
        return audience_persona, author_persona

    def get_all_persona_variants(self, persona_type):
        """
        Take all persona (pronoun) variants from the default file for multi languages.
        persona_type: 'audience' atau 'author'
        """
        default_lang_path = os.path.join(self.base_path, "languages", "default", "author")
        filename = f"{persona_type}-persona.default.txt"
        path = os.path.join(default_lang_path, filename)
        variants = set()
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    val = line.strip()
                    if val:
                        variants.add(val.lower())
        return variants
    
    def validate_persona_consistency(self, content):
        """Validate that only selected personas are used in the article with context awareness"""
        if not content or not self.audience_reference or not self.author_reference:
            return False
            
        # Get forbidden personas
        forbidden_audience = self.get_all_persona_variants("audience")
        forbidden_author = self.get_all_persona_variants("author")
        
        # Remove currently selected personas
        forbidden_audience.discard(self.audience_reference.lower())
        forbidden_author.discard(self.author_reference.lower())
        
        # Check for forbidden personas - with word boundary detection
        found_forbidden = []
        content_lower = content.lower()
        
        # Use regex with word boundaries to find whole words only
        for word in forbidden_audience:
            if word and re.search(r'\b' + re.escape(word) + r'\b', content_lower):
                found_forbidden.append(word)
        for word in forbidden_author:
            if word and re.search(r'\b' + re.escape(word) + r'\b', content_lower):
                found_forbidden.append(word)
                
        # Check minimum usage requirements - with word boundary detection
        audience_matches = re.findall(r'\b' + re.escape(self.audience_reference.lower()) + r'\b', content_lower)
        author_matches = re.findall(r'\b' + re.escape(self.author_reference.lower()) + r'\b', content_lower)
        min_audience_count = len(audience_matches)
        min_author_count = len(author_matches)
        
        if found_forbidden:
            self.logger.warning(f"Found forbidden personas: {', '.join(found_forbidden)}")
            return False
            
        if min_audience_count < 3:
            self.logger.warning(f"Audience persona '{self.audience_reference}' used only {min_audience_count} times (minimum 3)")
            return False
            
        if min_author_count < 2:
            self.logger.warning(f"Author persona '{self.author_reference}' used only {min_author_count} times (minimum 2)")
            return False
            
        return True
    
    def fix_persona_consistency(self, content):
        """Replace incorrect personas with the selected ones with improved context awareness"""
        if not content or not self.audience_reference or not self.author_reference:
            return content
            
        try:
            # Get forbidden personas
            forbidden_audience = self.get_all_persona_variants("audience")
            forbidden_author = self.get_all_persona_variants("author")
            
            # Remove selected personas
            forbidden_audience.discard(self.audience_reference.lower())
            forbidden_author.discard(self.author_reference.lower())
            
            # Track replacements for logging
            replacements_made = []
            
            # Replace forbidden personas with word boundaries
            result = content
            for wrong in forbidden_audience:
                if wrong and re.search(r'\b' + re.escape(wrong) + r'\b', result.lower(), re.IGNORECASE):
                    count = len(re.findall(r'\b' + re.escape(wrong) + r'\b', result.lower(), re.IGNORECASE))
                    result = re.sub(
                        r'\b' + re.escape(wrong) + r'\b', 
                        lambda m: self.audience_reference if m.group(0).lower() == wrong.lower() else m.group(0),
                        result, 
                        flags=re.IGNORECASE
                    )
                    replacements_made.append(f"{wrong} → {self.audience_reference} ({count}x)")
                    
            for wrong in forbidden_author:
                if wrong and re.search(r'\b' + re.escape(wrong) + r'\b', result.lower(), re.IGNORECASE):
                    count = len(re.findall(r'\b' + re.escape(wrong) + r'\b', result.lower(), re.IGNORECASE))
                    result = re.sub(
                        r'\b' + re.escape(wrong) + r'\b',
                        lambda m: self.author_reference if m.group(0).lower() == wrong.lower() else m.group(0),
                        result,
                        flags=re.IGNORECASE
                    )
                    replacements_made.append(f"{wrong} → {self.author_reference} ({count}x)")
                    
            # Additional check for common pronouns like 'you', 'your', 'we', 'our', etc.
            audience_replacements = {
                r'\byou\b': self.audience_reference,
                r'\byour\b': f"{self.audience_reference}'s",
                r'\byours\b': f"{self.audience_reference}'s"
            }
            
            author_replacements = {
                r'\bwe\b': self.author_reference,
                r'\bour\b': f"{self.author_reference}'s",
                r'\bi\b': self.author_reference,
                r'\bmy\b': f"{self.author_reference}'s",
                r'\bmine\b': f"{self.author_reference}'s"
            }
            
            # Apply additional replacements
            for pattern, replacement in audience_replacements.items():
                if re.search(pattern, result.lower()):
                    count = len(re.findall(pattern, result.lower(), re.IGNORECASE))
                    result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
                    replacements_made.append(f"{pattern[2:-2]} → {replacement} ({count}x)")
                    
            for pattern, replacement in author_replacements.items():
                if re.search(pattern, result.lower()):
                    count = len(re.findall(pattern, result.lower(), re.IGNORECASE))
                    result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
                    replacements_made.append(f"{pattern[2:-2]} → {replacement} ({count}x)")
                    
            if replacements_made:
                self.logger.info(f"Persona replacements made: {', '.join(replacements_made)}")
                    
            return result
                
        except Exception as e:
            self.logger.error(f"Error fixing persona consistency: {str(e)}")
            return content

    def load_and_select_preferences(self):
        """Load and consistently select audience and author personas for the entire article"""
        try:
            # Load all available personas
            audience_persona, author_persona = self.load_preference_persona()
            
            # Generate stable random selection based on timestamp 
            timestamp = int(time.time())
            random.seed(timestamp)
            
            # Select personas with validation
            selected_audience = self._select_valid_persona(audience_persona, "audience")
            selected_author = self._select_valid_persona(author_persona, "author")
            
            # Update BOTH reference variables consistently
            self.audience_reference = selected_audience
            self.author_reference = selected_author
            
            # Log selections
            self.logger.info(f"Selected audience persona: {self.audience_reference}")
            self.logger.info(f"Selected author persona: {self.author_reference}")
            print(f"Using audience persona: {self.audience_reference}")
            print(f"Using author persona: {self.author_reference}")
            
            return self.audience_reference, self.author_reference
            
        except Exception as e:
            self.logger.error(f"Error selecting personas: {str(e)}")
            raise ValueError("Failed to select valid personas")
    
    def _select_valid_persona(self, personas, persona_type):
        """Helper to select and validate a persona"""
        if not personas:
            default_path = os.path.join(self.base_path, "languages", "default", 
                                      "author", f"{persona_type}-persona.default.txt")
            try:
                with open(default_path, "r", encoding="utf-8") as f:
                    personas = [line.strip() for line in f if line.strip()]
            except Exception as e:
                self.logger.error(f"Error reading default {persona_type} personas: {str(e)}")
                personas = ["Reader" if persona_type == "audience" else "Expert"]
                
        return random.choice(personas) if personas else "Reader" if persona_type == "audience" else "Expert"
    
    def load_writing_model(self):
        """Load writing model persona from models.txt file"""
        lang_path = self.get_language_path()
        models_file = os.path.join(lang_path, "prompt", "models", "models.txt")
        models_default_file = os.path.join(lang_path, "prompt", "models", "models.default.txt")
        default_lang_path = os.path.join(self.base_path, "languages", "default")
        default_models_file = os.path.join(default_lang_path, "prompt", "models", "models.default.txt")
        
        # Create models directory if it doesn't exist
        os.makedirs(os.path.dirname(models_file), exist_ok=True)
        
        try:
            models = []
            
            # Try to read from regular file first
            if os.path.exists(models_file):
                with open(models_file, "r", encoding="utf-8") as f:
                    models = [line.strip() for line in f if line.strip()]
            
            # If no models, try language-specific default file
            if not models and os.path.exists(models_default_file):
                with open(models_default_file, "r", encoding="utf-8") as f:
                    models = [line.strip() for line in f if line.strip()]
            
            # If still no models, try default language directory
            if not models and os.path.exists(default_models_file):
                with open(default_models_file, "r", encoding="utf-8") as f:
                    models = [line.strip() for line in f if line.strip()]
            
            # Extract model names and descriptions
            model_options = {}
            for model in models:
                if ":" in model:
                    parts = model.split(":", 1)
                    if len(parts) == 2:
                        name, description = parts
                        model_options[name.strip()] = description.strip()
            
            if model_options:
                # Select a random model
                model_name = random.choice(list(model_options.keys()))
                model_description = model_options[model_name]
                self.logger.info(f"Selected writing model: {model_name}")
                return model_name, model_description
            else:
                # Fallback to default value
                self.logger.warning("No valid writing models found. Using default.")
                return "Informative", "Provide objective and comprehensive information with facts, data, and clear explanations."
        except Exception as e:
            self.logger.error(f"Error loading writing models: {str(e)}")
            return "Informative", "Provide objective and comprehensive information with facts, data, and clear explanations."
    
    def load_writing_tone(self):
        """Load writing tone options from tones.txt file"""
        lang_path = self.get_language_path()
        tones_file = os.path.join(lang_path, "style", "tone", "tones.txt")
        tones_default_file = os.path.join(lang_path, "style", "tone", "tones.default.txt")
        default_lang_path = os.path.join(self.base_path, "languages", "default")
        default_tones_file = os.path.join(default_lang_path, "style", "tone", "tones.default.txt")
        
        # Create tone directory if it doesn't exist
        os.makedirs(os.path.dirname(tones_file), exist_ok=True)
        
        try:
            tones = []
            
            # Try to read from regular file first
            if os.path.exists(tones_file):
                with open(tones_file, "r", encoding="utf-8") as f:
                    tones = [line.strip() for line in f if line.strip()]
            
            # If no tones, try language-specific default file
            if not tones and os.path.exists(tones_default_file):
                with open(tones_default_file, "r", encoding="utf-8") as f:
                    tones = [line.strip() for line in f if line.strip()]
                    
            # If still no tones, try default language directory
            if not tones and os.path.exists(default_tones_file):
                with open(default_tones_file, "r", encoding="utf-8") as f:
                    tones = [line.strip() for line in f if line.strip()]
            
            # Extract tone names and descriptions
            tone_options = {}
            for tone in tones:
                if ":" in tone:
                    parts = tone.split(":", 1)
                    if len(parts) == 2:
                        name, description = parts
                        tone_options[name.strip()] = description.strip()
            
            if tone_options:
                # Select a random tone
                tone_name = random.choice(list(tone_options.keys()))
                tone_description = tone_options[tone_name]
                self.logger.info(f"Selected writing tone: {tone_name}")
                return tone_name, tone_description
            else:
                self.logger.warning("No valid writing tones found. Using default.")
                return "Professional", "Clear, authoritative language with industry-specific terminology where appropriate."
        except Exception as e:
            self.logger.error(f"Error loading writing tones: {str(e)}")
            return "Professional", "Clear, authoritative language with industry-specific terminology where appropriate."

    def load_copywriting_style(self):
        """Load copywriting style options from copywriting.txt file"""
        lang_path = self.get_language_path()
        copywriting_file = os.path.join(lang_path, "style", "copywriting", "copywriting.txt")
        copywriting_default_file = os.path.join(lang_path, "style", "copywriting", "copywriting.default.txt")
        default_lang_path = os.path.join(self.base_path, "languages", "default")
        default_copywriting_file = os.path.join(default_lang_path, "style", "copywriting", "copywriting.default.txt")
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(copywriting_file), exist_ok=True)
        
        try:
            copywriting_styles = []
            
            # Try to read from regular file first
            if os.path.exists(copywriting_file):
                with open(copywriting_file, "r", encoding="utf-8") as f:
                    copywriting_styles = [line.strip() for line in f if line.strip()]
            
            # If no styles, try language-specific default file
            if not copywriting_styles and os.path.exists(copywriting_default_file):
                with open(copywriting_default_file, "r", encoding="utf-8") as f:
                    copywriting_styles = [line.strip() for line in f if line.strip()]
                    
            # If still no styles, try default language directory
            if not copywriting_styles and os.path.exists(default_copywriting_file):
                with open(default_copywriting_file, "r", encoding="utf-8") as f:
                    copywriting_styles = [line.strip() for line in f if line.strip()]
            
            # Extract style names and descriptions
            style_options = {}
            for style in copywriting_styles:
                if ":" in style:
                    parts = style.split(":", 1)
                    if len(parts) == 2:
                        name, description = parts
                        # Extract the main name without the explanation in parentheses
                        main_name = name.split("(")[0].strip()
                        style_options[main_name] = description.strip()
            
            if style_options:
                # Select a random copywriting style
                style_name = random.choice(list(style_options.keys()))
                style_description = style_options[style_name]
                self.logger.info(f"Selected copywriting style: {style_name}")
                return style_name, style_description
            else:
                self.logger.warning("No valid copywriting styles found. Using default.")
                return "AIDA", "Grab attention, build interest, create desire, prompt action."
        except Exception as e:
            self.logger.error(f"Error loading copywriting styles: {str(e)}")
            return "AIDA", "Grab attention, build interest, create desire, prompt action."
    
    def record_writing_stats(self, keyword, tone_name, copywriting_style, model_name):
        """Record information about writing tone and style for tracking"""
        lang_path = self.get_language_path()
        writing_stats_file = os.path.join(lang_path, "stats", "writing_stats.json")
        os.makedirs(os.path.dirname(writing_stats_file), exist_ok=True)
        
        stats = {}
        if os.path.exists(writing_stats_file):
            try:
                with open(writing_stats_file, "r", encoding="utf-8") as f:
                    stats = json.load(f)
            except:
                stats = {}
        
        stats[keyword] = {
            "date": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
            "language": self.language,
            "tone": tone_name,
            "copywriting_style": copywriting_style,
            "writing_model": model_name
        }
        
        with open(writing_stats_file, "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=4, ensure_ascii=False)
        
    def load_language(self):
        """Load language setting from language.txt file using code-name mapping"""
        lang_path = self.get_language_path()
        language_file = os.path.join(lang_path, "prompt", "language", "language.txt")
        language_default_file = os.path.join(lang_path, "prompt", "language", "language.default.txt")
        default_lang_path = os.path.join(self.base_path, "languages", "default")
        default_language_file = os.path.join(default_lang_path, "prompt", "language", "language.default.txt")
        
        os.makedirs(os.path.dirname(language_file), exist_ok=True)
        
        # Ensure default files exist
        self.create_default_files()
    
        try:
            # Try to read from active language directory first
            if os.path.exists(language_file):
                with open(language_file, "r", encoding="utf-8") as f:
                    language_lines = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
            # Fallback to default language directory
            elif os.path.exists(default_language_file):
                with open(default_language_file, "r", encoding="utf-8") as f:
                    language_lines = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
            else:
                # No language file found
                self.language_code = "en"
                self.language_name = "English"
                self.language = "en"
                self.logger.warning("No language file found. Using English as default.")
                return "en"
    
            languages = {}
            for line in language_lines:
                try:
                    code, name = line.split(":", 1)
                    code = code.strip().strip('"\'')
                    name = name.strip().strip('"\'')
                    languages[code] = name
                except ValueError:
                    continue
    
            if languages:
                first_code = list(languages.keys())[0]
                selected_language = languages[first_code]
    
                self.language_code = first_code
                self.language_name = selected_language
                self.language = first_code
    
                self.logger.info(f"Selected language: {selected_language} ({first_code})")
                print(f"Selected language: {selected_language} ({first_code})")
                return first_code  # return kode ISO
            else:
                self.language_code = "en"
                self.language_name = "English"
                self.language = "en"
                self.logger.warning("No language found in language.txt. Using English as default.")
                print("No language found in language.txt. Using English as default.")
                return "en"
        except Exception as e:
            self.logger.error(f"Error loading language: {str(e)}")
            self.language_code = "en"
            self.language_name = "English"
            self.language = "en"
            return "en"
    
    def load_website_name(self):
        """Load website name from config.toml file using toml parser"""
        config_file = os.path.join(self.base_path, "config.toml")
        default_name = "My Website"
    
        if not os.path.exists(config_file):
            self.logger.warning(f"Config file not found: {config_file}. Using default website name.")
            print(f"Config file not found: {config_file}. Using default website name.")
            return default_name
    
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                config = toml.load(f)
            
            # Take it from root, if not try from [params]
            website_name = config.get("title") or config.get("params", {}).get("title", default_name)
            self.logger.info(f"Loaded website name: {website_name}")
            print(f"Loaded website name: {website_name}")
            return website_name
        except Exception as e:
            self.logger.error(f"Error loading website name from config.toml: {str(e)}")
            print(f"Error loading website name from config.toml: {str(e)}")
            return default_name
    
    def load_cultural_references(self):
        """Load cultural references for target language/country"""
        # File paths for cultural references
        lang_path = self.get_language_path()
        config_file = os.path.join(lang_path, "style", "engagement", "culture_config.txt")
        config_default_file = os.path.join(lang_path, "style", "engagement", "culture_config.default.txt")
        default_lang_path = os.path.join(self.base_path, "languages", "default")
        default_config_file = os.path.join(default_lang_path, "style", "engagement", "culture_config.default.txt")
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(config_file), exist_ok=True)
                    
        # Try to load the custom file
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                content = f.read()
                # Try to parse as JSON
                return json.loads(content)
        except Exception as e:
            self.logger.error(f"Error loading culture config from {config_file}: {str(e)}")
            print(f"Error loading culture config: {str(e)}")
            try:
                with open(config_default_file, "r", encoding="utf-8") as f:
                    content = f.read()
                    return json.loads(content)
            except Exception:
                # Fallback to minimal default
                return {
                    "events": ["New Year's Day"],
                    "locations": ["Local area"],
                    "cuisines": ["Local food"],
                    "notable_figures": ["Local leaders"],
                    "cultural_values": ["Community"]
                }
    
    def analyze_cultural_relevance(self, article_content):
        """Enhanced cultural relevance analysis"""
        score = 0
        analysis = {"matches": [], "categories_used": set()}
        
        # Check for cultural references with weighted scoring
        for category, items in self.cultural_references.items():
            category_matches = 0
            for item in items:
                if item.lower() in article_content.lower():
                    category_matches += 1
                    analysis["matches"].append(f"Cultural: {item}")
                    analysis["categories_used"].add(category)
            
            # Progressive scoring based on number of matches per category
            if category_matches > 0:
                score += category_matches * 5  # Base points per match
                score += 10  # Bonus for using the category
        
        # Bonus for using multiple categories
        category_coverage = len(analysis["categories_used"]) / len(self.cultural_references)
        score += int(category_coverage * 30)  # Up to 30 bonus points for category coverage
        
        # Check for natural integration
        paragraph_count = len(article_content.split('\n\n'))
        references_per_paragraph = len(analysis["matches"]) / paragraph_count
        if references_per_paragraph >= 0.5:  # At least one reference every two paragraphs
            score += 15
        
        # Calculate overall score (0-100)
        analysis["score"] = min(100, score)
        analysis["rating"] = (
            "Exceptional" if score > 70 else
            "Excellent" if score > 50 else
            "Very Good" if score > 35 else
            "Good" if score > 20 else
            "Basic"
        )
        
        self.logger.info(f"Cultural relevance score: {analysis['score']} ({analysis['rating']})")
        print(f"Cultural relevance score: {analysis['score']} ({analysis['rating']})")
        
        return analysis
    
    def record_cultural_adaptation(self, keyword, analysis):
        """Record information about cultural adaptation for tracking"""
        lang_path = self.get_language_path()
        cultural_stats_file = os.path.join(lang_path, "stats", "cultural_adaptation.json")
        os.makedirs(os.path.dirname(cultural_stats_file), exist_ok=True)
        
        stats = {}
        if os.path.exists(cultural_stats_file):
            try:
                with open(cultural_stats_file, "r", encoding="utf-8") as f:
                    stats = json.load(f)
            except:
                stats = {}
        
        stats[keyword] = {
            "date": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
            "language": self.language,
            "cultural_score": analysis["score"],
            "rating": analysis["rating"],
            "matches": analysis["matches"][:5]
        }
        
        with open(cultural_stats_file, "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=4, ensure_ascii=False)
    
    def load_idioms_and_phrases(self):
        """Load local idioms and phrases for target language"""
        # File paths for idioms
        lang_path = self.get_language_path()
        config_file = os.path.join(lang_path, "style", "engagement", "idioms_config.txt")
        config_default_file = os.path.join(lang_path, "style", "engagement", "idioms_config.default.txt")
        default_lang_path = os.path.join(self.base_path, "languages", "default")
        default_config_file = os.path.join(default_lang_path, "style", "engagement", "idioms_config.default.txt")
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(config_file), exist_ok=True)
        
        # Try to load the custom file
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                content = f.read()
                # Try to parse as JSON
                return json.loads(content)
        except Exception as e:
            self.logger.error(f"Error loading idioms config from {config_file}: {str(e)}")
            print(f"Error loading idioms config: {str(e)}")
            try:
                with open(config_default_file, "r", encoding="utf-8") as f:
                    content = f.read()
                    return json.loads(content)
            except Exception:
                # Fallback to minimal default
                return {
                    "greetings": ["Hello"],
                    "transitions": ["Furthermore"],
                    "calls_to_action": ["Start now"],
                    "common_phrases": ["In conclusion"],
                    "closing": ["Thanks for reading"]
                }
    
    def load_user_behavior(self):
        """Load internet user behavior specific to target country"""
        # File paths for user behavior
        lang_path = self.get_language_path()
        config_file = os.path.join(lang_path, "style", "engagement", "behavior_config.txt")
        config_default_file = os.path.join(lang_path, "style", "engagement", "behavior_config.default.txt")
        default_lang_path = os.path.join(self.base_path, "languages", "default")
        default_config_file = os.path.join(default_lang_path, "style", "engagement", "behavior_config.default.txt")
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(config_file), exist_ok=True)
                    
        # Try to load the custom file
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                content = f.read()
                # Try to parse as JSON
                return json.loads(content)
        except Exception as e:
            self.logger.error(f"Error loading behavior config from {config_file}: {str(e)}")
            print(f"Error loading behavior config: {str(e)}")
            try:
                with open(config_default_file, "r", encoding="utf-8") as f:
                    content = f.read()
                    return json.loads(content)
            except Exception:
                # Fallback to minimal default
                return {
                    "preferred_platforms": ["Facebook"],
                    "content_preferences": ["Blog posts"],
                    "reading_habits": ["Reading online"],
                    "search_patterns": ["Searching in English"],
                    "trust_signals": ["Reviews"]
                }
    
    def ensure_client_initialized(self):
        """Make sure client and sdk_type are set correctly"""
        if not hasattr(self, 'sdk_type') or self.sdk_type is None:
            self.logger.warning("SDK type not set, attempting to reinitialize...")
            if not self.authenticate():
                return False
        
        if not hasattr(self, 'client') or self.client is None:
            self.logger.warning("Client not initialized, attempting to reinitialize...")
            token = self.get_current_token()
            if not token:
                return False
                
            try:
                if self.model_name.startswith(("openai/")):
                    from openai import OpenAI
                    self.client = OpenAI(
                        base_url=self.endpoint,
                        api_key=token,
                    )
                    self.sdk_type = "openai"
                else:
                    from azure.ai.inference import ChatCompletionsClient
                    from azure.core.credentials import AzureKeyCredential
                    self.client = ChatCompletionsClient(
                        endpoint=self.endpoint,
                        credential=AzureKeyCredential(token),
                    )
                    self.sdk_type = "azure"
                return True
            except Exception as e:
                self.logger.error(f"Error reinitializing client: {str(e)}")
                return False
        
        return True

    def generate_article(self, keyword, prompt, template):
        """Generate an article using GPT-4o via Azure - Updated with schema detection"""
        self.logger.info(f"Generating culturally-tailored article for keyword: {keyword} in {self.language}")
        print(f"\nGenerating culturally-tailored article for keyword: {keyword} in {self.language}")
        self.load_and_select_preferences()
    
        if not self.ensure_client_initialized():
            self.logger.error("Failed to initialize client. Cannot generate article.")
            print("❌ Failed to initialize client. Cannot generate article.")
            return None

        if not hasattr(self, 'sdk_type') or self.sdk_type is None:
            self.logger.error("SDK type not set. Please authenticate first.")
            print("❌ SDK type not set. Please authenticate first.")
            return None
            
        if not hasattr(self, 'client') or self.client is None:
            self.logger.error("Client not initialized. Please authenticate first.")
            print("❌ Client not initialized. Please authenticate first.")
            return None
    
        # Detect schema type and load appropriate template
        schema_type = self.detect_schema_type(keyword, self.active_niche)
        schema_template = self.load_template_by_schema(schema_type)
    
        # Use schema-specific template if available, otherwise use provided template
        if schema_template and schema_template.strip():
            template = schema_template
            self.logger.info(f"Using {schema_type} schema template for keyword: {keyword}")
        else:
            self.logger.warning(f"No {schema_type} template found, using default template")
    
        # Ensure personas are set before building prompt
        if not self.audience_reference or not self.author_reference:
            self.load_and_select_preferences()
    
        try:
            # Load writing model with better error handling
            try:
                writing_model_info = self.load_writing_model()
                if isinstance(writing_model_info, tuple) and len(writing_model_info) == 2:
                    writing_model_name, writing_model_description = writing_model_info
                else:
                    # Use defaults if returned value isn't as expected
                    self.logger.warning("Invalid writing model format, using defaults")
                    writing_model_name = "Informative"
                    writing_model_description = "Provide objective and comprehensive information with facts, data, and clear explanations."
            except Exception as e:
                self.logger.error(f"Error loading writing model: {str(e)}")
                writing_model_name = "Informative"
                writing_model_description = "Provide objective and comprehensive information with facts, data, and clear explanations."
            
            # Log the selected model for debugging
            self.logger.info(f"Selected writing model: {writing_model_name}")
            print(f"Selected writing model: {writing_model_name}")
    
            # Load writing tone with better error handling
            try:
                writing_tone_info = self.load_writing_tone()
                if isinstance(writing_tone_info, tuple) and len(writing_tone_info) == 2:
                    writing_tone_name, writing_tone_description = writing_tone_info
                else:
                    # Use defaults if returned value isn't as expected
                    self.logger.warning("Invalid writing tone format, using defaults")
                    writing_tone_name = "Professional"
                    writing_tone_description = "Clear, authoritative language with industry-specific terminology where appropriate."
            except Exception as e:
                self.logger.error(f"Error loading writing tone: {str(e)}")
                writing_tone_name = "Professional"
                writing_tone_description = "Clear, authoritative language with industry-specific terminology where appropriate."
            
            # Log the selected tone for debugging
            self.logger.info(f"Selected writing tone: {writing_tone_name}")
            print(f"Selected writing tone: {writing_tone_name}")
    
            # Load copywriting style with better error handling
            try:
                copywriting_style_info = self.load_copywriting_style()
                if isinstance(copywriting_style_info, tuple) and len(copywriting_style_info) == 2:
                    copywriting_style_name, copywriting_style_description = copywriting_style_info
                else:
                    # Use defaults if returned value isn't as expected
                    self.logger.warning("Invalid copywriting style format, using defaults")
                    copywriting_style_name = "AIDA"
                    copywriting_style_description = "Grab attention, build interest, create desire, prompt action."
            except Exception as e:
                self.logger.error(f"Error loading copywriting style: {str(e)}")
                copywriting_style_name = "AIDA"
                copywriting_style_description = "Grab attention, build interest, create desire, prompt action."
            
            # Log the selected style for debugging
            self.logger.info(f"Selected copywriting style: {copywriting_style_name}")
            print(f"Selected copywriting style: {copywriting_style_name}")
    
            # Load cultural elements with defensive programming and explicit defaults
            cultural_references = self.load_cultural_references() or {
                "events": ["Historical Event"],
                "locations": ["Notable Location"],
                "cuisines": ["Traditional Cuisine"], 
                "notable_figures": ["Important Figure"],
                "cultural_values": ["Core Value"]
            }
    
            idioms_and_phrases = self.load_idioms_and_phrases() or {
                "transitions": ["Furthermore", "Additionally"],
                "common_phrases": ["For example", "In other words"],
                "closing": ["In conclusion"]
            }
    
            user_behavior = self.load_user_behavior() or {
                "content_preferences": ["Detailed Articles", "Educational Content"],
                "reading_habits": ["Online Reading", "Research"],
                "trust_signals": ["Expert Sources", "Academic References"]
            }
    
            # Safe sample helper with explicit error handling
            def safe_sample(items, count=2):
                try:
                    if not items or not isinstance(items, (list, tuple)):
                        return []
                    return random.sample(items, min(count, len(items)))
                except Exception as e:
                    self.logger.error(f"Error in safe_sample: {str(e)}")
                    return items[:min(count, len(items))] if items else []
    
            # Load system prompts from files instead of hardcoding
            cultural_context_template = self.load_system_prompt("cultural_context")
            if not cultural_context_template:
                self.logger.warning("Cultural context template not found, using default")
                cultural_context_template = self.get_default_cultural_context_template()
    
            # Create cultural context with explicit error handling
            try:
                cultural_context = cultural_context_template
                replacements = {
                    "events": safe_sample(cultural_references.get("events", [])),
                    "locations": safe_sample(cultural_references.get("locations", [])),
                    "cuisines": safe_sample(cultural_references.get("cuisines", [])),
                    "notable_figures": safe_sample(cultural_references.get("notable_figures", [])),
                    "transitions": safe_sample(idioms_and_phrases.get("transitions", [])),
                    "common_phrases": safe_sample(idioms_and_phrases.get("common_phrases", [])),
                    "closing": safe_sample(idioms_and_phrases.get("closing", [])),
                    "content_preferences": safe_sample(user_behavior.get("content_preferences", [])),
                    "reading_habits": safe_sample(user_behavior.get("reading_habits", [])),
                    "trust_signals": safe_sample(user_behavior.get("trust_signals", []))
                }
    
                for key, items in replacements.items():
                    cultural_context = cultural_context.replace(
                        f"{{{key}}}", 
                        ", ".join(items) if items else f"Default {key}"
                    )
            except Exception as e:
                self.logger.error(f"Error creating cultural context: {str(e)}")
                cultural_context = cultural_context_template
            
            # Analyze keyword complexity to adjust instructions
            keyword_complexity = self.analyze_keyword_complexity(keyword)
            keyword_tokens = keyword.lower().split()
            num_tokens = len(keyword_tokens)
            
            # Create keyword variants for more natural inclusion
            keyword_variants = self.generate_keyword_variants(keyword)
            
            # Different instructions based on keyword complexity
            if num_tokens == 1:
                # Single word keywords - can be used directly
                keyword_instructions = f"""
                KEYWORD USAGE: Use the exact keyword '{keyword}' at least 5 times naturally throughout the article, 
                including once in the first paragraph and once in the conclusion.
                """
            elif num_tokens == 2:
                # Two-word keywords - can use exact or slight variations
                keyword_instructions = f"""
                KEYWORD USAGE: Use the exact keyword '{keyword}' at least 3-4 times naturally throughout the article.
                Additionally, you can use these natural variations occasionally: {', '.join(keyword_variants[:3])}.
                Make sure to include either the full keyword or a close variation in both the introduction and conclusion.
                """
            else:
                # Multi-word keywords - need more flexibility
                keyword_instructions = f"""
                KEYWORD USAGE: This is a complex multi-word keyword: '{keyword}'
                - Use the complete keyword phrase at least 2-3 times in the article
                - Use meaningful variations like: {', '.join(keyword_variants[:3])}
                - In the introduction and conclusion, include either the full keyword or most of its key terms
                - Ensure the key terms appear throughout the article in a natural way
                """
            
            formatted_prompt = prompt.replace("{keyword}", keyword)
            
            # Build prompt with explicit persona instructions
            prompt_with_personas = f"""
            IMPORTANT PERSONA INSTRUCTIONS:
            - ALWAYS use "{self.audience_reference}" to refer to the readers/audience
            - ALWAYS use "{self.author_reference}" to refer to the writer/author
            - DO NOT use any other pronouns or persona words
            
            {formatted_prompt}
            """
    
            # Add language and writing style instructions
            tone_and_style_prompt = f"""
            Write in {self.language} language.
            
            IMPORTANT: Only use "{self.audience_reference}" to refer to the audience and "{self.author_reference}" to refer to the author/writer. 
            Do NOT use any other pronouns or persona words except those set in persona files.
            
            Use these writing characteristics:
            1. Writing Model: {writing_model_name} - {writing_model_description}
            2. Tone: {writing_tone_name} - {writing_tone_description}
            3. Copywriting Structure: {copywriting_style_name} - {copywriting_style_description}
            
            {cultural_context}
            
            {prompt_with_personas}
            
            {keyword_instructions}
            
            The article should be 600-1100 words long and comprehensive.
            Include at least 2-3 headings with appropriate subtopics.
            """
    
            # Get current token and update client
            token = self.get_current_token()
            
            # Check if token is valid
            if not token:
                self.logger.error("No valid token available. Cannot generate article.")
                print("❌ No valid token available. Cannot generate article.")
                return None
            
            # Client based on SDK type
            if self.sdk_type == "openai":
                from openai import OpenAI
                self.client = OpenAI(
                    base_url=self.endpoint,
                    api_key=token,
                )
            else:  # azure
                from azure.ai.inference import ChatCompletionsClient
                from azure.core.credentials import AzureKeyCredential
                self.client = ChatCompletionsClient(
                    endpoint=self.endpoint,
                    credential=AzureKeyCredential(token),
                )
    
            # Load and prepare system message
            system_message_template = self.load_system_prompt("article_generator")
            if not system_message_template:
                self.logger.warning("Article generator system prompt not found, using default")
                system_message_template = self.get_default_article_generator_template()
                
            system_message = system_message_template.replace("{language}", self.language)
            system_message = system_message.replace("{writing_model_name}", writing_model_name)
            system_message = system_message.replace("{writing_tone_name}", writing_tone_name) 
            system_message = system_message.replace("{copywriting_style_name}", copywriting_style_name)
            system_message = system_message.replace("{keyword}", keyword)
    
            # Send request to AI model
            messages = [
                {
                    "role": "system",
                    "content": system_message
                },
                {
                    "role": "user", 
                    "content": tone_and_style_prompt
                }
            ]
            
            def api_call_with_advanced_params():
                if self.sdk_type == "openai":
                    response = self.client.chat.completions.create(
                        messages=messages,
                        temperature=0.4,
                        max_tokens=4500,
                        model=self.model_name,
                        presence_penalty=0.6,
                        frequency_penalty=0.6,
                        top_p=0.7
                    )
                else:  # azure
                    from azure.ai.inference.models import SystemMessage, UserMessage
                    azure_messages = [
                        SystemMessage(system_message),
                        UserMessage(tone_and_style_prompt)
                    ]
                    response = self.client.complete(
                        messages=azure_messages,
                        temperature=0.4,
                        max_tokens=4500,
                        model=self.model_name,
                        presence_penalty=0.6,
                        frequency_penalty=0.6,
                        top_p=0.7
                    )
                
                if response and response.choices and len(response.choices) > 0:
                    return response.choices[0].message.content
                return None
            
            article_content = self.retry_with_token_rotation(api_call_with_advanced_params)
            
            if not article_content:
                self.logger.error("Failed to generate article content after retries")
                return None
    
            # Increment article count for token rotation
            self.article_count += 1
    
            # Apply more flexible validation
            if not self.validate_article_content(article_content, keyword):
                self.logger.warning(f"Article for '{keyword}' failed validation")
                
                # Try one recovery attempt with keyword enhancement for complex keywords
                if num_tokens > 1 and keyword_complexity > 3:
                    self.logger.info(f"Attempting keyword enhancement for complex keyword: {keyword}")
                    
                    # Enhance the article with better keyword placement
                    enhanced_article = self.enhance_keyword_usage(article_content, keyword, keyword_variants)
                    
                    # Validate again with the enhanced article
                    if enhanced_article and self.validate_article_content(enhanced_article, keyword):
                        self.logger.info("Article passed validation after keyword enhancement")
                        article_content = enhanced_article
                    else:
                        self.logger.warning("Article failed validation even after keyword enhancement")
                        return None
                else:
                    return None
    
            # Ensure persona consistency in generated content
            if not self.validate_persona_consistency(article_content):
                self.logger.info(f"Improving persona consistency for '{keyword}'")
                article_content = self.fix_persona_consistency(article_content)
    
            # Validate character model, tone, copywriting
            style_config = {
                'model': writing_model_name,
                'tone': writing_tone_name,
                'copywriting': copywriting_style_name
            }
            article_content = self.enhance_with_model(article_content, style_config['model'])
            article_content = self.enhance_with_tone(article_content, style_config['tone'])
            article_content = self.enhance_with_copywriting(article_content, style_config['copywriting'])
    
            # Format and clean the content
            formatted_article = self.remove_h1_after_front_matter(
                self.format_template(template, keyword, article_content)
            )
        
            return formatted_article
    
        except Exception as e:
            self.logger.error(f"Error generating article: {str(e)}")
            print(f"Error generating article: {str(e)}")
            return None
    
    def enhance_with_model(self, content, model_name):
        """Enhance content based on writing model"""
        if model_name == 'Tutorial':
            return self._add_tutorial_elements(content)
        elif model_name == 'Informative':
            return self._add_informative_elements(content)
        elif model_name == 'Expository':
            return self._add_expository_elements(content)
        elif model_name == 'Descriptive':
            return self._add_descriptive_elements(content)
        elif model_name == 'Narrative':
            return self._add_narrative_elements(content)
        elif model_name == 'Persuasive':
            return self._add_persuasive_elements(content)
        elif model_name == 'Analytical':
            return self._add_analytical_elements(content)
        # Fallback if model not found
        return content
   
    def enhance_with_tone(self, content, tone_name):
        """Enhance content based on tone"""
        if tone_name == 'Professional':
            return self._add_professional_tone(content)
        elif tone_name == 'Casual':
            return self._add_casual_tone(content)
        elif tone_name == 'Formal':
            return self._add_formal_tone(content)
        elif tone_name == 'Friendly':
            return self._add_friendly_tone(content)
        elif tone_name == 'Enthusiastic':
            return self._add_enthusiastic_tone(content)
        elif tone_name == 'Humorous':
            return self._add_humorous_tone(content)
        elif tone_name == 'Technical':
            return self._add_technical_tone(content)
        # Fallback if tone not found
        return content
   
    def enhance_with_copywriting(self, content, style_name):
        """Enhance content based on copywriting style"""
        if style_name == 'AIDA':
            return self._apply_aida_framework(content)
        elif style_name == 'StoryBrand':
            return self._apply_storybrand_framework(content)
        elif style_name == 'PAS':
            return self._apply_pas_framework(content)
        elif style_name == '8 Life Force':
            return self._apply_life_force_framework(content)
        elif style_name == '4C':
            return self._apply_4c_framework(content)
        elif style_name == 'FAB':
            return self._apply_fab_framework(content)
        elif style_name == 'BAB':
            return self._apply_bab_framework(content)
        elif style_name == '4U':
            return self._apply_4u_framework(content)
        elif style_name == 'QUEST':
            return self._apply_quest_framework(content)
        elif style_name == 'Bucket Brigade':
            return self._apply_bucket_brigade_framework(content)
        elif style_name == 'Ladder of Engagement':
            return self._apply_ladder_framework(content)
        elif style_name == 'Power of 3':
            return self._apply_power_of_three_framework(content)
        # Fallback if copywriting style not found
        return content

    def _add_tutorial_elements(self, content):
        sections = [
            "## Prerequisites",
            "## Step-by-Step Instructions",
            "## Tips & Checklist",
            "## Case Study",
            "## FAQ"
        ]
        return self._merge_sections(content, sections)

    def _add_informative_elements(self, content):
        sections = [
            "## Key Facts",
            "## Statistical Data",
            "## Expert Analysis",
            "## References"
        ]
        return self._merge_sections(content, sections)

    def _add_professional_tone(self, content):
        """Add professional tone based on detected language"""
    
        # Multi-language professional tone replacements
        tone_patterns = {
            'en': {  # English
                r'\b(you|your)\b': 'the reader',
                r'\b(I|my|me|we|our)\b': 'the author',
                r'\b(folks|guys|dude|hey)\b': 'ladies and gentlemen',
                r'\b(wanna|gonna)\b': 'going to'
            },
            'id': {  # Indonesian  
                r'\b(kamu|anda|kalian)\b': 'pembaca',
                r'\b(saya|aku|gue|gw)\b': 'penulis',
                r'\b(guys|sob|bro)\b': 'pembaca sekalian'
            },
            'ar': {  # Arabic
                r'\b(انت|انتم)\b': 'القارئ',
                r'\b(انا|نحن)\b': 'الكاتب'
            },
            'ru': {  # Russian
                r'\b(ты|вы)\b': 'читатель',
                r'\b(я|мы)\b': 'автор'
            },
            'fr': {  # French
                r'\b(tu|vous)\b': 'le lecteur',
                r'\b(je|nous)\b': "l'auteur"
            },
            'es': {  # Spanish
                r'\b(tú|usted|ustedes)\b': 'el lector',
                r'\b(yo|nosotros)\b': 'el autor'
            },
            'pt': {  # Portuguese
                r'\b(tu|você|vocês)\b': 'o leitor',
                r'\b(eu|nós)\b': 'o autor'
            },
            'bn': {  # Bengali
                r'\b(তুমি|আপনি)\b': 'পাঠক',
                r'\b(আমি|আমরা)\b': 'লেখক'
            },
            'hi': {  # Hindi
                r'\b(तुम|आप)\b': 'पাঠक',
                r'\b(मैं|हम)\b': 'लेखক'
            },
            'ur': {  # Urdu
                r'\b(تم|آپ)\b': 'قاری',
                r'\b(میں|ہم)\b': 'مصنف'
            },
            'ja': {  # Japanese
                r'\b(あなた|君|お前)\b': '読者',
                r'\b(私|僕|俺|我々)\b': '筆者'
            },
            'ko': {  # Korean
                r'\b(너|당신)\b': '독자',
                r'\b(나|우리)\b': '저자'
            },
            'zh': {  # Chinese
                r'\b(你|您)\b': '读者',
                r'\b(我|我们)\b': '作者'
            },
            'de': {  # German
                r'\b(du|ihr|sie)\b': 'der Leser',
                r'\b(ich|wir)\b': 'der Autor'
            },
            'it': {  # Italian
                r'\b(tu|voi|lei)\b': 'il lettore',
                r'\b(io|noi)\b': "l'autore"
            },
            'nl': {  # Dutch
                r'\b(jij|u)\b': 'de lezer',
                r'\b(ik|wij)\b': 'de auteur'
            },
            'sv': {  # Swedish
                r'\b(du|ni)\b': 'läsaren',
                r'\b(jag|vi)\b': 'författaren'
            },
            'no': {  # Norwegian
                r'\b(du|dere)\b': 'leseren',
                r'\b(jeg|vi)\b': 'forfatteren'
            },
            'fi': {  # Finnish
                r'\b(sinä|te)\b': 'lukija',
                r'\b(minä|me)\b': 'kirjoittaja'
            },
            'da': {  # Danish
                r'\b(du|I)\b': 'læseren',
                r'\b(jeg|vi)\b': 'forfatteren'
            }
        }
    
        # Get patterns for detected language or fallback to English
        patterns = tone_patterns.get(self.language_code, tone_patterns['en'])
        
        # Apply all replacements
        for pattern, repl in patterns.items():
            content = re.sub(pattern, repl, content, flags=re.IGNORECASE)
        
        return content

    def _add_casual_tone(self, content):
        """Add casual tone based on detected language"""
        
        # Multi-language casual tone replacements
        casual_patterns = {
            'en': {  # English
                r'\bHowever\b': 'But',
                r'\bTherefore\b': 'So',
                r'\butilize\b': 'use',
                r'\brequire\b': 'need'
            },
            'id': {  # Indonesian
                r'\bNamun\b': 'Tapi',
                r'\bOleh karena itu\b': 'Jadi',
                r'\bgunakan\b': 'pakai',
                r'\bselanjutnya\b': 'terus'
            },
            'ar': {  # Arabic
                r'\bومع ذلك\b': 'لكن',
                r'\bوبالتالي\b': 'ف',
                r'\bيستخدم\b': 'يستعمل'
            },
            'ru': {  # Russian
                r'\bоднако\b': 'но',
                r'\bследовательно\b': 'значит',
                r'\bиспользовать\b': 'юзать'
            },
            'fr': {  # French
                r'\bcependant\b': 'mais',
                r'\bdonc\b': 'alors',
                r'\butiliser\b': 'employer'
            },
            'es': {  # Spanish
                r'\bSin embargo\b': 'Pero',
                r'\bPor lo tanto\b': 'Así que',
                r'\butilizar\b': 'usar',
                r'\brequerir\b': 'necesitar'
            },
            'pt': {  # Portuguese
                r'\bNo entanto\b': 'Mas',
                r'\bPortanto\b': 'Então',
                r'\butilizar\b': 'usar',
                r'\brequerer\b': 'precisar'
            },
            'bn': {  # Bengali
                r'\bতবে\b': 'কিন্তু',
                r'\bঅতএব\b': 'তাই',
                r'\bব্যবহার\b': 'ইউজ',
                r'\bপ্রয়োজন\b': 'চাই'
            },
            'hi': {  # Hindi
                r'\bहालांकि\b': 'लेकिन',
                r'\bइसलिए\b': 'तो',
                r'\bप्रयोग\b': 'यूज़',
                r'\bआवश्यक\b': 'ज़रूरत'
            },
            'ur': {  # Urdu
                r'\bتاہم\b': 'لیکن',
                r'\bلہذا\b': 'تو',
                r'\bاستعمال\b': 'یوز',
                r'\bضرورت\b': 'چاہیے'
            },
            'ja': {  # Japanese
                r'\bしかし\b': 'でも',
                r'\bしたがって\b': 'だから',
                r'\b利用\b': '使う',
                r'\b必要\b': 'いる'
            },
            'ko': {  # Korean
                r'\b하지만\b': '근데',
                r'\b그러므로\b': '그래서',
                r'\b사용\b': '쓰다',
                r'\b필요\b': '필요해'
            },
            'zh': {  # Chinese
                r'\b然而\b': '但是',
                r'\b因此\b': '所以',
                r'\b使用\b': '用',
                r'\b需要\b': '要'
            },
            'de': {  # German
                r'\bJedoch\b': 'Aber',
                r'\bDaher\b': 'Also',
                r'\bverwenden\b': 'nutzen',
                r'\berfordern\b': 'brauchen'
            },
            'it': {  # Italian
                r'\bTuttavia\b': 'Ma',
                r'\bPertanto\b': 'Quindi',
                r'\butilizzare\b': 'usare',
                r'\brichiedere\b': 'servire'
            },
            'nl': {  # Dutch
                r'\bEchter\b': 'Maar',
                r'\bDaarom\b': 'Dus',
                r'\bgebruiken\b': 'gebruiken',
                r'\bvereisen\b': 'nodig hebben'
            },
            'sv': {  # Swedish
                r'\bDock\b': 'Men',
                r'\bDärför\b': 'Så',
                r'\banvända\b': 'bruka',
                r'\bkräva\b': 'behöva'
            },
            'no': {  # Norwegian
                r'\bImidlertid\b': 'Men',
                r'\bDerfor\b': 'Så',
                r'\bbruke\b': 'bruke',
                r'\bkreve\b': 'trenge'
            },
            'fi': {  # Finnish
                r'\bKuitenkin\b': 'Mutta',
                r'\bSiksi\b': 'Joten',
                r'\bkäyttää\b': 'käyttää',
                r'\bvaatia\b': 'tarvita'
            },
            'da': {  # Danish
                r'\bDog\b': 'Men',
                r'\bDerfor\b': 'Så',
                r'\banvende\b': 'bruge',
                r'\bkræve\b': 'have brug for'
            }
        }
    
        # Get patterns for detected language or fallback to English
        patterns = casual_patterns.get(self.language_code, casual_patterns['en'])
        
        # Apply all replacements
        for pattern, repl in patterns.items():
            content = re.sub(pattern, repl, content, flags=re.IGNORECASE)
        
        return content

    def _add_expository_elements(self, content):
        sections = [
            "## Main Concept",
            "## Detailed Explanation",
            "## Illustrative Examples",
            "## Practical Applications"
        ]
        return self._merge_sections(content, sections)
    
    def _add_descriptive_elements(self, content):
        sections = [
            "## Visual Elements",
            "## Sensory Details",
            "## Spatial Relationships",
            "## Emotional Atmosphere"
        ]
        return self._merge_sections(content, sections)
    
    def _add_narrative_elements(self, content):
        sections = [
            "## Character Background",
            "## Setting",
            "## Plot Development",
            "## Resolution",
            "## Main Takeaway"
        ]
        return self._merge_sections(content, sections)
    
    def _add_persuasive_elements(self, content):
        sections = [
            "## Thesis Statement",
            "## Supporting Arguments",
            "## Evidence and Facts",
            "## Counter-Arguments",
            "## Call to Action"
        ]
        return self._merge_sections(content, sections)
    
    def _add_analytical_elements(self, content):
        sections = [
            "## Methodology",
            "## Core Components",
            "## Critical Analysis",
            "## Comparative Assessment",
            "## Conclusion and Implications"
        ]
        return self._merge_sections(content, sections)

    def _add_formal_tone(self, content):
        """Add formal tone based on detected language"""

        # Multi-language formal tone replacements
        formal_patterns = {
            'en': {  # English
                r"\bdon't\b": 'do not',
                r"\bcan't\b": 'cannot',
                r"\bwon't\b": 'will not',
                r"\bdidn't\b": 'did not',
                r"\bisn't\b": 'is not',
                r"\baren't\b": 'are not',
                r"\bwasn't\b": 'was not',
                r"\bweren't\b": 'were not',
                r"\bhadn't\b": 'had not',
                r"\bhaven't\b": 'have not',
                r"\blet's\b": 'let us',
                r"\bI'm\b": 'I am',
                r"\byou're\b": 'you are',
                r"\bwe're\b": 'we are',
                r"\bthey're\b": 'they are',
                r"\bhe's\b": 'he is',
                r"\bshe's\b": 'she is',
                r"\bit's\b": 'it is',
                r"\bthat's\b": 'that is',
                r"\bthere's\b": 'there is',
                r"\bwhat's\b": 'what is',
                r"\bwho's\b": 'who is',
                r"\bwhere's\b": 'where is',
                r"\bwhen's\b": 'when is',
                r"\bwhy's\b": 'why is',
                r"\bhow's\b": 'how is'
            },
            'id': {  # Indonesian
                r'\benggak\b': 'tidak',
                r'\bgak\b': 'tidak',
                r'\bkalo\b': 'kalau',
                r'\bgini\b': 'begini',
                r'\bgitu\b': 'begitu',
                r'\bkaya\b': 'seperti',
                r'\bdapet\b': 'dapat',
                r'\bbikin\b': 'membuat'
            },
            'ar': {  # Arabic
                r'\bمش\b': 'ليس',
                r'\bمافي\b': 'لا يوجد',
                r'\bمو\b': 'ليس',
                r'\bإنت\b': 'أنت',
                r'\bأنا\b': 'أنا',
                r'\bإحنا\b': 'نحن'
            },
            'ru': {  # Russian
                r'\bчё\b': 'что',
                r'\bчего\b': 'чего',
                r'\bщас\b': 'сейчас',
                r'\bтебя\b': 'вас',
                r'\bтвой\b': 'ваш',
                r'\bмой\b': 'мой',
                r'\bчё-то\b': 'что-то'
            },
            'fr': {  # French
                r"\bj'suis\b": 'je suis',
                r"\bt'es\b": 'tu es',
                r"\by'a\b": 'il y a',
                r"\bça\b": 'cela',
                r"\bparce qu'\b": 'parce que',
                r"\bqu'est-ce\b": 'que est-ce'
            },
            'es': {  # Spanish
                r"\bpa\b": 'para',
                r"\bna\b": 'nada',
                r"\btoa\b": 'toda',
                r"\bq\b": 'que',
                r"\bno más\b": 'solamente',
                r"\bvos\b": 'usted'
            },
            'pt': {  # Portuguese
                r"\btá\b": 'está',
                r"\bvc\b": 'você',
                r"\bnum\b": 'não',
                r"\bpro\b": 'para o',
                r"\bpra\b": 'para a',
                r"\bq\b": 'que'
            },
            'bn': {  # Bengali
                r'\bনা\b': 'নয়',
                r'\bতুই\b': 'আপনি',
                r'\bতুমি\b': 'আপনি',
                r'\bআমি\b': 'আমি',
                r'\bকই\b': 'কোথায়'
            },
            'hi': {  # Hindi
                r'\bनहीं\b': 'नहीं है',
                r'\bतू\b': 'आप',
                r'\bतुम\b': 'आप',
                r'\bमैं\b': 'मैं',
                r'\bक्या\b': 'क्या है'
            },
            'ur': {  # Urdu
                r'\bنہیں\b': 'نہیں ہے',
                r'\bتم\b': 'آپ',
                r'\bمیں\b': 'میں',
                r'\bکیا\b': 'کیا ہے'
            },
            'ja': {  # Japanese
                r'だよ': 'です',
                r'じゃない': 'ではありません',
                r'ね': 'です',
                r'よ': 'です',
                r'わかんない': '分かりません',
                r'やばい': '大変です'
            },
            'ko': {  # Korean
                r'야': '입니다',
                r'아니야': '아닙니다',
                r'그래': '그렇습니다',
                r'몰라': '모릅니다',
                r'진짜': '정말로'
            },
            'zh': {  # Chinese
                r'不是': '并非',
                r'没': '没有',
                r'啥': '什么',
                r'你们': '您们',
                r'咱们': '我们'
            },
            'de': {  # German
                r'\bdu\b': 'Sie',
                r'\bdein\b': 'Ihr',
                r'\bich\b': 'ich',
                r'\bwir\b': 'wir',
                r'\bkein\b': 'keines',
                r'\bwas\b': 'was ist'
            },
            'it': {  # Italian
                r'\btu\b': 'Lei',
                r'\btua\b': 'Sua',
                r'\bsono\b': 'sono',
                r'\bnoi\b': 'noi',
                r'\bnon\b': 'non è'
            },
            'nl': {  # Dutch
                r'\bjij\b': 'u',
                r'\bje\b': 'u',
                r'\bik\b': 'ik',
                r'\bwij\b': 'wij',
                r'\bgeen\b': 'niet'
            },
            'sv': {  # Swedish
                r'\bdu\b': 'Ni',
                r'\bdin\b': 'Er',
                r'\bvi\b': 'vi',
                r'\binget\b': 'ingenting'
            },
            'no': {  # Norwegian
                r'\bdu\b': 'De',
                r'\bdin\b': 'Deres',
                r'\bvi\b': 'vi',
                r'\bingenting\b': 'intet'
            },
            'fi': {  # Finnish
                r'\bsinä\b': 'Te',
                r'\bminä\b': 'minä',
                r'\bme\b': 'me',
                r'\bei\b': 'ei ole'
            },
            'da': {  # Danish
                r'\bdu\b': 'De',
                r'\bdin\b': 'Deres',
                r'\bvi\b': 'vi',
                r'\binget\b': 'intet'
            }
        }

        # Get patterns for detected language or fallback to English
        patterns = formal_patterns.get(self.language_code, formal_patterns['en'])

        # Apply all replacements
        for pattern, repl in patterns.items():
            content = re.sub(pattern, repl, content, flags=re.IGNORECASE)

        return content
    
    def _add_friendly_tone(self, content):
        """Add friendly tone based on detected language"""

        # Multi-language friendly tone replacements
        friendly_patterns = {
            'en': {
                r'\bInquiries\b': 'Questions',
                r'\bAssistance\b': 'Help',
                r'\bUtilize\b': 'Use',
                r'\bCommence\b': 'Start',
                r'\bProceed\b': 'Go ahead',
                r'\bAdditionally\b': 'Also',
                r'\bSubsequently\b': 'Then'
            },
            'id': {
                r'\bSelanjutnya\b': 'Lalu',
                r'\bSehubungan dengan\b': 'Tentang',
                r'\bMengenai\b': 'Soal',
                r'\bSebelumnya\b': 'Sebelum ini',
                r'\bDemikian\b': 'Begitu'
            },
            'ar': {
                r'\bاستفسارات\b': 'أسئلة',
                r'\bمساعدة\b': 'مساعدة بسيطة',
                r'\bاستخدم\b': 'استعمل',
                r'\bابدأ\b': 'لنبدأ',
                r'\bتابع\b': 'استمر',
                r'\bبالإضافة إلى ذلك\b': 'أيضًا',
                r'\bبعد ذلك\b': 'ثم'
            },
            'ru': {
                r'\bЗапросы\b': 'Вопросы',
                r'\bПомощь\b': 'Поддержка',
                r'\bИспользовать\b': 'Применять',
                r'\bНачать\b': 'Давайте начнем',
                r'\bПродолжить\b': 'Давайте продолжим',
                r'\bКроме того\b': 'Также',
                r'\bЗатем\b': 'Потом'
            },
            'fr': {
                r'\bDemandes\b': 'Questions',
                r'\bAssistance\b': 'Aide',
                r'\bUtiliser\b': 'Employer',
                r'\bCommencer\b': 'On commence',
                r'\bProcéder\b': 'Allons-y',
                r'\bDe plus\b': 'Aussi',
                r'\bEnsuite\b': 'Puis'
            },
            'es': {
                r'\bConsultas\b': 'Preguntas',
                r'\bAsistencia\b': 'Ayuda',
                r'\bUtilizar\b': 'Usar',
                r'\bComenzar\b': 'Empecemos',
                r'\bProceder\b': 'Adelante',
                r'\bAdemás\b': 'También',
                r'\bPosteriormente\b': 'Luego'
            },
            'pt': {
                r'\bDúvidas\b': 'Perguntas',
                r'\bAssistência\b': 'Ajuda',
                r'\bUtilizar\b': 'Usar',
                r'\bComeçar\b': 'Vamos começar',
                r'\bProsseguir\b': 'Vamos lá',
                r'\bAlém disso\b': 'Também',
                r'\bSubsequentemente\b': 'Depois'
            },
            'bn': {
                r'\bজিজ্ঞাসা\b': 'প্রশ্ন',
                r'\bসহায়তা\b': 'সহজ সাহায্য',
                r'\bব্যবহার\b': 'ইউজ করুন',
                r'\bআরম্ভ\b': 'চলুন শুরু করি',
                r'\bঅগ্রসর\b': 'এগিয়ে যান',
                r'\bঅতিরিক্তভাবে\b': 'এছাড়াও',
                r'\bপরবর্তীতে\b': 'তারপর'
            },
            'hi': {
                r'\bपूछताछ\b': 'सवाल',
                r'\bसहायता\b': 'मदद',
                r'\bप्रयोग\b': 'इस्तेमाल',
                r'\bआरंभ\b': 'चलो शुरू करें',
                r'\bआगे बढ़ें\b': 'आगे बढ़िए',
                r'\bअतिरिक्त\b': 'साथ ही',
                r'\bबाद में\b': 'फिर'
            },
            'ur': {
                r'\bاستفسارات\b': 'سوالات',
                r'\bمدد\b': 'آسان مدد',
                r'\bاستعمال\b': 'یوز کریں',
                r'\bآغاز\b': 'شروع کریں',
                r'\bآگے بڑھیں\b': 'آگے بڑھیں',
                r'\bاضافی\b': 'ساتھ ہی',
                r'\bبعد میں\b': 'پھر'
            },
            'ja': {
                r'\bお問い合わせ\b': 'ご質問',
                r'\bサポート\b': 'お手伝い',
                r'\b利用\b': '使ってください',
                r'\b開始\b': '始めましょう',
                r'\b進める\b': 'どうぞ',
                r'\bさらに\b': 'また',
                r'\bその後\b': 'それから'
            },
            'ko': {
                r'\b문의\b': '질문',
                r'\b지원\b': '도움',
                r'\b사용\b': '이용하세요',
                r'\b시작\b': '시작합시다',
                r'\b진행\b': '계속하세요',
                r'\b또한\b': '또',
                r'\b이후\b': '그 다음'
            },
            'zh': {
                r'\b咨询\b': '问题',
                r'\b协助\b': '帮助',
                r'\b使用\b': '用',
                r'\b开始\b': '让我们开始吧',
                r'\b继续\b': '请继续',
                r'\b此外\b': '还有',
                r'\b随后\b': '然后'
            },
            'de': {
                r'\bAnfragen\b': 'Fragen',
                r'\bUnterstützung\b': 'Hilfe',
                r'\bVerwenden\b': 'Nutzen',
                r'\bBeginnen\b': 'Lass uns anfangen',
                r'\bFortfahren\b': 'Mach weiter',
                r'\bZusätzlich\b': 'Auch',
                r'\bAnschließend\b': 'Dann'
            },
            'it': {
                r'\bRichieste\b': 'Domande',
                r'\bAssistenza\b': 'Aiuto',
                r'\bUtilizzare\b': 'Usa',
                r'\bIniziare\b': 'Iniziamo',
                r'\bProcedere\b': 'Vai avanti',
                r'\bInoltre\b': 'Anche',
                r'\bSuccessivamente\b': 'Poi'
            },
            'nl': {
                r'\bVragen\b': 'Vragen',
                r'\bHulp\b': 'Hulp',
                r'\bGebruiken\b': 'Gebruik',
                r'\bBeginnen\b': 'Laten we beginnen',
                r'\bDoorgaan\b': 'Ga door',
                r'\bBovendien\b': 'Ook',
                r'\bVervolgens\b': 'Daarna'
            },
            'sv': {
                r'\bFörfrågningar\b': 'Frågor',
                r'\bHjälp\b': 'Hjälp',
                r'\bAnvända\b': 'Använd',
                r'\bBörja\b': 'Låt oss börja',
                r'\bFortsätt\b': 'Fortsätt',
                r'\bDessutom\b': 'Också',
                r'\bDärefter\b': 'Sedan'
            },
            'no': {
                r'\bForespørsler\b': 'Spørsmål',
                r'\bHjelp\b': 'Hjelp',
                r'\bBruke\b': 'Bruk',
                r'\bBegynne\b': 'La oss begynne',
                r'\bFortsett\b': 'Fortsett',
                r'\bI tillegg\b': 'Også',
                r'\bDeretter\b': 'Så'
            },
            'fi': {
                r'\bKyselyt\b': 'Kysymykset',
                r'\bApua\b': 'Apu',
                r'\bKäyttää\b': 'Käytä',
                r'\bAloittaa\b': 'Aloitetaan',
                r'\bJatkaa\b': 'Jatka',
                r'\bLisäksi\b': 'Myös',
                r'\bSeuraavaksi\b': 'Sitten'
            },
            'da': {
                r'\bForespørgsler\b': 'Spørgsmål',
                r'\bHjælp\b': 'Hjælp',
                r'\bBrug\b': 'Brug',
                r'\bBegynd\b': 'Lad os begynde',
                r'\bFortsæt\b': 'Fortsæt',
                r'\bDerudover\b': 'Også',
                r'\bDerefter\b': 'Så'
            }
        }

        # Get patterns for detected language or fallback to English
        patterns = friendly_patterns.get(self.language_code, friendly_patterns['en'])

        # Apply all replacements
        for pattern, repl in patterns.items():
            content = re.sub(pattern, repl, content, flags=re.IGNORECASE)

        # Add friendly greetings and closings
        friendly_greetings = {
            'en': ['Hi there!', 'Hello!', 'Hey!'],
            'id': ['Halo!', 'Hai!', 'Apa kabar!'],
            'ar': ['مرحبًا!', 'أهلاً!', 'تحية طيبة!'],
            'ru': ['Привет!', 'Здравствуйте!', 'Добрый день!'],
            'fr': ['Bonjour!', 'Salut!', 'Coucou!'],
            'es': ['¡Hola!', '¡Buenas!', '¡Saludos!'],
            'pt': ['Olá!', 'Oi!', 'Saudações!'],
            'bn': ['হ্যালো!', 'স্বাগতম!', 'কেমন আছেন!'],
            'hi': ['नमस्ते!', 'हैलो!', 'सुप्रभात!'],
            'ur': ['سلام!', 'ہیلو!', 'خوش آمدید!'],
            'ja': ['こんにちは！', 'やあ！', 'お元気ですか！'],
            'ko': ['안녕하세요!', '안녕!', '반갑습니다!'],
            'zh': ['你好！', '嗨！', '大家好！'],
            'de': ['Hallo!', 'Guten Tag!', 'Servus!'],
            'it': ['Ciao!', 'Salve!', 'Buongiorno!'],
            'nl': ['Hallo!', 'Hoi!', 'Goedendag!'],
            'sv': ['Hej!', 'Hallå!', 'God dag!'],
            'no': ['Hei!', 'Hallo!', 'God dag!'],
            'fi': ['Hei!', 'Moi!', 'Terve!'],
            'da': ['Hej!', 'Halløj!', 'Goddag!']
        }

        friendly_closings = {
            'en': ['Thanks for reading!', 'Hope this helps!', 'Feel free to reach out!'],
            'id': ['Terima kasih sudah membaca!', 'Semoga membantu!', 'Jangan ragu untuk bertanya!'],
            'ar': ['شكرًا للقراءة!', 'أتمنى أن يكون مفيدًا!', 'لا تتردد في التواصل!'],
            'ru': ['Спасибо за чтение!', 'Надеюсь, это поможет!', 'Обращайтесь, если что!'],
            'fr': ['Merci de votre lecture!', 'J\'espère que cela aide!', 'N\'hésitez pas à me contacter!'],
            'es': ['¡Gracias por leer!', '¡Espero que ayude!', '¡No dudes en preguntar!'],
            'pt': ['Obrigado por ler!', 'Espero que ajude!', 'Fique à vontade para perguntar!'],
            'bn': ['পড়ার জন্য ধন্যবাদ!', 'আশা করি সাহায্য করবে!', 'জিজ্ঞাসা করতে দ্বিধা করবেন না!'],
            'hi': ['पढ़ने के लिए धन्यवाद!', 'आशा है यह मदद करेगा!', 'पूछने में संकोच न करें!'],
            'ur': ['پڑھنے کا شکریہ!', 'امید ہے مدد ملے گی!', 'پوچھنے میں ہچکچائیں نہیں!'],
            'ja': ['読んでくれてありがとう！', 'お役に立てれば幸いです！', '気軽にご連絡ください！'],
            'ko': ['읽어주셔서 감사합니다!', '도움이 되었으면 합니다!', '언제든 문의하세요!'],
            'zh': ['感谢阅读！', '希望对你有帮助！', '随时联系我！'],
            'de': ['Danke fürs Lesen!', 'Ich hoffe, das hilft!', 'Melden Sie sich gerne!'],
            'it': ['Grazie per aver letto!', 'Spero sia utile!', 'Sentiti libero di chiedere!'],
            'nl': ['Bedankt voor het lezen!', 'Hopelijk helpt dit!', 'Stel gerust je vraag!'],
            'sv': ['Tack för att du läste!', 'Hoppas det hjälper!', 'Tveka inte att fråga!'],
            'no': ['Takk for at du leste!', 'Håper dette hjelper!', 'Bare spør om du lurer på noe!'],
            'fi': ['Kiitos lukemisesta!', 'Toivottavasti tästä on apua!', 'Kysy rohkeasti!'],
            'da': ['Tak for at du læste med!', 'Håber det hjælper!', 'Spørg endelig!']
        }

        greetings = friendly_greetings.get(self.language_code, friendly_greetings['en'])
        closings = friendly_closings.get(self.language_code, friendly_closings['en'])

        import random
        greeting = random.choice(greetings)
        closing = random.choice(closings)

        if not content.startswith(tuple(greetings)):
            content = f"{greeting}\n\n{content}"

        if not any(content.rstrip().endswith(c) for c in closings):
            content = f"{content}\n\n{closing}"

        return content
    
    def _add_enthusiastic_tone(self, content):
        """Add enthusiastic tone based on detected language"""

        # Multi-language enthusiastic tone replacements
        enthusiastic_patterns = {
            'en': {  # English
                r'\bgood\b': 'great',
                r'\bnice\b': 'amazing',
                r'\bhelpful\b': 'incredibly helpful',
                r'\bimportant\b': 'crucial',
                r'\binteresting\b': 'fascinating'
            },
            'id': {  # Indonesian
                r'\bbaik\b': 'sangat baik',
                r'\bbagus\b': 'luar biasa',
                r'\bmembantu\b': 'sangat membantu',
                r'\bpenting\b': 'sangat penting',
                r'\bmenarik\b': 'sangat menarik'
            },
            'ar': {  # Arabic
                r'\bجيد\b': 'رائع',
                r'\bممتاز\b': 'مذهل',
                r'\bمفيد\b': 'مفيد للغاية',
                r'\bمهم\b': 'بالغ الأهمية',
                r'\bمثير\b': 'مثير للغاية'
            },
            'ru': {  # Russian
                r'\bхорошо\b': 'отлично',
                r'\bприятно\b': 'потрясающе',
                r'\bполезно\b': 'невероятно полезно',
                r'\bважно\b': 'крайне важно',
                r'\bинтересно\b': 'очень интересно'
            },
            'fr': {  # French
                r'\bbien\b': 'génial',
                r'\bagréable\b': 'incroyable',
                r'\butile\b': 'extrêmement utile',
                r'\bimportant\b': 'crucial',
                r'\bintéressant\b': 'fascinant'
            },
            'es': {  # Spanish
                r'\bbueno\b': 'genial',
                r'\bagradable\b': 'increíble',
                r'\bútil\b': 'sumamente útil',
                r'\bimportante\b': 'crucial',
                r'\binteresante\b': 'fascinante'
            },
            'pt': {  # Portuguese
                r'\bbom\b': 'ótimo',
                r'\blegal\b': 'incrível',
                r'\bútil\b': 'extremamente útil',
                r'\bimportante\b': 'crucial',
                r'\binteressante\b': 'fascinante'
            },
            'bn': {  # Bengali
                r'\bভাল\b': 'দারুণ',
                r'\bসুন্দর\b': 'অসাধারণ',
                r'\bসহায়ক\b': 'অত্যন্ত সহায়ক',
                r'\bগুরুত্বপূর্ণ\b': 'অত্যন্ত গুরুত্বপূর্ণ',
                r'\bমজার\b': 'অত্যন্ত মজার'
            },
            'hi': {  # Hindi
                r'\bअच्छा\b': 'शानदार',
                r'\bसुंदर\b': 'अद्भुत',
                r'\bसहायक\b': 'अत्यंत सहायक',
                r'\bमहत्वपूर्ण\b': 'अत्यंत महत्वपूर्ण',
                r'\bदिलचस्प\b': 'बेहद दिलचस्प'
            },
            'ur': {  # Urdu
                r'\bاچھا\b': 'زبردست',
                r'\bخوبصورت\b': 'حیرت انگیز',
                r'\bمددگار\b': 'انتہائی مددگار',
                r'\bاہم\b': 'انتہائی اہم',
                r'\bدلچسپ\b': 'انتہائی دلچسپ'
            },
            'ja': {  # Japanese
                r'\b良い\b': '素晴らしい',
                r'\b素敵\b': '驚くべき',
                r'\b役立つ\b': '非常に役立つ',
                r'\b重要\b': '極めて重要',
                r'\b面白い\b': 'とても面白い'
            },
            'ko': {  # Korean
                r'\b좋다\b': '최고다',
                r'\b멋지다\b': '놀랍다',
                r'\b도움이\b': '엄청나게 도움이',
                r'\b중요\b': '매우 중요',
                r'\b흥미롭다\b': '정말 흥미롭다'
            },
            'zh': {  # Chinese
                r'\b好\b': '非常好',
                r'\b棒\b': '太棒了',
                r'\b有用\b': '极其有用',
                r'\b重要\b': '至关重要',
                r'\b有趣\b': '非常有趣'
            },
            'de': {  # German
                r'\bgut\b': 'großartig',
                r'\bschön\b': 'fantastisch',
                r'\bhilfreich\b': 'unglaublich hilfreich',
                r'\bwichtig\b': 'äußerst wichtig',
                r'\binteressant\b': 'faszinierend'
            },
            'it': {  # Italian
                r'\bbuono\b': 'fantastico',
                r'\bbello\b': 'incredibile',
                r'\butile\b': 'estremamente utile',
                r'\bimportante\b': 'cruciale',
                r'\binteressante\b': 'affascinante'
            },
            'nl': {  # Dutch
                r'\bgoed\b': 'geweldig',
                r'\bmooi\b': 'fantastisch',
                r'\bbehulpzaam\b': 'ongelooflijk behulpzaam',
                r'\bbelangrijk\b': 'cruciaal',
                r'\binteressant\b': 'fascinerend'
            },
            'sv': {  # Swedish
                r'\bbra\b': 'fantastisk',
                r'\bfint\b': 'otroligt',
                r'\bhjälpsam\b': 'otroligt hjälpsam',
                r'\bviktig\b': 'avgörande',
                r'\bintressant\b': 'fängslande'
            },
            'no': {  # Norwegian
                r'\bgod\b': 'fantastisk',
                r'\bfin\b': 'utrolig',
                r'\bnyttig\b': 'ekstremt nyttig',
                r'\bviktig\b': 'avgjørende',
                r'\binteressant\b': 'fascinerende'
            },
            'fi': {  # Finnish
                r'\bhyvä\b': 'mahtava',
                r'\bhieno\b': 'uskomaton',
                r'\bhyödyllinen\b': 'erittäin hyödyllinen',
                r'\btärkeä\b': 'äärimmäisen tärkeä',
                r'\bkiinnostava\b': 'kiehtova'
            },
            'da': {  # Danish
                r'\bgod\b': 'fantastisk',
                r'\bflot\b': 'utrolig',
                r'\bhjælpsom\b': 'utrolig hjælpsom',
                r'\bvigtig\b': 'afgørende',
                r'\binteressant\b': 'fascinerende'
            }
        }

        # Get patterns for detected language or fallback to English
        patterns = enthusiastic_patterns.get(self.language_code, enthusiastic_patterns['en'])

        # Apply all replacements
        for pattern, repl in patterns.items():
            content = re.sub(pattern, repl, content, flags=re.IGNORECASE)

        # Add exclamation marks to end of sentences occasionally
        sentences = re.split(r'([.!?])', content)
        for i in range(0, len(sentences) - 1, 2):
            if sentences[i].strip() and sentences[i+1] == '.' and random.random() < 0.3:
                sentences[i+1] = '!'

        content = ''.join(sentences)

        return content
    
    def _add_humorous_tone(self, content):
        """Add humorous tone based on detected language"""

        # Multi-language humorous tone additions
        humorous_additions = {
            'en': [
                "(And trust me, I'm not making this up!)",
                "(Who would have thought, right?)",
                "(Shocking, I know!)",
                "(Hold onto your seats for this one!)",
                "(Plot twist!)"
            ],
            'id': [
                "(Dan percayalah, saya tidak mengada-ada!)",
                "(Siapa sangka, ya?)",
                "(Mengejutkan, bukan!)",
                "(Pegangan kursi untuk yang satu ini!)",
                "(Kejutan!)"
            ],
            'ar': [
                "(وصدقني، أنا لا أختلق هذا!)",
                "(من كان يظن ذلك؟)",
                "(مفاجأة، أليس كذلك!)",
                "(تمسكوا بمقاعدكم لهذا!)",
                "(منعطف غير متوقع!)"
            ],
            'ru': [
                "(И поверьте, я это не выдумал!)",
                "(Кто бы мог подумать, правда?)",
                "(Шок, знаю!)",
                "(Держитесь за стулья!)",
                "(Неожиданный поворот!)"
            ],
            'fr': [
                "(Et croyez-moi, je n'invente rien !)",
                "(Qui l'aurait cru ?)",
                "(Incroyable, non ?)",
                "(Accrochez-vous bien !)",
                "(Changement de situation !)"
            ],
            'es': [
                "(Y créeme, ¡no me lo estoy inventando!)",
                "(¿Quién lo hubiera pensado?)",
                "(¡Sorprendente, lo sé!)",
                "(¡Agárrense a sus asientos para esto!)",
                "(¡Giro inesperado!)"
            ],
            'pt': [
                "(E acredite, não estou inventando nada!)",
                "(Quem diria, né?)",
                "(Chocante, eu sei!)",
                "(Segure-se na cadeira para essa!)",
                "(Reviravolta!)"
            ],
            'bn': [
                "(বিশ্বাস করুন, আমি এটা বানাচ্ছি না!)",
                "(কে ভেবেছিল, তাই না?)",
                "(চমকপ্রদ, তাই না!)",
                "(এইটার জন্য চেয়ারে ধরে থাকুন!)",
                "(অপ্রত্যাশিত মোড়!)"
            ],
            'hi': [
                "(और यकीन मानिए, मैं यह बना नहीं रहा हूँ!)",
                "(किसने सोचा था, है ना?)",
                "(चौंकाने वाला, है ना!)",
                "(इसके लिए अपनी सीट पकड़ लें!)",
                "(प्लॉट ट्विस्ट!)"
            ],
            'ur': [
                "(اور یقین کریں، میں یہ بنا نہیں رہا!)",
                "(کس نے سوچا تھا، ہے نا؟)",
                "(حیران کن، ہے نا!)",
                "(اس کے لیے اپنی نشستیں سنبھال لیں!)",
                "(غیر متوقع موڑ!)"
            ],
            'ja': [
                "（信じてください、これは作り話じゃありません！）",
                "（誰が想像したでしょう？）",
                "（驚きですよね！）",
                "（これは椅子から落ちないように！）",
                "（まさかの展開！）"
            ],
            'ko': [
                "(믿으세요, 이건 진짜예요!)",
                "(누가 알았겠어요?)",
                "(충격적이죠!)",
                "(이건 의자 꽉 잡으세요!)",
                "(반전입니다!)"
            ],
            'zh': [
                "（相信我，我不是在编故事！）",
                "（谁能想到呢？）",
                "（震惊吧！）",
                "（这下要坐稳了！）",
                "（剧情反转！）"
            ],
            'de': [
                "(Und glauben Sie mir, ich erfinde das nicht!)",
                "(Wer hätte das gedacht?)",
                "(Schockierend, ich weiß!)",
                "(Halten Sie sich fest!)",
                "(Plot-Twist!)"
            ],
            'it': [
                "(E credetemi, non sto inventando nulla!)",
                "(Chi l'avrebbe mai detto?)",
                "(Sconvolgente, vero?)",
                "(Tenetevi forte per questa!)",
                "(Colpo di scena!)"
            ],
            'nl': [
                "(En geloof me, ik verzin dit niet!)",
                "(Wie had dat gedacht?)",
                "(Schokkend, hè!)",
                "(Hou je vast voor deze!)",
                "(Plottwist!)"
            ],
            'sv': [
                "(Och tro mig, jag hittar inte på det här!)",
                "(Vem hade kunnat tro det?)",
                "(Chockerande, eller hur!)",
                "(Håll i er nu!)",
                "(Plottwist!)"
            ],
            'no': [
                "(Og tro meg, jeg finner ikke på dette!)",
                "(Hvem skulle trodd det?)",
                "(Sjokkerende, ikke sant!)",
                "(Hold dere fast for denne!)",
                "(Plottwist!)"
            ],
            'fi': [
                "(Ja usko pois, en keksi tätä!)",
                "(Kuka olisi uskonut?)",
                "(Yllättävää, vai mitä!)",
                "(Pidä kiinni tuolistasi nyt!)",
                "(Juonenkäänne!)"
            ],
            'da': [
                "(Og tro mig, jeg finder ikke på det her!)",
                "(Hvem skulle have troet det?)",
                "(Chokerende, ikke sandt!)",
                "(Hold fast i stolen for denne her!)",
                "(Plottwist!)"
            ]
        }

        # Get humorous additions for detected language or fallback to English
        additions = humorous_additions.get(self.language_code, humorous_additions['en'])

        # Split content into paragraphs
        paragraphs = content.split("\n\n")

        # Add humorous remarks to some paragraphs (about 1/3 of them)
        for i in range(len(paragraphs)):
            if random.random() < 0.3 and len(paragraphs[i]) > 30:  # Only add to substantial paragraphs
                paragraphs[i] += " " + random.choice(additions)

        # Join paragraphs back together
        content = "\n\n".join(paragraphs)

        return content
    
    def _add_technical_tone(self, content):
        """Add technical tone based on detected language"""

        # Multi-language technical tone replacements
        technical_patterns = {
            'en': {  # English
                r'\buse\b': 'utilize',
                r'\bhelp\b': 'facilitate',
                r'\bmake\b': 'implement',
                r'\bchange\b': 'modify',
                r'\bstart\b': 'initialize',
                r'\bend\b': 'terminate',
                r'\btry\b': 'attempt',
                r'\bdo\b': 'execute',
                r'\bshow\b': 'demonstrate',
                r'\bfix\b': 'resolve',
                r'\blook at\b': 'analyze',
                r'\bcheck\b': 'verify'
            },
            'id': {  # Indonesian
                r'\bpakai\b': 'mengimplementasikan',
                r'\bbantu\b': 'memfasilitasi',
                r'\bbuat\b': 'mengeksekusi',
                r'\bubah\b': 'memodifikasi',
                r'\bmulai\b': 'menginisialisasi',
                r'\bakhir\b': 'menterminasi',
                r'\bcoba\b': 'melakukan percobaan',
                r'\blakukan\b': 'mengeksekusi',
                r'\btunjukkan\b': 'mendemonstrasikan',
                r'\bperbaiki\b': 'menyelesaikan permasalahan',
                r'\blihat\b': 'menganalisa',
                r'\bcek\b': 'verifikasi'
            },
            'ar': {  # Arabic
                r'\bاستخدم\b': 'وظف',
                r'\bساعد\b': 'سهل',
                r'\bاصنع\b': 'نفذ',
                r'\bغير\b': 'عدل',
                r'\bابدأ\b': 'هيئ',
                r'\bانته\b': 'أنهِ',
                r'\bحاول\b': 'جرب',
                r'\bافعل\b': 'نفذ',
                r'\bاعرض\b': 'وضح',
                r'\bاصلح\b': 'عالج',
                r'\bانظر\b': 'حلل',
                r'\bتحقق\b': 'تحقق'
            },
            'ru': {  # Russian
                r'\bиспользуй\b': 'применяй',
                r'\bпомоги\b': 'обеспечь',
                r'\bсделай\b': 'реализуй',
                r'\bизмени\b': 'модифицируй',
                r'\bначни\b': 'инициализируй',
                r'\bзаверши\b': 'заверши процесс',
                r'\bпопробуй\b': 'попытайся',
                r'\bсделай\b': 'выполни',
                r'\bпокажи\b': 'продемонстрируй',
                r'\bпочини\b': 'устрани',
                r'\bпосмотри\b': 'проанализируй',
                r'\bпроверь\b': 'верифицируй'
            },
            'fr': {  # French
                r'\butilise\b': 'exploite',
                r'\baide\b': 'facilite',
                r'\bfais\b': 'implémente',
                r'\bchange\b': 'modifie',
                r'\bdémarre\b': 'initialise',
                r'\btermine\b': 'termine',
                r'\bessaie\b': 'tente',
                r'\bfais\b': 'exécute',
                r'\bmontre\b': 'démontre',
                r'\brépare\b': 'résous',
                r'\brégarde\b': 'analyse',
                r'\bvérifie\b': 'vérifie'
            },
            'es': {  # Spanish
                r'\busar\b': 'utilizar',
                r'\bayuda\b': 'facilita',
                r'\bhaz\b': 'implementa',
                r'\bcambia\b': 'modifica',
                r'\binicia\b': 'inicializa',
                r'\btermina\b': 'finaliza',
                r'\bintenta\b': 'intenta',
                r'\bhaz\b': 'ejecuta',
                r'\bmuestra\b': 'demuestra',
                r'\brepara\b': 'resuelve',
                r'\bmira\b': 'analiza',
                r'\bverifica\b': 'verifica'
            },
            'pt': {  # Portuguese
                r'\busar\b': 'utilizar',
                r'\bajuda\b': 'facilita',
                r'\bfaça\b': 'implemente',
                r'\bmude\b': 'modifique',
                r'\binicie\b': 'inicialize',
                r'\btermine\b': 'finalize',
                r'\btente\b': 'tente',
                r'\bexecute\b': 'execute',
                r'\bmostre\b': 'demonstre',
                r'\bconserte\b': 'resolva',
                r'\bolhe\b': 'analise',
                r'\bverifique\b': 'verifique'
            },
            'bn': {  # Bengali
                r'\bব্যবহার\b': 'প্রয়োগ',
                r'\bসহায়তা\b': 'সহজীকরণ',
                r'\bকরো\b': 'বাস্তবায়ন',
                r'\bপরিবর্তন\b': 'পরিমার্জন',
                r'\bশুরু\b': 'আরম্ভ',
                r'\bশেষ\b': 'সমাপ্তি',
                r'\bচেষ্টা\b': 'প্রচেষ্টা',
                r'\bকরো\b': 'নির্বাহ',
                r'\bদেখাও\b': 'প্রদর্শন',
                r'\bমেরামত\b': 'সমাধান',
                r'\bদেখ\b': 'বিশ্লেষণ',
                r'\bপরীক্ষা\b': 'যাচাই'
            },
            'hi': {  # Hindi
                r'\bउपयोग\b': 'प्रयोग',
                r'\bमदद\b': 'सुविधा',
                r'\bबनाओ\b': 'कार्यान्वयन',
                r'\bबदल\b': 'संशोधित',
                r'\bशुरू\b': 'आरंभ',
                r'\bसमाप्त\b': 'समापन',
                r'\bकोशिश\b': 'प्रयास',
                r'\bकरो\b': 'निष्पादित',
                r'\bदिखाओ\b': 'प्रदर्शित',
                r'\bठीक\b': 'समाधान',
                r'\bदेखो\b': 'विश्लेषण',
                r'\bजांच\b': 'सत्यापन'
            },
            'ur': {  # Urdu
                r'\bاستعمال\b': 'اطلاق',
                r'\bمدد\b': 'آسانی',
                r'\bبناؤ\b': 'عمل درآمد',
                r'\bتبدیل\b': 'ترمیم',
                r'\bشروع\b': 'آغاز',
                r'\bختم\b': 'اختتام',
                r'\bکوشش\b': 'کوشش',
                r'\bکرو\b': 'عملدرآمد',
                r'\bدکھاؤ\b': 'نمائش',
                r'\bدرست\b': 'حل',
                r'\bدیکھو\b': 'تجزیہ',
                r'\bچیک\b': 'تصدیق'
            },
            'ja': {  # Japanese
                r'\b使う\b': '利用する',
                r'\b助ける\b': '促進する',
                r'\b作る\b': '実装する',
                r'\b変える\b': '修正する',
                r'\b始める\b': '初期化する',
                r'\b終わる\b': '終了する',
                r'\b試す\b': '試行する',
                r'\bする\b': '実行する',
                r'\b見せる\b': 'デモする',
                r'\b直す\b': '解決する',
                r'\b見る\b': '分析する',
                r'\b確認\b': '検証する'
            },
            'ko': {  # Korean
                r'\b사용\b': '활용',
                r'\b도움\b': '촉진',
                r'\b만들다\b': '구현',
                r'\b변경\b': '수정',
                r'\b시작\b': '초기화',
                r'\b종료\b': '종결',
                r'\b시도\b': '시도',
                r'\b하다\b': '실행',
                r'\b보여주다\b': '시연',
                r'\b고치다\b': '해결',
                r'\b보다\b': '분석',
                r'\b확인\b': '검증'
            },
            'zh': {  # Chinese
                r'\b使用\b': '利用',
                r'\b帮助\b': '促进',
                r'\b制作\b': '实现',
                r'\b更改\b': '修改',
                r'\b开始\b': '初始化',
                r'\b结束\b': '终止',
                r'\b尝试\b': '尝试',
                r'\b做\b': '执行',
                r'\b展示\b': '演示',
                r'\b修复\b': '解决',
                r'\b查看\b': '分析',
                r'\b检查\b': '验证'
            },
            'de': {  # German
                r'\bbenutzen\b': 'verwenden',
                r'\bhilfe\b': 'unterstützen',
                r'\bmachen\b': 'implementieren',
                r'\bändern\b': 'modifizieren',
                r'\bstarten\b': 'initialisieren',
                r'\bbeenden\b': 'terminieren',
                r'\bversuchen\b': 'versuchen',
                r'\btun\b': 'ausführen',
                r'\bzeigen\b': 'demonstrieren',
                r'\breparieren\b': 'beheben',
                r'\banschauen\b': 'analysieren',
                r'\bprüfen\b': 'verifizieren'
            },
            'it': {  # Italian
                r'\busare\b': 'utilizzare',
                r'\baiutare\b': 'facilitare',
                r'\bfare\b': 'implementare',
                r'\bcambiare\b': 'modificare',
                r'\biniziare\b': 'inizializzare',
                r'\bfinire\b': 'terminare',
                r'\bprovare\b': 'tentare',
                r'\beseguire\b': 'eseguire',
                r'\bmostrare\b': 'dimostrare',
                r'\briparare\b': 'risolvere',
                r'\bguardare\b': 'analizzare',
                r'\bcontrollare\b': 'verificare'
            },
            'nl': {  # Dutch
                r'\bgebruik\b': 'toepassen',
                r'\bhelp\b': 'faciliteren',
                r'\bmaak\b': 'implementeren',
                r'\bverander\b': 'modificeren',
                r'\bbegin\b': 'initialiseren',
                r'\beindig\b': 'beëindigen',
                r'\bprobeer\b': 'proberen',
                r'\bdoe\b': 'uitvoeren',
                r'\btoon\b': 'demonstreren',
                r'\brepareer\b': 'oplossen',
                r'\bbekijk\b': 'analyseren',
                r'\bcontroleer\b': 'verifiëren'
            },
            'sv': {  # Swedish
                r'\banvänd\b': 'tillämpa',
                r'\bhjälp\b': 'underlätta',
                r'\bgör\b': 'implementera',
                r'\bändra\b': 'modifiera',
                r'\bstarta\b': 'initiera',
                r'\bavsluta\b': 'terminera',
                r'\bförsök\b': 'försöka',
                r'\butför\b': 'exekvera',
                r'\bvisa\b': 'demonstrera',
                r'\breparera\b': 'åtgärda',
                r'\btitta\b': 'analysera',
                r'\bkontrollera\b': 'verifiera'
            },
            'no': {  # Norwegian
                r'\bbruk\b': 'benytt',
                r'\bhjelp\b': 'fasiliter',
                r'\blag\b': 'implementer',
                r'\bendring\b': 'modifiser',
                r'\bstart\b': 'initialiser',
                r'\bslutt\b': 'terminer',
                r'\bprøv\b': 'forsøk',
                r'\bgjør\b': 'utfør',
                r'\bvis\b': 'demonstrer',
                r'\breparer\b': 'løs',
                r'\bse\b': 'analyser',
                r'\bsjekk\b': 'verifiser'
            },
            'fi': {  # Finnish
                r'\bkäytä\b': 'hyödynnä',
                r'\bauta\b': 'helpota',
                r'\btee\b': 'toteuta',
                r'\bmuuta\b': 'muokkaa',
                r'\baloita\b': 'initialisoi',
                r'\blopeta\b': 'lopeta',
                r'\byritä\b': 'yritä',
                r'\bsuorita\b': 'suorita',
                r'\bnäytä\b': 'demonstroi',
                r'\bkorjaa\b': 'ratkaise',
                r'\bkatso\b': 'analysoi',
                r'\btarkista\b': 'verifioi'
            },
            'da': {  # Danish
                r'\bbrug\b': 'anvend',
                r'\bhjælp\b': 'facilitér',
                r'\blav\b': 'implementér',
                r'\bændr\b': 'modificér',
                r'\bstart\b': 'initialisér',
                r'\bslut\b': 'terminér',
                r'\bprøv\b': 'forsøg',
                r'\bgør\b': 'udfør',
                r'\bvis\b': 'demonstrér',
                r'\breparer\b': 'løs',
                r'\bkig\b': 'analysér',
                r'\btjek\b': 'verificér'
            }
        }

        # Get patterns for detected language or fallback to English
        patterns = technical_patterns.get(self.language_code, technical_patterns['en'])

        # Apply all replacements
        for pattern, repl in patterns.items():
            content = re.sub(pattern, repl, content, flags=re.IGNORECASE)

        return content

    def _apply_aida_framework(self, content):
        sections = [
            "## Attention",
            "## Interest",
            "## Desire",
            "## Action"
        ]
        return self._merge_sections(content, sections)

    def _apply_storybrand_framework(self, content):
        sections = [
            "## Hero: {audience_persona}",
            "## Guide: {author_persona}",
            "## Problem",
            "## Plan",
            "## Success",
            "## Failure",
            "## Call to Action"
        ]
        return self._merge_sections(content, sections)

    def _apply_pas_framework(self, content):
        sections = [
            "## Problem",
            "## Agitation",
            "## Solution"
        ]
        return self._merge_sections(content, sections)
    
    def _apply_life_force_framework(self, content):
        sections = [
            "## Survival/Health",
            "## Pleasure/Enjoyment",
            "## Pain Avoidance",
            "## Loved Ones Care",
            "## Social Approval",
            "## Status/Competence",
            "## Self-actualization"
        ]
        return self._merge_sections(content, sections)
    
    def _apply_4c_framework(self, content):
        sections = [
            "## Clear",
            "## Concise",
            "## Compelling",
            "## Credible"
        ]
        return self._merge_sections(content, sections)
    
    def _apply_fab_framework(self, content):
        sections = [
            "## Features",
            "## Advantages",
            "## Benefits"
        ]
        return self._merge_sections(content, sections)
    
    def _apply_bab_framework(self, content):
        sections = [
            "## Before",
            "## After",
            "## Bridge"
        ]
        return self._merge_sections(content, sections)
    
    def _apply_4u_framework(self, content):
        sections = [
            "## Unique",
            "## Useful",
            "## Urgent",
            "## Ultra-specific"
        ]
        return self._merge_sections(content, sections)
    
    def _apply_quest_framework(self, content):
        sections = [
            "## Qualify",
            "## Understand",
            "## Educate",
            "## Stimulate",
            "## Transition"
        ]
        return self._merge_sections(content, sections)
    
    def _apply_bucket_brigade_framework(self, content):

        # Split content into paragraphs
        paragraphs = content.split("\n\n")

        # Bucket brigade transition phrases for multiple languages
        transitions = {
            'en': [
                "But that's not all...",
                "Here's the interesting part...",
                "Now, you might be wondering...",
                "Let me explain why this matters...",
                "This is where it gets interesting...",
                "The best part is...",
                "Keep reading to discover...",
                "Let me tell you something important..."
            ],
            'id': [
                "Tapi itu belum semuanya...",
                "Inilah bagian yang menarik...",
                "Mungkin Anda bertanya-tanya...",
                "Biar saya jelaskan mengapa ini penting...",
                "Ini dia bagian yang menarik...",
                "Yang terbaik adalah...",
                "Teruslah membaca untuk mengetahui...",
                "Saya akan memberitahu Anda sesuatu yang penting..."
            ],
            'ar': [
                "ولكن هذا ليس كل شيء...",
                "إليك الجزء المثير...",
                "قد تتساءل الآن...",
                "دعني أوضح لماذا هذا مهم...",
                "هنا تصبح الأمور مثيرة...",
                "أفضل جزء هو...",
                "استمر في القراءة لاكتشاف...",
                "دعني أخبرك بشيء مهم..."
            ],
            'ru': [
                "Но это ещё не всё...",
                "Вот что интересно...",
                "Возможно, вы задаётесь вопросом...",
                "Позвольте объяснить, почему это важно...",
                "Здесь становится интересно...",
                "Самое лучшее впереди...",
                "Читайте дальше, чтобы узнать...",
                "Позвольте рассказать вам нечто важное..."
            ],
            'fr': [
                "Mais ce n'est pas tout...",
                "Voici la partie intéressante...",
                "Vous vous demandez peut-être...",
                "Laissez-moi vous expliquer pourquoi c'est important...",
                "C'est là que ça devient intéressant...",
                "Le meilleur reste à venir...",
                "Continuez à lire pour découvrir...",
                "Laissez-moi vous dire quelque chose d'important..."
            ],
            'es': [
                "Pero eso no es todo...",
                "Aquí viene la parte interesante...",
                "Ahora te estarás preguntando...",
                "Déjame explicarte por qué esto importa...",
                "Aquí es donde se pone interesante...",
                "La mejor parte es...",
                "Sigue leyendo para descubrir...",
                "Déjame contarte algo importante..."
            ],
            'pt': [
                "Mas isso não é tudo...",
                "Aqui está a parte interessante...",
                "Agora você deve estar se perguntando...",
                "Deixe-me explicar por que isso importa...",
                "É aqui que fica interessante...",
                "A melhor parte é...",
                "Continue lendo para descobrir...",
                "Deixe-me te contar algo importante..."
            ],
            'bn': [
                "কিন্তু এটাই সব নয়...",
                "এখানেই মজার অংশ...",
                "এখন আপনি ভাবতে পারেন...",
                "আমি ব্যাখ্যা করি কেন এটা গুরুত্বপূর্ণ...",
                "এখানেই বিষয়টি আকর্ষণীয় হয়ে ওঠে...",
                "সেরা অংশ হলো...",
                "আরও জানতে পড়তে থাকুন...",
                "আমি আপনাকে একটি গুরুত্বপূর্ণ কথা বলি..."
            ],
            'hi': [
                "लेकिन यही सब नहीं है...",
                "यहाँ है सबसे दिलचस्प हिस्सा...",
                "अब आप सोच रहे होंगे...",
                "मैं बताता हूँ कि यह क्यों महत्वपूर्ण है...",
                "यहीं से चीज़ें दिलचस्प हो जाती हैं...",
                "सबसे अच्छा हिस्सा है...",
                "जानने के लिए पढ़ते रहें...",
                "मैं आपको एक महत्वपूर्ण बात बताता हूँ..."
            ],
            'ur': [
                "لیکن یہ سب کچھ نہیں...",
                "یہ ہے دلچسپ حصہ...",
                "اب آپ سوچ رہے ہوں گے...",
                "میں وضاحت کرتا ہوں کہ یہ کیوں اہم ہے...",
                "یہاں سے بات دلچسپ ہو جاتی ہے...",
                "سب سے بہترین حصہ یہ ہے...",
                "مزید جاننے کے لیے پڑھتے رہیں...",
                "میں آپ کو ایک اہم بات بتاتا ہوں..."
            ],
            'ja': [
                "でも、これだけではありません…",
                "ここが面白いところです…",
                "今、あなたは疑問に思っているかもしれません…",
                "なぜこれが重要なのか説明します…",
                "ここからが本番です…",
                "一番のポイントは…",
                "続きを知りたい方は読み進めてください…",
                "大切なことをお伝えします…"
            ],
            'ko': [
                "하지만 이게 다가 아닙니다...",
                "여기서 흥미로운 부분이 있습니다...",
                "지금 궁금하실 수도 있습니다...",
                "왜 중요한지 설명드리겠습니다...",
                "여기서부터가 진짜입니다...",
                "가장 좋은 점은...",
                "계속 읽어보세요...",
                "중요한 이야기를 하나 말씀드릴게요..."
            ],
            'zh': [
                "但这还不是全部……",
                "精彩的部分来了……",
                "你现在可能会想……",
                "让我解释为什么这很重要……",
                "这里才是重点……",
                "最精彩的部分是……",
                "继续阅读以了解更多……",
                "让我告诉你一个重要的事情……"
            ],
            'de': [
                "Aber das ist noch nicht alles...",
                "Hier kommt der interessante Teil...",
                "Jetzt fragen Sie sich vielleicht...",
                "Lassen Sie mich erklären, warum das wichtig ist...",
                "Jetzt wird es spannend...",
                "Das Beste kommt noch...",
                "Lesen Sie weiter, um mehr zu erfahren...",
                "Ich möchte Ihnen etwas Wichtiges mitteilen..."
            ],
            'it': [
                "Ma non è tutto...",
                "Ecco la parte interessante...",
                "Ora ti starai chiedendo...",
                "Lascia che ti spieghi perché è importante...",
                "Qui diventa interessante...",
                "La parte migliore è...",
                "Continua a leggere per scoprire...",
                "Lascia che ti dica qualcosa di importante..."
            ],
            'nl': [
                "Maar dat is nog niet alles...",
                "Hier komt het interessante gedeelte...",
                "Nu vraag je je misschien af...",
                "Laat me uitleggen waarom dit belangrijk is...",
                "Hier wordt het pas echt interessant...",
                "Het beste moet nog komen...",
                "Blijf lezen om te ontdekken...",
                "Laat me je iets belangrijks vertellen..."
            ],
            'sv': [
                "Men det är inte allt...",
                "Här kommer den intressanta delen...",
                "Nu undrar du kanske...",
                "Låt mig förklara varför detta är viktigt...",
                "Här blir det spännande...",
                "Det bästa är...",
                "Fortsätt läsa för att upptäcka...",
                "Låt mig berätta något viktigt..."
            ],
            'no': [
                "Men det er ikke alt...",
                "Her kommer den interessante delen...",
                "Nå lurer du kanskje på...",
                "La meg forklare hvorfor dette er viktig...",
                "Her blir det spennende...",
                "Den beste delen er...",
                "Fortsett å lese for å finne ut...",
                "La meg fortelle deg noe viktig..."
            ],
            'fi': [
                "Mutta se ei ole vielä kaikki...",
                "Tässä tulee mielenkiintoinen osa...",
                "Nyt saatat miettiä...",
                "Annanpa selittää, miksi tämä on tärkeää...",
                "Tässä vaiheessa menee mielenkiintoiseksi...",
                "Paras osa on...",
                "Jatka lukemista saadaksesi selville...",
                "Kerronpa sinulle jotain tärkeää..."
            ],
            'da': [
                "Men det er ikke alt...",
                "Her kommer den interessante del...",
                "Nu tænker du måske...",
                "Lad mig forklare, hvorfor dette er vigtigt...",
                "Her bliver det spændende...",
                "Den bedste del er...",
                "Fortsæt med at læse for at opdage...",
                "Lad mig fortælle dig noget vigtigt..."
            ]
        }

        # Get transitions for detected language or fallback to English
        phrase_list = transitions.get(self.language_code, transitions['en'])

        # Add transitions to some paragraphs
        import random
        modified_paragraphs = []

        for i, para in enumerate(paragraphs):
            if i > 0 and i < len(paragraphs) - 1 and len(para) > 30 and random.random() < 0.4:
                # Add a transition at the beginning of paragraph
                transition = random.choice(phrase_list)
                modified_para = transition + " " + para
                modified_paragraphs.append(modified_para)
            else:
                modified_paragraphs.append(para)

        # Join paragraphs back together
        modified_content = "\n\n".join(modified_paragraphs)

        return modified_content
    
    def _apply_ladder_framework(self, content):
        sections = [
            "## Initial Offer (Low Commitment)",
            "## Engagement Point (Medium Commitment)",
            "## Value Demonstration",
            "## Trust Building",
            "## Main Conversion (High Commitment)"
        ]
        return self._merge_sections(content, sections)
    
    def _apply_power_of_three_framework(self, content):
        sections = [
            "## First Key Point",
            "## Second Key Point",
            "## Third Key Point"
        ]
        return self._merge_sections(content, sections)

    def _merge_sections(self, content, sections):
        """Helper method to merge sections into content"""
        
        # Check if the content already has similar sections
        existing_sections = re.findall(r'^#{2,3}\s+(.+)$', content, re.MULTILINE)
        
        if existing_sections:
            # Content already has sections, don't modify it
            return content
        else:
            # Split content into paragraphs
            paragraphs = content.split("\n\n")
            
            # Calculate paragraphs per section
            if len(paragraphs) < len(sections):
                # Not enough paragraphs, add sections to existing content
                return content + "\n\n" + "\n\n".join(sections)
            
            paras_per_section = max(1, len(paragraphs) // len(sections))
            
            result = []
            section_index = 0
            
            # Distribute paragraphs across sections
            for i in range(0, len(paragraphs), paras_per_section):
                if section_index < len(sections):
                    result.append(sections[section_index])
                    section_index += 1
                
                # Add paragraphs for this section
                for j in range(i, min(i + paras_per_section, len(paragraphs))):
                    result.append(paragraphs[j])
            
            # Add any remaining sections
            while section_index < len(sections):
                result.append(sections[section_index])
                section_index += 1
                result.append("Content for this section.")
            
            return "\n\n".join(result)
    
    def remove_h1_after_front_matter(self, markdown_text):
        """
        Comprehensive markdown processing function that:
        1. Fixes double quotes in front matter fields (""text"" -> "text")
        2. Removes H1/H2 headings after front matter
        3. Ensures proper spacing after front matter
        
        Handles various heading formats:
        - Regular headings (# or ##)
        - Headings wrapped in bold (**# Title**)
        - Headings wrapped in italic (*# Title*)
        - Bold/italic text followed by headings
        - Keyword placeholders followed by headings
        - Code blocks (```markdown)
        """
    
        lines = markdown_text.split('\n')
        new_lines = []
        in_front_matter = False
        front_matter_done = False
        heading_removed = False
        empty_line_after_frontmatter_added = False
    
        for i, line in enumerate(lines):
            stripped = line.strip()
    
            # Front matter boundary detection
            if stripped == "---":
                if not in_front_matter:
                    in_front_matter = True
                elif in_front_matter:
                    in_front_matter = False
                    front_matter_done = True
                    new_lines.append(line)
                    new_lines.append("")
                    empty_line_after_frontmatter_added = True
                    continue
                new_lines.append(line)
                continue
    
            # Process front matter lines - Fix double quotes
            if in_front_matter:
                if ':' in line:
                    # Split by first colon to separate key and value
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        key = parts[0]
                        value = parts[1].strip()
                        
                        # Handle different quote patterns
                        if value:
                            # Case 1: Empty double quotes ""
                            if value == '""':
                                new_lines.append(f'{key}: ""')
                                continue
                            
                            # Case 2: Double quotes at start and end with content
                            if value.startswith('""') and value.endswith('""') and len(value) > 4:
                                # Extract content between double quotes
                                content = value[2:-2]  # Remove "" from start and end
                                
                                # Check if content contains quotes that need escaping
                                if '"' in content:
                                    # Escape internal quotes
                                    escaped_content = content.replace('"', '\\"')
                                    new_lines.append(f'{key}: "{escaped_content}"')
                                else:
                                    new_lines.append(f'{key}: "{content}"')
                                continue
                            
                            # Case 3: Title with nested quotes like "Title: "Subtitle""
                            if value.startswith('"') and value.endswith('""') and value.count('"') >= 3:
                                # Find the pattern: "text "nested" text"
                                if re.match(r'^".*".*"$', value):
                                    # Remove the extra quote at the end
                                    fixed_value = value[:-1]  # Remove last "
                                    
                                    # Escape internal quotes (but not the wrapping ones)
                                    content = fixed_value[1:-1]  # Get content without wrapping quotes
                                    if '"' in content:
                                        escaped_content = content.replace('"', '\\"')
                                        new_lines.append(f'{key}: "{escaped_content}"')
                                    else:
                                        new_lines.append(f'{key}: {fixed_value}')
                                    continue
                            
                            # Case 4: Handle array values with double quotes
                            if value.startswith('[') and value.endswith(']'):
                                # Fix quotes within array elements
                                array_content = value[1:-1]  # Remove [ ]
                                elements = []
                                
                                # Split by comma but respect quoted strings
                                current = ""
                                in_quotes = False
                                quote_count = 0
                                
                                for char in array_content:
                                    if char == '"':
                                        quote_count += 1
                                        if quote_count == 2 and current.endswith('"'):
                                            # Double quote at end, replace with single
                                            current = current[:-1]
                                            quote_count = 1
                                        elif quote_count > 2:
                                            # Skip extra quotes
                                            continue
                                        else:
                                            current += char
                                            in_quotes = not in_quotes
                                    elif char == ',' and not in_quotes:
                                        if current.strip():
                                            elements.append(current.strip())
                                        current = ""
                                        quote_count = 0
                                    else:
                                        current += char
                                
                                if current.strip():
                                    elements.append(current.strip())
                                
                                # Reconstruct array
                                fixed_array = '[' + ', '.join(elements) + ']'
                                new_lines.append(f'{key}: {fixed_array}')
                                continue
                
                # If no special processing needed for front matter, keep original line
                new_lines.append(line)
                continue
    
            # Process content after front matter - Remove unwanted headings
            if front_matter_done and not heading_removed:
                # Remove unwanted ```markdown or ``` blocks
                if stripped.startswith("```"):
                    continue
    
                # Case 1: Regular headings (# or ##) - including those with italic content
                if re.match(r"^#{1,2} ", stripped):
                    heading_removed = True
                    continue
    
                # Case 2: Headings wrapped in bold (**# Title** or **## Title**)
                if re.match(r"^\*\*#{1,2} .*?\*\*$", stripped):
                    heading_removed = True
                    continue
    
                # Case 3: Headings wrapped in italic (*# Title* or *## Title*)
                if re.match(r"^\*#{1,2} .*?\*$", stripped):
                    heading_removed = True
                    continue
    
                # Case 4: Bold text followed by heading (**text**: # heading)
                if re.match(r"^\*\*.*\*\*:\s*#{1,2} ", stripped):
                    # Extract only the bold part before the colon
                    bold_match = re.match(r"^\*\*.*\*\*", stripped)
                    if bold_match:
                        new_lines.append(bold_match.group(0))
                    heading_removed = True
                    continue
    
                # Case 5: Italic text followed by heading (*text*: # heading)
                if re.match(r"^\*.*\*:\s*#{1,2} ", stripped):
                    # Extract only the italic part before the colon
                    italic_match = re.match(r"^\*.*\*", stripped)
                    if italic_match:
                        new_lines.append(italic_match.group(0))
                    heading_removed = True
                    continue
    
                # Case 6: Keyword placeholder followed by heading ({keyword} # heading)
                if re.match(r"\{.*?\}.*?#{1,2}", stripped):
                    heading_removed = True
                    continue
    
                # Case 7: Line that starts with # but is part of a complex format
                if stripped.startswith("#") and not re.match(r"^#{1,6} \w", stripped):
                    heading_removed = True
                    continue
    
            # Handle empty lines - prevent consecutive empty lines
            if stripped == "":
                if empty_line_after_frontmatter_added and i > 0:
                    # Check if previous line was also empty
                    prev_line_empty = (i > 0 and lines[i-1].strip() == "")
                    if prev_line_empty:
                        continue
                        
            new_lines.append(line)
    
        # Final cleanup: Ensure no consecutive empty lines in the entire document
        result = []
        prev_empty = False
        for line in new_lines:
            current_empty = line.strip() == ""
            
            if current_empty:
                if not prev_empty:
                    result.append(line)
            else:
                result.append(line)
            
            prev_empty = current_empty
    
        return '\n'.join(result)

    def remove_image_links_from_content(self, markdown_text):
        """
        Remove lines containing markdown image links ![...](...) or direct links to image files
        from article content after front matter. Also handles HTML img tags and various image formats.
        
        Supported formats:
        - Markdown images: ![alt](url)
        - Direct image URLs: https://example.com/image.jpg
        - HTML img tags: <img src="..." />
        - Various extensions: jpg, jpeg, png, webp, gif, svg, bmp, tiff, ico
        
        Args:
            markdown_text (str): Full markdown text with front matter
            
        Returns:
            str: Cleaned markdown text with image links removed from content
        """
        
        # Split front matter and content
        parts = markdown_text.split('---', 2)
        if len(parts) < 3:
            # No front matter found, process entire text as content
            front_matter = ""
            content = markdown_text
        else:
            # Front matter exists
            front_matter = f"---{parts[1]}---"
            content = parts[2]
        
        # Comprehensive regex patterns for different image formats
        patterns = [
            # Markdown image syntax: ![alt text](image_url)
            r'^\s*!\[.*?\]\(.*?\.(jpg|jpeg|png|webp|gif|svg|bmp|tiff|tif|ico)(\?[^\s]*)?\s*.*?\)\s*$',
            
            # Direct image URLs (with or without protocol)
            r'^\s*(https?://|www\.)[^\s]+?\.(jpg|jpeg|png|webp|gif|svg|bmp|tiff|tif|ico)(\?[^\s]*)?\s*$',
            
            # HTML img tags (single line)
            r'^\s*<img[^>]+src=["\'][^"\']*\.(jpg|jpeg|png|webp|gif|svg|bmp|tiff|tif|ico)[^"\']*["\'][^>]*/?>\s*$',
            
            # Image URLs without protocol
            r'^\s*[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/[^\s]*\.(jpg|jpeg|png|webp|gif|svg|bmp|tiff|tif|ico)(\?[^\s]*)?\s*$',
            
            # Base64 encoded images in markdown
            r'^\s*!\[.*?\]\(data:image/[^;]+;base64,[A-Za-z0-9+/=]+\)\s*$',
            
            # Markdown reference-style images
            r'^\s*!\[.*?\]\s*\[.*?\]\s*$',
            
            # Image reference definitions
            r'^\s*\[.*?\]:\s+.*\.(jpg|jpeg|png|webp|gif|svg|bmp|tiff|tif|ico)(\?[^\s]*)?\s*.*$'
        ]
        
        # Compile all patterns with case-insensitive matching
        compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
        
        # Additional patterns for common AI-generated image descriptions
        ai_image_patterns = [
            # Lines that look like image captions or descriptions
            r'^\s*\*?Image\s*(of|showing|depicting).*\*?\s*$',
            r'^\s*\*?Figure\s*\d*:.*\*?\s*$',
            r'^\s*\*?Photo\s*(of|showing).*\*?\s*$',
            r'^\s*\*?\[Image:.*\]\*?\s*$',
            r'^\s*\*?\(Image:.*\)\*?\s*$'
        ]
        
        # Compile AI image description patterns
        ai_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in ai_image_patterns]
        
        def is_image_line(line):
            """
            Check if a line contains an image link or AI-generated image description.
            
            Args:
                line (str): Line to check
                
            Returns:
                bool: True if line contains image content
            """
            stripped_line = line.strip()
            
            # Skip empty lines
            if not stripped_line:
                return False
            
            # Check against image patterns
            for pattern in compiled_patterns:
                if pattern.match(stripped_line):
                    return True
            
            # Check against AI image description patterns
            for pattern in ai_patterns:
                if pattern.match(stripped_line):
                    return True
                    
            return False
        
        # Process content line by line
        cleaned_lines = []
        content_lines = content.splitlines()
        prev_line_was_image = False
        
        for i, line in enumerate(content_lines):
            current_is_image = is_image_line(line)
            
            if current_is_image:
                # Skip image lines but don't create excessive empty lines
                if not prev_line_was_image and cleaned_lines and cleaned_lines[-1].strip():
                    # Add single empty line before removing image (for spacing)
                    cleaned_lines.append("")
                prev_line_was_image = True
                continue
            else:
                # Keep non-image lines
                cleaned_lines.append(line)
                prev_line_was_image = False
        
        # Clean up excessive empty lines
        final_lines = []
        prev_empty = False
        
        for line in cleaned_lines:
            is_empty = not line.strip()
            
            if is_empty:
                # Only add empty line if previous wasn't empty
                if not prev_empty:
                    final_lines.append(line)
            else:
                final_lines.append(line)
            
            prev_empty = is_empty
        
        # Reconstruct the markdown text
        cleaned_content = "\n".join(final_lines)
        
        if front_matter:
            return front_matter + "\n" + cleaned_content
        else:
            return cleaned_content

    def remove_meta_description_from_content(self, markdown_text):
        """
        Remove meta description lines from markdown content with comprehensive pattern matching.
        
        This function removes various formats of meta description including:
        - __Meta Description: ...
        - *Meta Description: ...*
        - **Meta Description**
        - Meta Description: ...
        - ---\nMeta Description: ...
        - And combinations with bold/italic/underline/strikethrough formatting
        
        Args:
            markdown_text (str): The markdown content to clean
            
        Returns:
            str: Cleaned markdown content without meta description lines
        """
        
        # Comprehensive regex patterns for meta description detection
        meta_desc_patterns = [
            # Pattern 1: Basic meta description with various markdown formatting
            # Matches: Meta Description:, **Meta Description:**, *Meta Description:*, etc.
            r'^\s*[*_~-]{0,3}\s*(?:\*{1,2}|_{1,2}|~{1,2})*\s*Meta\s*Description\s*[:：]\s*.*?(?:\*{1,2}|_{1,2}|~{1,2})*\s*[*_~-]{0,3}\s*$',
            
            # Pattern 2: Meta description without colon but with formatting
            # Matches: **Meta Description**, *Meta Description*, __Meta Description__
            r'^\s*(?:\*{1,2}|_{1,2}|~{1,2})+\s*Meta\s*Description\s*(?:\*{1,2}|_{1,2}|~{1,2})+\s*$',
            
            # Pattern 3: Meta description with HTML-like formatting
            # Matches: <strong>Meta Description</strong>, <em>Meta Description</em>
            r'^\s*<(?:strong|em|b|i)>\s*Meta\s*Description\s*(?:[:：].*?)?\s*</(?:strong|em|b|i)>\s*$',
            
            # Pattern 4: Meta description after horizontal rule
            # Matches: ---\nMeta Description: or ***\nMeta Description:
            r'^\s*[-*_]{3,}\s*\n\s*Meta\s*Description\s*[:：].*$',
            
            # Pattern 5: Meta description with numbers or special characters
            # Matches: 1. Meta Description:, - Meta Description:, • Meta Description:
            r'^\s*(?:\d+\.|\-|\*|\•|\+)\s*Meta\s*Description\s*[:：].*$',
            
            # Pattern 6: Meta description in quotes
            # Matches: "Meta Description:", 'Meta Description:', `Meta Description:`
            r'^\s*["\'\`]\s*Meta\s*Description\s*[:：].*?["\'\`]\s*$',
            
            # Pattern 7: Meta description with extra spacing and punctuation
            # Matches variations with multiple spaces, tabs, and punctuation
            r'^\s*[*_~-]*\s*M\s*e\s*t\s*a\s*\s+D\s*e\s*s\s*c\s*r\s*i\s*p\s*t\s*i\s*o\s*n\s*[*_~-]*\s*[:：].*$'
        ]
        
        # Compile all patterns with case-insensitive and multiline flags
        compiled_patterns = [
            re.compile(pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL) 
            for pattern in meta_desc_patterns
        ]
        
        # Split content to preserve front matter
        parts = markdown_text.split('---', 2)
        
        if len(parts) < 3:
            # No front matter detected
            content = markdown_text
            front_matter = ""
        else:
            # Front matter exists
            front_matter = f"---{parts[1]}---"
            content = parts[2]
        
        # Process content line by line
        lines = content.splitlines()
        cleaned_lines = []
        skip_next_empty = False
        
        for i, line in enumerate(lines):
            stripped_line = line.strip()
            is_meta_desc = False
            
            # Check against all patterns
            for pattern in compiled_patterns:
                if pattern.match(stripped_line):
                    is_meta_desc = True
                    break
            
            # Additional check for meta description after horizontal rules
            if not is_meta_desc and i > 0:
                prev_line = lines[i-1].strip()
                # Check if previous line is a horizontal rule and current line is meta desc
                if re.match(r'^[-*_]{3,}$', prev_line):
                    for pattern in compiled_patterns[1:]:  # Skip the first pattern to avoid duplicate
                        if pattern.match(stripped_line):
                            is_meta_desc = True
                            # Also remove the horizontal rule
                            if cleaned_lines and cleaned_lines[-1].strip() == prev_line:
                                cleaned_lines[-1] = ""
                            break
            
            if is_meta_desc:
                # Replace meta description line with empty line to maintain spacing
                cleaned_lines.append("")
                skip_next_empty = True
            elif stripped_line == "" and skip_next_empty:
                # Skip consecutive empty lines after meta description
                skip_next_empty = False
                continue
            else:
                cleaned_lines.append(line)
                skip_next_empty = False
        
        # Clean up excessive empty lines at the end
        while cleaned_lines and cleaned_lines[-1].strip() == "":
            cleaned_lines.pop()
        
        # Reconstruct the content
        cleaned_content = "\n".join(cleaned_lines)
        
        # Combine front matter and cleaned content
        if front_matter:
            return front_matter + "\n" + cleaned_content
        else:
            return cleaned_content

    def format_template(self, template, keyword, content):
        """Format template with dynamic content - Updated to use niche for categories"""
        # Get current date and time
        current_date = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        
        # Create improved title from keyword
        improved_title = self.generate_improved_title(keyword)
        
        # Create tags from the keyword (keep existing logic)
        keywords_list = keyword.split()
        tags = ', '.join([f'"{tag.strip()}"' for tag in keywords_list[:5]])
        
        # Use active_niche for categories instead of first keyword
        categories = f'"{self.active_niche}"'
        
        # Create keyword variants
        keyword_variant1 = f"best {keyword}" if len(keyword) > 0 else keyword
        keyword_variant2 = f"{keyword} guide" if len(keyword) > 0 else keyword
        
        # Generate AI-created description that includes the keyword
        description = self.generate_description(keyword)
        
        # Get random author
        author = self.get_random_author()
        # Generate author profile
        self.generate_author_profile(author)
        # Ensure personas are set
        if not self.audience_reference or not self.author_reference:
            self.load_and_select_preferences()
        
        # Detect schema type based on keyword and niche
        schema_type = self.detect_schema_type(keyword, self.active_niche)
        
        # Create replacements dictionary with schema-specific fields
        replacements = {
            "{title}": improved_title,
            "{date}": current_date,
            "{tags}": tags,
            "{categories}": categories,  # Now uses niche
            "{content}": content,
            "{keyword}": keyword,
            "{keyword_variant1}": keyword_variant1,
            "{keyword_variant2}": keyword_variant2,
            "{description}": description,
            "{authors}": author,
            "{author}": author,
            "{name_authors}": author.lower().replace(" ", "-"),
            "{audience_persona}": self.audience_reference,
            "{author_persona}": self.author_reference,
            "{website_name}": self.website_name,
            "{schema_type}": schema_type,
            "{niche}": self.active_niche,
            # Schema-specific replacements
            "{price}": self.generate_price_if_product(keyword, schema_type),
            "{rating}": self.generate_rating_if_applicable(schema_type),
            "{location}": self.get_location_if_local(schema_type),
            "{service_type}": self.get_service_type_if_applicable(keyword, schema_type),
            "{publish_date}": current_date,
            "{modified_date}": current_date
        }
        
        # Apply all replacements to the template
        formatted_article = template
        for placeholder, value in replacements.items():
            formatted_article = formatted_article.replace(placeholder, value)
        
        # Check if any placeholders remain
        remaining_placeholders = []
        for placeholder in replacements.keys():
            if placeholder in formatted_article:
                self.logger.warning(f"Placeholder {placeholder} not replaced in template")
                remaining_placeholders.append(placeholder)
        
        if remaining_placeholders:
            print(f"Warning: Beberapa placeholder tidak diganti: {', '.join(remaining_placeholders)}")
        
        return formatted_article
    
    def detect_schema_type(self, keyword, niche):
        """Detect appropriate schema type based on keyword and niche"""
        keyword_lower = keyword.lower()
        niche_lower = niche.lower()
        
        # Product-related keywords
        product_indicators = ['buy', 'price', 'review', 'best', 'top', 'compare', 'vs', 'product', 'tool', 'software', 'app']
        
        # News-related keywords  
        news_indicators = ['news', 'update', 'latest', 'breaking', 'announcement', 'report', 'trend']
        
        # Person-related keywords
        person_indicators = ['biography', 'profile', 'about', 'life', 'career', 'achievement', 'story']
        
        # Local business keywords
        local_indicators = ['near me', 'location', 'address', 'local', 'city', 'area', 'restaurant', 'shop', 'store']
        
        # Service keywords
        service_indicators = ['service', 'help', 'support', 'consultation', 'repair', 'maintenance', 'how to', 'guide']
        
        # Check keyword indicators
        if any(indicator in keyword_lower for indicator in product_indicators):
            return 'product'
        elif any(indicator in keyword_lower for indicator in news_indicators):
            return 'news'  
        elif any(indicator in keyword_lower for indicator in person_indicators):
            return 'person'
        elif any(indicator in keyword_lower for indicator in local_indicators):
            return 'local_business'
        elif any(indicator in keyword_lower for indicator in service_indicators):
            return 'service'
        
        # Check niche indicators
        if niche_lower in ['ecommerce', 'shopping', 'products', 'reviews']:
            return 'product'
        elif niche_lower in ['news', 'media', 'journalism']:
            return 'news'
        elif niche_lower in ['biography', 'people', 'celebrity']:
            return 'person'
        elif niche_lower in ['local', 'business', 'directory']:
            return 'local_business'
        elif niche_lower in ['services', 'consulting', 'support']:
            return 'service'
        
        # Default to article/blog posting
        return 'blog'
    
    def generate_price_if_product(self, keyword, schema_type):
        """Generate price for product schema"""
        if schema_type == 'product':
            # Generate realistic price based on keyword
            keyword_lower = keyword.lower()
            if 'software' in keyword_lower or 'app' in keyword_lower:
                return f"${random.randint(9, 99)}.99"
            elif 'course' in keyword_lower or 'training' in keyword_lower:
                return f"${random.randint(49, 299)}.00"
            else:
                return f"${random.randint(19, 199)}.99"
        return ""
    
    def generate_rating_if_applicable(self, schema_type):
        """Generate rating for applicable schemas"""
        if schema_type in ['product', 'local_business', 'service']:
            return f"{random.uniform(4.0, 5.0):.1f}"
        return ""
    
    def get_location_if_local(self, schema_type):
        """Get location for local business schema"""
        if schema_type == 'local_business':
            # Load from region file or use default
            try:
                region_file = os.path.join(self.get_language_path(), "kw", "region.txt")
                if os.path.exists(region_file):
                    with open(region_file, "r", encoding="utf-8") as f:
                        return f.read().strip()
            except:
                pass
            return "Local Area"
        return ""
    
    def get_service_type_if_applicable(self, keyword, schema_type):
        """Get service type for service schema"""
        if schema_type == 'service':
            keyword_lower = keyword.lower()
            if 'repair' in keyword_lower:
                return "Repair Service"
            elif 'consulting' in keyword_lower:
                return "Consulting Service"  
            elif 'maintenance' in keyword_lower:
                return "Maintenance Service"
            else:
                return "Professional Service"
        return ""
    
    def load_template_by_schema(self, schema_type='blog'):
        """Load template based on schema type"""
        lang_path = self.get_language_path()
        default_lang_path = os.path.join(self.base_path, "languages", "default")
        
        # Try to load schema-specific template first
        schema_template_file = os.path.join(lang_path, "templates_md", schema_type, "template.md")
        schema_default_file = os.path.join(lang_path, "templates_md", schema_type, "template.default.md")
        default_schema_template_file = os.path.join(default_lang_path, "templates_md", schema_type, "template.md")
        default_schema_default_file = os.path.join(default_lang_path, "templates_md", schema_type, "template.default.md")
        
        # Try schema-specific template in current language
        if os.path.exists(schema_template_file):
            try:
                with open(schema_template_file, "r", encoding="utf-8") as f:
                    template_content = f.read()
                    if template_content.strip():
                        self.logger.info(f"Loaded {schema_type} template from {schema_template_file}")
                        return template_content
            except Exception as e:
                self.logger.error(f"Error reading {schema_type} template: {str(e)}")
        
        # Try schema-specific default in current language
        if os.path.exists(schema_default_file):
            try:
                with open(schema_default_file, "r", encoding="utf-8") as f:
                    template_content = f.read()
                    if template_content.strip():
                        self.logger.info(f"Loaded {schema_type} default template from {schema_default_file}")
                        return template_content
            except Exception as e:
                self.logger.error(f"Error reading {schema_type} default template: {str(e)}")
        
        # Try schema-specific template in default language
        if os.path.exists(default_schema_template_file):
            try:
                with open(default_schema_template_file, "r", encoding="utf-8") as f:
                    template_content = f.read()
                    if template_content.strip():
                        self.logger.warning(f"Loaded {schema_type} template from default language: {default_schema_template_file}")
                        return template_content
            except Exception as e:
                self.logger.error(f"Error reading default language {schema_type} template: {str(e)}")
        
        # Try schema-specific default in default language
        if os.path.exists(default_schema_default_file):
            try:
                with open(default_schema_default_file, "r", encoding="utf-8") as f:
                    template_content = f.read()
                    if template_content.strip():
                        self.logger.warning(f"Loaded {schema_type} default template from default language: {default_schema_default_file}")
                        return template_content
            except Exception as e:
                self.logger.error(f"Error reading default language {schema_type} default template: {str(e)}")
        
        # Fallback to blog template if schema template not found
        if schema_type != "blog":
            self.logger.warning(f"Template for {schema_type} not found, falling back to blog template")
            return self.load_template_by_schema("blog")
        
        # If blog template also not found, return empty
        self.logger.error(f"No template available for schema type: {schema_type}")
        return ""

    def replace_placeholders(self, text, additional_replacements=None):
        """Replace all common placeholders in the text"""
        if not text:
            return text
        
        # Default replacements
        replacements = {
            "{author_persona}": self.author_reference,
            "{audience_persona}": self.audience_reference,
            "{website_name}": self.website_name
        }
        
        # Add additional replacements if provided
        if additional_replacements:
            replacements.update(additional_replacements)
        
        # Apply all replacements to the text
        for placeholder, value in replacements.items():
            text = text.replace(placeholder, value)
        
        return text
    
    def generate_description(self, keyword):
        """Generate an SEO-friendly description that includes the keyword"""
        try:
            if not self.ensure_client_initialized():
                raise ValueError("Failed to initialize client")
        
            if not hasattr(self, 'sdk_type') or self.sdk_type is None:
                raise ValueError("SDK type not set. Please authenticate first.")
                
            if not hasattr(self, 'client') or self.client is None:
                raise ValueError("Client not initialized. Please authenticate first.")
            
            # Get current token and update client
            token = self.get_current_token()
            if not token:
                raise ValueError("No valid token available")
                
            # Client based on SDK type
            if self.sdk_type == "openai":
                from openai import OpenAI
                self.client = OpenAI(
                    base_url=self.endpoint,
                    api_key=token,
                )
            else:  # azure
                from azure.ai.inference import ChatCompletionsClient
                from azure.core.credentials import AzureKeyCredential
                self.client = ChatCompletionsClient(
                    endpoint=self.endpoint,
                    credential=AzureKeyCredential(token),
                )
    
            # Load prompt template with proper error handling
            lang_path = self.get_language_path()
            prompt_paths = [
                os.path.join(lang_path, "prompt", "blog", "description_prompt.txt"),
                os.path.join(lang_path, "prompt", "blog", "description_prompt.default.txt"),
                os.path.join(self.base_path, "languages", "default", "prompt", "blog", "description_prompt.txt"),
                os.path.join(self.base_path, "languages", "default", "prompt", "blog", "description_prompt.default.txt")
            ]
            
            prompt_template = None
            for path in prompt_paths:
                if os.path.exists(path):
                    try:
                        with open(path, "r", encoding="utf-8") as f:
                            content = f.read().strip()
                            if content:
                                prompt_template = content
                                self.logger.info(f"Loaded description prompt from: {path}")
                                break
                    except Exception as e:
                        self.logger.error(f"Error reading {path}: {str(e)}")
                        continue
                        
            if not prompt_template:
                raise FileNotFoundError("No valid description prompt found")
    
            # Load system prompt with proper error handling
            system_prompt = self.load_system_prompt("description_writer")
            if not system_prompt:
                raise ValueError("No valid system prompt for description writer")
    
            try:
                # Format description prompt with error handling
                description_prompt = prompt_template.format(
                    keyword=keyword,
                    language=self.language
                )
            except KeyError as e:
                self.logger.error(f"Error formatting prompt template: {str(e)}")
                description_prompt = f"Create a short description for the article about '{keyword}' in {self.language}"
    
            # Make API call with proper error handling
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": description_prompt}
            ]
            
            description = self.retry_with_token_rotation(
                self.safe_api_call, 
                messages, 
                temperature=0.6, 
                max_tokens=200
            )
            
            if not description:
                raise ValueError("Failed to generate description after retries")
            
            description = description.strip()
            
            # Ensure description contains keyword
            if keyword.lower() not in description.lower():
                description = f"{description} Learn more about {keyword}."
                
            # Truncate if too long
            if len(description) > 160:
                description = description[:157] + "..."
    
            self.logger.info(f"Generated SEO description: {description}")
            return description
    
        except Exception as e:
            self.logger.error(f"Error generating description: {str(e)}")
            # Return a basic description as fallback
            return f"Learn everything you need to know about {keyword}. Comprehensive guide with expert insights and practical information."
    
    def generate_improved_title(self, keyword):
        """Generate an improved title that includes the keyword in the selected language, without years."""
        try:
            if not self.ensure_client_initialized():
                raise ValueError("Failed to initialize client")
            
            if not hasattr(self, 'sdk_type') or self.sdk_type is None:
                raise ValueError("SDK type not set. Please authenticate first.")
                
            if not hasattr(self, 'client') or self.client is None:
                raise ValueError("Client not initialized. Please authenticate first.")
            
            # Get current token
            token = self.get_current_token()
            
            # Update client based on SDK type
            if self.sdk_type == "openai":
                from openai import OpenAI
                self.client = OpenAI(
                    base_url=self.endpoint,
                    api_key=token,
                )
            else:  # azure
                from azure.ai.inference import ChatCompletionsClient
                from azure.core.credentials import AzureKeyCredential
                self.client = ChatCompletionsClient(
                    endpoint=self.endpoint,
                    credential=AzureKeyCredential(token),
                )
            
            # Load title prompt template
            title_prompt_template = self.load_system_prompt("title_generator")
            
            # Add explicit instruction to avoid years
            title_prompt = (
                f"Create a compelling title in {self.language} for content about '{keyword}'.\n"
                "IMPORTANT RULES:\n"
                "1. ONLY return the title itself, do NOT add any explanation or extra text\n"
                "2. DO NOT include any years or dates (like 2023, 2024, etc)\n"
                "3. Must include the keyword naturally\n"
                "4. Keep it clear and engaging\n"
                "5. Maximum 60 characters"
            )
            
            # Load system message template
            system_message_template = self.load_system_prompt("title_system")
            
            # Fill in system message template
            system_message = system_message_template.replace("{language}", self.language)
            
            # Send request to AI model
            messages = [
                {
                    "role": "system", 
                    "content": system_message
                },
                {
                    "role": "user",
                    "content": title_prompt
                }
            ]
            
            title = self.retry_with_token_rotation(
                self.safe_api_call,
                messages,
                temperature=0.6,
                max_tokens=100
            )
            
            if not title:
                title = f"{keyword.capitalize()}"
                self.logger.warning(f"Failed to generate title, using fallback: {title}")
                return title
                
            title = title.strip()
            title = title.strip('"\'')
            
            # Filter: Remove any years (1900-2099)
            title = re.sub(r'\b(19|20)\d{2}\b', '', title)
            
            # Remove multiple spaces after year removal
            title = re.sub(r'\s+', ' ', title).strip()
            
            # Validation checks
            if not title or len(title) < 10:
                title = f"{keyword.capitalize()}"
                self.logger.warning(f"Generated title too short. Using fallback: {title}")
                return title
                
            if keyword.lower() not in title.lower():
                title = f"{keyword.capitalize()}"
                self.logger.warning(f"Generated title missing keyword. Using fallback: {title}")
                return title
                
            if len(title) > 60:
                title = title[:57] + "..."
                
            self.logger.info(f"Generated title in {self.language}: {title}")
            return title
            
        except Exception as e:
            self.logger.error(f"Error generating improved title: {str(e)}")
            return f"{keyword.capitalize()}"  # Fallback

    def validate_and_improve_article(self, article_content, keyword):
        """Validates and improves the article content based on specific criteria"""
        self.logger.info(f"Validating and improving article for keyword: {keyword}")
        print(f"\nValidating and improving article for keyword: {keyword}")
        
        try:
            # Extract front matter and main content
            front_matter, main_content = self.extract_front_matter_and_content(article_content)
            
            # If extraction failed, return original content
            if not front_matter or not main_content:
                self.logger.warning("Failed to extract front matter and content. Skipping validation.")
                return article_content
            
            # First, perform persona consistency validation and fixing
            if not self.validate_persona_consistency(main_content):
                self.logger.info("Article failed persona consistency check. Attempting to fix...")
                main_content = self.fix_persona_consistency(main_content)
                if not self.validate_persona_consistency(main_content):
                    self.logger.warning("Article still fails persona consistency check after fixing.")
                    # Continue with other validations anyway
            
            # Extract title from front matter
            title_match = re.search(r'title: "([^"]+)"', front_matter)
            title = title_match.group(1) if title_match else keyword.capitalize()
            
            # Ensure the first paragraph starts with the title
            if not main_content.startswith(f"*{title}*"):
                main_content = f"*{title}* - {main_content}"
            
            # Perform preliminary analysis of the content
            validation_results = self.analyze_article_content(main_content)
            
            # Load validation prompt template dynamically based on active language
            validation_prompt_template = self.load_system_prompt("validation_prompt")
            
            # Prepare excerpt and truncation notice
            article_excerpt = main_content[:3500]
            article_truncation_notice = '' if len(main_content) <= 3500 else '(rest of article omitted for brevity)'
            
            # Prepare length recommendation
            length_recommendation = '' if len(main_content.split()) >= 1100 else '- ADD CONTENT to reach 1100-1500 words. Add new sections or expand existing ones.'
            
            # Convert float values to strings before replacing
            readability_score = str(validation_results.get('readability_score', 'N/A'))
            sentence_variation = str(validation_results.get('sentence_variation', 'N/A'))
            
            # Fill in validation prompt template
            validation_prompt = validation_prompt_template.replace("{keyword}", keyword)
            validation_prompt = validation_prompt.replace("{article_excerpt}", article_excerpt)
            validation_prompt = validation_prompt.replace("{article_truncation_notice}", article_truncation_notice)
            validation_prompt = validation_prompt.replace("{word_count}", str(len(main_content.split())))
            validation_prompt = validation_prompt.replace("{length_recommendation}", length_recommendation)
            validation_prompt = validation_prompt.replace("{readability_score}", readability_score)
            validation_prompt = validation_prompt.replace("{sentence_variation}", sentence_variation)
            validation_prompt = validation_prompt.replace("{language}", self.language)
            
            # Add persona consistency instructions to validation prompt
            validation_prompt += f"""
            
    8. PERSONA CONSISTENCY CHECK:
       - ALWAYS use "{self.audience_reference}" to refer to readers (at least 3 times)
       - ALWAYS use "{self.author_reference}" to refer to the writer (at least 2 times)
       - DO NOT use any other reader or writer pronouns (you, your, we, our, I, etc.)
            """
            
            # Get current token
            token = self.get_current_token()
            
            # Update client based on SDK type
            if self.sdk_type == "openai":
                from openai import OpenAI
                self.client = OpenAI(
                    base_url=self.endpoint,
                    api_key=token,
                )
            else:  # azure
                from azure.ai.inference import ChatCompletionsClient
                from azure.core.credentials import AzureKeyCredential
                self.client = ChatCompletionsClient(
                    endpoint=self.endpoint,
                    credential=AzureKeyCredential(token),
                )
            
            # Load system message template dynamically based on active language
            system_message_template = self.load_system_prompt("validation_system")
            
            # Fill in system message template with persona instructions
            system_message = system_message_template.replace("{language}", self.language)
            system_message += f"""
    
    CRITICAL PERSONA REQUIREMENT:
    - ALWAYS use "{self.audience_reference}" (at least 3 times) to refer to readers. Never use "you", "your", etc.
    - ALWAYS use "{self.author_reference}" (at least 2 times) to refer to the writer. Never use "I", "we", "our", etc.
            """
            
            # Send request to AI model
            messages = [
                {
                    "role": "system", 
                    "content": system_message
                },
                {
                    "role": "user",
                    "content": validation_prompt
                }
            ]
            
            improved_content = self.retry_with_token_rotation(
                self.safe_api_call,
                messages,
                temperature=0.4,
                max_tokens=4000
            )
            
            if not improved_content:
                self.logger.warning("Failed to improve article content, keeping original")
                return article_content
                
            improved_content = improved_content.strip()
            
            # Clean up any remaining code block markers
            improved_content = self.clean_markdown_artifacts(improved_content)
            
            # Apply additional randomization and humanization techniques
            improved_content = self.apply_humanization_techniques(improved_content)
            
            # Final persona consistency check and fixing
            improved_content = self.fix_persona_consistency(improved_content)
            
            # Validate final content for persona consistency
            if not self.validate_persona_consistency(improved_content):
                self.logger.warning("Final content still has persona consistency issues. Making one more attempt...")
                improved_content = self.fix_persona_consistency(improved_content)
            
            # Check if the improved content looks like a full article
            if len(improved_content.split()) < 300:
                self.logger.warning("Improved content too short. Keeping original content.")
                return article_content
            
            # Reconstruct the article with original front matter and improved content
            validated_article = front_matter + "\n\n" + improved_content
            
            # Check word count of improved version
            improved_word_count = len(improved_content.split())
            self.logger.info(f"Article improved: {len(main_content.split())} words → {improved_word_count} words")
            print(f"Article improved: {len(main_content.split())} words → {improved_word_count} words")
            
            # Log validation results
            self.log_validation_results(improved_content)
            
            return validated_article
        
        except Exception as e:
            self.logger.error(f"Error validating article: {str(e)}")
            print(f"Error validating article: {str(e)}")
            return article_content  # Return original content if validation fails
    
    def validate_cultural_elements(self, content):
        """Validate if cultural elements are included in the content"""
        cultural_elements = self.load_cultural_references()
        missing_elements = []
        
        for category, items in cultural_elements.items():
            if not any(item.lower() in content.lower() for item in items):
                missing_elements.append(category)
        
        if missing_elements:
            self.logger.warning(f"Missing cultural elements: {', '.join(missing_elements)}")
            print(f"Missing cultural elements: {', '.join(missing_elements)}")
        else:
            self.logger.info("All cultural elements are included.")
            print("All cultural elements are included.")
    
    def analyze_keyword_complexity(self, keyword):
        """Analyze keyword complexity to adapt generation and validation strategies"""
        try:
            # Split into tokens
            tokens = keyword.lower().split()
            num_tokens = len(tokens)
            
            # Calculate complexity score
            complexity = 0
            
            # Base complexity from token count
            if num_tokens == 1:
                complexity += 1
            elif num_tokens == 2:
                complexity += 2
            elif num_tokens == 3:
                complexity += 3
            else:
                complexity += 4
                
            # Add complexity for longer words
            for token in tokens:
                if len(token) > 8:
                    complexity += 0.5
                    
            # Add complexity for uncommon terms
            uncommon_words = ['historical', 'figures', 'analysis', 'comprehensive', 'strategies', 
                              'methodology', 'framework', 'paradigm', 'implementation']
            for token in tokens:
                if token in uncommon_words:
                    complexity += 0.5
                    
            return complexity
            
        except Exception as e:
            self.logger.error(f"Error analyzing keyword complexity: {str(e)}")
            return 2  # Default moderate complexity
            
    def generate_keyword_variants(self, keyword):
        """Generate natural variations of keywords for more flexible content creation"""
        try:
            tokens = keyword.lower().split()
            num_tokens = len(tokens)
            variants = []
            
            if num_tokens == 1:
                # For single word, not much variation needed
                return [keyword, f"the {keyword}", f"this {keyword}"]
                
            elif num_tokens == 2:
                # For two words, create simple variations
                word1, word2 = tokens
                variants = [
                    f"{word2} {word1}",  # Reversed order if appropriate
                    f"the {keyword}",
                    f"{word1} of {word2}",  # Prepositional phrase
                    f"{word1} and {word2}"  # Conjunction
                ]
                
            else:
                # For complex multi-word keywords
                # Extract key nouns/topics from the phrase
                main_tokens = [t for t in tokens if len(t) > 3 and t not in ['and', 'the', 'for', 'with', 'about']]
                
                # Create variations using the main tokens
                if len(main_tokens) >= 2:
                    variants.append(f"{main_tokens[0]} and {main_tokens[-1]}")
                    variants.append(f"{main_tokens[-1]} related to {main_tokens[0]}")
                    
                # Create a possessive form
                if len(tokens) > 2:
                    variants.append(f"{tokens[0]}'s {' '.join(tokens[1:])}")
                    
                # Add a few key tokens together
                if len(main_tokens) >= 3:
                    variants.append(f"{main_tokens[0]} {main_tokens[-1]}")
                    variants.append(f"{main_tokens[1]} {main_tokens[-1]}")
            
            # Add original keyword and truncated version
            variants.append(keyword)
            if num_tokens > 2:
                variants.append(' '.join(tokens[:2]))
                variants.append(' '.join(tokens[-2:]))
                
            # Deduplicate and return
            return list(dict.fromkeys(variants))
            
        except Exception as e:
            self.logger.error(f"Error generating keyword variants: {str(e)}")
            return [keyword]  # Return original as fallback
            
    def enhance_keyword_usage(self, content, keyword, variants):
        """Enhance article with better keyword placement for complex keywords"""
        try:
            if not content or not keyword:
                return content
                
            paragraphs = content.split('\n\n')
            if len(paragraphs) < 3:
                return content
                
            # Check if first paragraph needs enhancement
            if keyword.lower() not in paragraphs[0].lower():
                first_modified = False
                # Try to insert a variant naturally
                for variant in variants:
                    if len(variant.split()) <= 2 and variant.lower() not in paragraphs[0].lower():
                        # Find a good position to insert the keyword
                        sentences = paragraphs[0].split('. ')
                        if len(sentences) > 1:
                            # Insert into second sentence if possible
                            sentences[1] = self._insert_keyword_into_sentence(sentences[1], variant)
                            paragraphs[0] = '. '.join(sentences)
                            first_modified = True
                            break
                
                # If no variant worked, try to prepend a new sentence with the keyword
                if not first_modified:
                    intro_sentence = f"{keyword.capitalize()} is a fascinating topic. "
                    paragraphs[0] = intro_sentence + paragraphs[0]
            
            # Check if last paragraph needs enhancement
            if keyword.lower() not in paragraphs[-1].lower():
                # Try to append a conclusion sentence with keyword
                conclusion_sentence = f" In conclusion, {keyword} remains an important subject for further exploration."
                paragraphs[-1] = paragraphs[-1] + conclusion_sentence
                
            # Enhance one middle paragraph for good measure
            if len(paragraphs) > 3:
                middle_idx = len(paragraphs) // 2
                if keyword.lower() not in paragraphs[middle_idx].lower():
                    # Try to insert a variant naturally
                    for variant in variants:
                        if variant.lower() not in paragraphs[middle_idx].lower():
                            sentences = paragraphs[middle_idx].split('. ')
                            if len(sentences) > 0:
                                sentences[0] = self._insert_keyword_into_sentence(sentences[0], variant)
                                paragraphs[middle_idx] = '. '.join(sentences)
                                break
            
            return '\n\n'.join(paragraphs)
            
        except Exception as e:
            self.logger.error(f"Error enhancing keyword usage: {str(e)}")
            return content  # Return original on error
            
    def _insert_keyword_into_sentence(self, sentence, keyword):
        """Helper to insert a keyword naturally into a sentence"""
        try:
            words = sentence.split()
            if len(words) < 3:
                return f"{keyword.capitalize()} - {sentence}"
                
            # Try to insert after a transition point
            transitions = ["and", "but", "however", "also", "therefore", "thus", "moreover"]
            for i, word in enumerate(words[:-1]):
                if word.lower() in transitions:
                    return ' '.join(words[:i+1]) + f" {keyword} " + ' '.join(words[i+1:])
                    
            # If no good transition, insert in a natural position
            position = min(len(words) // 3, 3)  # Insert near beginning but not at the very start
            return ' '.join(words[:position]) + f" {keyword} " + ' '.join(words[position:])
            
        except Exception as e:
            self.logger.error(f"Error inserting keyword: {str(e)}")
            return f"{sentence} ({keyword})"  # Simple fallback
    
    def get_default_cultural_context_template(self):
        """Return a default cultural context template when file is not found"""
        return """
        Write in {language} considering these cultural elements:
        Events: {events}
        Locations: {locations}
        Cuisines: {cuisines}
        Notable Figures: {notable_figures}
        Using these transitions: {transitions}
        Common phrases: {common_phrases}
        Closing phrases: {closing}
        Content preferences: {content_preferences}
        Reading habits: {reading_habits}
        Trust signals: {trust_signals}
        """
    
    def get_default_article_generator_template(self):
        """Return a default article generator system prompt when file is not found"""
        return """
        You are an expert content writer creating an article in {language}.
        
        You're writing with these characteristics:
        - Writing Model: {writing_model_name}
        - Tone: {writing_tone_name}
        - Style: {copywriting_style_name}
        
        Create a well-structured article about "{keyword}" that includes:
        - An engaging introduction
        - Several informative sections with proper headings
        - A clear conclusion
        
        Use Markdown formatting for structure. Include appropriate headings (H2, H3).
        Do not use an H1 heading as it will be generated separately.
        """
        
    def analyze_article_content(self, content):
        """
        Analyze the article content for various metrics:
        - Readability score
        - Sentence length variation
        - Emotional tone
        - AI detection risk factors
        
        Args:
            content: The article content to analyze
            
        Returns:
            Dictionary with analysis results
        """
        results = {}
        
        try:
            # Calculate readability score
            results['readability_score'] = round(textstat.flesch_reading_ease(content), 1)
            
            # Analyze sentence lengths
            tokenizer = PunktSentenceTokenizer()
            sentences = tokenizer.tokenize(content)
            sentence_lengths = [len(s.split()) for s in sentences]
            
            if sentence_lengths:
                avg_length = sum(sentence_lengths) / len(sentence_lengths)
                variation = sum(abs(l - avg_length) for l in sentence_lengths) / len(sentence_lengths)
                results['sentence_variation'] = round(variation, 2)
                results['avg_sentence_length'] = round(avg_length, 2)
                
                # Check for sentence beginning variation
                sentence_starters = []
                for s in sentences:
                    words = s.strip().split()
                    if words:
                        starter = words[0].lower()
                        sentence_starters.append(starter)
                
                starter_counter = Counter(sentence_starters)
                most_common = starter_counter.most_common(1)
                if most_common:
                    results['most_common_starter'] = most_common[0][0]
                    results['starter_repetition'] = most_common[0][1]
            
            # Check for common AI phrases
            ai_phrases = [
                "it is important to note",
                "in conclusion",
                "it's worth mentioning",
                "as we can see",
                "as mentioned earlier",
                "it is interesting to note",
                "in this article",
                "to summarize",
            ]
            
            phrase_count = 0
            for phrase in ai_phrases:
                phrase_count += content.lower().count(phrase)
            
            results['ai_phrase_count'] = phrase_count
            
            # Check for human-like emotional expressions
            human_expressions = [
                "!",  # Exclamation marks
                "?",  # Question marks
                "...",  # Ellipses
                "believe",
                "feel",
                "think",
                "opinion",
                "actually",
                "honestly",
                "surprisingly",
                "frankly",
            ]
            
            expression_count = 0
            for expr in human_expressions:
                expression_count += content.lower().count(expr)
            
            results['human_expression_count'] = expression_count
            
        except Exception as e:
            self.logger.error(f"Error during article analysis: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    def validate_article_content(self, content, keyword):
        """Validate generated article content with intelligent criteria that adapts to keyword complexity.
        If validation fails, print detailed info about which criteria are not met.
        """
        try:
            if not content:
                self.logger.error("Empty content received")
                print("Validation failed: Content is empty.")
                return False

            # Get word and character counts
            words = content.split()
            word_count = len(words)
            char_count = len(content)

            # Split keyword into tokens for more flexible matching
            keyword_tokens = keyword.lower().split()
            num_tokens = len(keyword_tokens)

            # Perform exact and partial keyword matching
            exact_keyword_count = content.lower().count(keyword.lower())

            # For multi-word keywords, also check for partial matches
            partial_matches = 0
            if num_tokens > 1:
                # Consider individual words or pairs from the keyword
                for token in keyword_tokens:
                    if len(token) > 3:  # Only count meaningful words, not articles or prepositions
                        partial_matches += content.lower().count(token)

                # Get adjacent word pairs for more precise partial matching
                if num_tokens > 2:
                    for i in range(num_tokens - 1):
                        word_pair = f"{keyword_tokens[i]} {keyword_tokens[i+1]}"
                        if len(word_pair) > 7:  # Only count meaningful pairs
                            partial_matches += content.lower().count(word_pair)

            # Calculate effective keyword count (weighted combination)
            effective_keyword_count = exact_keyword_count
            if num_tokens > 1:
                effective_keyword_count += partial_matches * 0.5  # Count partial matches at half value

            # Log detailed stats
            self.logger.info(f"Content validation stats:")
            self.logger.info(f"- Word count: {word_count}")
            self.logger.info(f"- Character count: {char_count}")
            self.logger.info(f"- Keyword count: {exact_keyword_count}")
            if num_tokens > 1:
                self.logger.info(f"- Partial keyword matches: {partial_matches}")
                self.logger.info(f"- Effective keyword count: {effective_keyword_count}")

            # Define adaptive thresholds based on keyword complexity
            MIN_WORDS = 600
            MAX_WORDS = 2500

            # Adjust minimum keyword requirements based on complexity
            if num_tokens == 1:  # Single word keywords
                MIN_KEYWORD_COUNT = 5
                MIN_EFFECTIVE_COUNT = 5
            elif num_tokens == 2:  # Two-word keywords
                MIN_KEYWORD_COUNT = 3
                MIN_EFFECTIVE_COUNT = 5
            elif num_tokens == 3:  # Three-word keywords
                MIN_KEYWORD_COUNT = 2
                MIN_EFFECTIVE_COUNT = 4
            else:  # Four or more words
                MIN_KEYWORD_COUNT = 2
                MIN_EFFECTIVE_COUNT = 3

            MAX_KEYWORD_COUNT = 15

            # Validation checks
            issues = []

            if word_count < MIN_WORDS:
                issues.append(f"Word count too low: {word_count}/{MIN_WORDS}")

            if word_count > MAX_WORDS:
                issues.append(f"Word count too high: {word_count}/{MAX_WORDS}")

            # Apply appropriate validation based on keyword complexity
            if num_tokens == 1:  # For single-word keywords, be more strict
                if exact_keyword_count < MIN_KEYWORD_COUNT:
                    issues.append(f"Keyword count too low: {exact_keyword_count}/{MIN_KEYWORD_COUNT}")
            else:  # For multi-word keywords, be more flexible
                if exact_keyword_count < MIN_KEYWORD_COUNT and effective_keyword_count < MIN_EFFECTIVE_COUNT:
                    issues.append(f"Effective keyword usage too low: {effective_keyword_count}/{MIN_EFFECTIVE_COUNT}")

            if exact_keyword_count > MAX_KEYWORD_COUNT:
                issues.append(f"Keyword count too high: {exact_keyword_count}/{MAX_KEYWORD_COUNT}")

            # Check for article structure
            paragraphs = [p for p in content.split('\n\n') if p.strip()]
            if len(paragraphs) < 3:
                issues.append("Too few paragraphs (minimum 3 required)")

            # First paragraph keyword check - more flexible for multi-word keywords
            first_paragraph = paragraphs[0].lower() if paragraphs else ""
            keyword_in_first = keyword.lower() in first_paragraph

            # For multi-word keywords, check if at least 70% of the tokens are present
            tokens_in_first = sum(1 for token in keyword_tokens if token in first_paragraph and len(token) > 3)
            tokens_ratio = tokens_in_first / max(1, sum(1 for token in keyword_tokens if len(token) > 3))

            if not keyword_in_first and (num_tokens == 1 or tokens_ratio < 0.7):
                issues.append("Keyword or majority of keyword terms missing from first paragraph")

            # Last paragraph keyword check - similar flexibility
            last_paragraph = paragraphs[-1].lower() if paragraphs else ""
            keyword_in_last = keyword.lower() in last_paragraph

            tokens_in_last = sum(1 for token in keyword_tokens if token in last_paragraph and len(token) > 3)
            last_tokens_ratio = tokens_in_last / max(1, sum(1 for token in keyword_tokens if len(token) > 3))

            if not keyword_in_last and (num_tokens == 1 or last_tokens_ratio < 0.7):
                issues.append("Keyword or majority of keyword terms missing from conclusion")

            # Check headings - require at least one
            headings = [line.strip() for line in content.split('\n') if line.strip().startswith('#')]
            if not headings:
                issues.append("No headings found (minimum 1 required)")

            # Determine severity of issues for weighted decision
            critical_issues = [issue for issue in issues if "count too low" in issue or "count too high" in issue]
            minor_issues = [issue for issue in issues if issue not in critical_issues]

            # Fail only on critical issues or 3+ minor issues
            if critical_issues or len(minor_issues) >= 3:
                for issue in issues:
                    self.logger.warning(f"Content validation issue: {issue}")
                # Print all validation issues to the user
                print("\nValidation failed for this article. Issues found:")
                for issue in issues:
                    print(f"- {issue}")
                return False

            # Log minor issues but pass validation
            for issue in minor_issues:
                self.logger.info(f"Content validation minor issue: {issue}")

            self.logger.info("Content validation passed all critical checks")
            return True

        except Exception as e:
            self.logger.error(f"Error validating content: {str(e)}")
            # If there's an error in validation, let it pass rather than block
            self.logger.warning("Validation error - allowing content to pass")
            print(f"Validation error: {str(e)} (allowing content to pass)")
            return True
            
    def apply_humanization_techniques(self, content):
        """
        Apply various humanization techniques to make the content more natural
        and less detectable by AI detection systems.
        
        Args:
            content: The article content to humanize
            
        Returns:
            Humanized content
        """
        try:
            # Only apply these changes if random conditions are met to avoid over-processing
            
            # 1. Add occasional unicode variations for common characters
            if random.random() < 0.7:
                # Replace some periods with alternative unicode periods (very subtle difference)
                if random.random() < 0.3:
                    content = content.replace('. ', '．', random.randint(1, 3))
                
                # Replace some quotation marks with alternative unicode versions
                if random.random() < 0.3:
                    content = content.replace('"', '"', random.randint(1, 2))
                    content = content.replace('"', '"', random.randint(1, 2))
            
            # 2. Add zero-width spaces in a few random places (invisible but affects string matching)
            if random.random() < 0.5:
                zero_width_space = '\u200B'
                for _ in range(random.randint(2, 5)):
                    position = random.randint(0, len(content) - 1)
                    content = content[:position] + zero_width_space + content[position:]
            
            # 3. Introduce subtle formatting inconsistencies
            if random.random() < 0.6:
                # Sometimes use double spaces after periods
                periods = re.finditer(r'\.(?=\s)', content)
                period_positions = [m.start() for m in periods]
                
                if period_positions:
                    # Choose random positions to add double spaces
                    for _ in range(min(3, len(period_positions))):
                        if period_positions:
                            position = random.choice(period_positions)
                            period_positions.remove(position)
                            content = content[:position+1] + ' ' + content[position+1:]
            
            # 4. Add rare/unusual but valid markdown formatting elements
            if random.random() < 0.4:
                format_options = [
                    (r'\*\*(.*?)\*\*', r'__\1__'),  # Change some bold formatting style
                    (r'\*(.*?)\*', r'_\1_'),        # Change some italic formatting style
                ]
                
                option = random.choice(format_options)
                pattern, replacement = option
                
                # Find matches of the pattern
                matches = list(re.finditer(pattern, content))
                if matches:
                    # Choose a random subset of matches to replace
                    for _ in range(min(2, len(matches))):
                        if matches:
                            match = random.choice(matches)
                            matches.remove(match)
                            start, end = match.span()
                            matched_text = match.group(1)
                            content = content[:start] + replacement.replace(r'\1', matched_text) + content[end:]
            
            # 5. If there's a table, make slight formatting inconsistencies
            if '|' in content and '-|-' in content and random.random() < 0.8:
                table_rows = re.findall(r'\|.*?\|', content, re.MULTILINE)
                if table_rows:
                    # Choose one random row to modify spacing
                    random_row_index = random.randint(0, len(table_rows) - 1)
                    original_row = table_rows[random_row_index]
                    
                    # Add or remove spaces around |
                    modified_row = original_row.replace(' | ', '| ')
                    content = content.replace(original_row, modified_row, 1)
            
            return content
            
        except Exception as e:
            self.logger.error(f"Error applying humanization techniques: {str(e)}")
            return content  # Return original content if humanization fails
    
    def log_validation_results(self, content):
        """
        Log the validation results of the improved content
        
        Args:
            content: The improved article content
        """
        try:
            # Get analysis results
            results = self.analyze_article_content(content)
            
            self.logger.info("Article validation results:")
            self.logger.info(f"- Readability score: {results.get('readability_score', 'N/A')}")
            self.logger.info(f"- Sentence variation: {results.get('sentence_variation', 'N/A')}")
            self.logger.info(f"- Average sentence length: {results.get('avg_sentence_length', 'N/A')}")
            self.logger.info(f"- Human expression count: {results.get('human_expression_count', 'N/A')}")
            self.logger.info(f"- AI phrase count: {results.get('ai_phrase_count', 'N/A')}")
            
            print("\nArticle validation results:")
            print(f"- Readability score: {results.get('readability_score', 'N/A')}")
            print(f"- Sentence variation: {results.get('sentence_variation', 'N/A')}")
            print(f"- Human expression count: {results.get('human_expression_count', 'N/A')}")
            
        except Exception as e:
            self.logger.error(f"Error logging validation results: {str(e)}")
    
    def clean_markdown_artifacts(self, content):
        """
        Removes unwanted markdown artifacts that might be added by the AI
        
        Args:
            content: The content to clean
            
        Returns:
            Cleaned content
        """
        # Remove code block markers
        content = re.sub(r'^```markdown\s*', '', content)
        content = re.sub(r'^```\s*', '', content) 
        content = re.sub(r'\s*```\s*$', '', content)
        
        # Remove any other language specifiers that might appear
        content = re.sub(r'^```[a-zA-Z]*\s*', '', content)
        
        # Remove code block markers that might appear in the middle of the text
        lines = content.split('\n')
        cleaned_lines = []
        skip_next_end_marker = False
        
        for line in lines:
            if skip_next_end_marker and line.strip() == '```':
                skip_next_end_marker = False
                continue
                
            if line.strip().startswith('```'):
                skip_next_end_marker = True
                continue
                
            cleaned_lines.append(line)
        
        return '\n'.join(cleaned_lines)
    
    def extract_front_matter_and_content(self, article_content):
        """
        Extracts the front matter and main content from an article
        
        Args:
            article_content: The full article content
            
        Returns:
            Tuple of (front_matter, main_content)
        """
        try:
            # Split by front matter delimiters
            parts = article_content.split('---', 2)
            
            if len(parts) >= 3:
                front_matter = f"---{parts[1]}---"
                main_content = parts[2].strip()
                return front_matter, main_content
            else:
                self.logger.warning("Could not properly split front matter and content")
                return None, None
        except Exception as e:
            self.logger.error(f"Error extracting front matter: {str(e)}")
            return None, None
        
    def get_random_author(self):
        """Get a random author from authors-name.txt, fallback to authors-name.default.txt if necessary"""
        lang_path = self.get_language_path()
        authors_file = os.path.join(lang_path, "author", "authors-name.txt")
        authors_default_file = os.path.join(lang_path, "author", "authors-name.default.txt")
        default_lang_path = os.path.join(self.base_path, "languages", "default")
        default_authors_file = os.path.join(default_lang_path, "author", "authors-name.default.txt")
    
        for path in [authors_file, authors_default_file]:
            try:
                if os.path.exists(path):
                    with open(path, "r", encoding="utf-8") as f:
                        authors = [line.strip() for line in f if line.strip()]
                    if authors:
                        return random.choice(authors)
            except Exception as e:
                self.logger.error(f"Error reading authors from {path}: {str(e)}")
    
        return "Anonymous"
    
    def generate_author_profile(self, author):
        """Generate unique author profile using AI in the specified language and save it to content/profile folder"""
        profile_dir = os.path.join(self.hugo_content_path, "profile")
        os.makedirs(profile_dir, exist_ok=True)
        
        # Create filename for author profile
        filename = author.lower().replace(" ", "-") + ".md"
        profile_path = os.path.join(profile_dir, filename)
        
        # Skip if profile already exists
        if os.path.exists(profile_path):
            return
        
        # Generate author profile with AI
        try:
            self.logger.info(f"Generating AI profile for author: {author} in {self.language}")
            print(f"Generating AI profile for author: {author} in {self.language}")
            
            # Get current token (may rotate if needed)
            token = self.get_current_token()
            
            # Update client based on SDK type
            if self.sdk_type == "openai":
                from openai import OpenAI
                self.client = OpenAI(
                    base_url=self.endpoint,
                    api_key=token,
                )
            else:  # azure
                from azure.ai.inference import ChatCompletionsClient
                from azure.core.credentials import AzureKeyCredential
                self.client = ChatCompletionsClient(
                    endpoint=self.endpoint,
                    credential=AzureKeyCredential(token),
                )
            
            # Load custom profile prompt
            custom_prompt = self.load_custom_prompt("profile")
            
            # Replace {placeholders} in prompt
            profile_prompt = self.replace_placeholders(custom_prompt, {"author": author})
            profile_prompt = f"Write in {self.language} language.\n\n" + profile_prompt
            
            # Load system message
            system_message = self.load_system_prompt("author_profile_system")
            
            # Send request to AI model
            messages = [
                {
                    "role": "system", 
                    "content": system_message
                },
                {
                    "role": "user",
                    "content": profile_prompt
                }
            ]
            
            profile_body = self.retry_with_token_rotation(
                self.safe_api_call,
                messages,
                temperature=0.7,
                max_tokens=1000
            )
            
            if not profile_body:
                raise Exception("Failed to generate profile content after retries")
            
            # Format the complete profile with front matter
            profile_content = textwrap.dedent(f"""\
    ---
    title: "{author}"
    date: {datetime.now().strftime("%Y-%m-%dT%H:%M:%S")}
    lastmod: {datetime.now().strftime("%Y-%m-%dT%H:%M:%S")}
    draft: false
    description: "Author profile for {author}"
    author: "{author}"
    ---
            
    {profile_body}
    """)
            
            # Apply heading cleanup to profile content
            profile_content = self.remove_h1_after_front_matter(profile_content)
            
            with open(profile_path, "w", encoding="utf-8") as f:
                f.write(profile_content)
            self.logger.info(f"Generated unique AI author profile at {profile_path}")
            print(f"Generated unique AI author profile at {profile_path}")
            
        except Exception as e:
            self.logger.error(f"Error generating AI author profile: {str(e)}")
            print(f"Error generating AI author profile: {str(e)}")
            
            # Fallback to basic template if AI generation fails
            basic_profile = textwrap.dedent(f"""\
    ---
    title: "{author}"
    date: {datetime.now().strftime("%Y-%m-%dT%H:%M:%S")}
    lastmod: {datetime.now().strftime("%Y-%m-%dT%H:%M:%S")}
    draft: false
    description: "Author profile for {author}"
    author: "{author}"
    ---
            
    {author} is a content writer with expertise in various subjects.
            
    ## Expertise
            
    - Content Creation
    - Research
    - Writing
            
    ## Contact
            
    For inquiries.
    """)
            
            try:
                # Apply heading cleanup to fallback profile
                basic_profile = self.remove_h1_after_front_matter(basic_profile)
                
                with open(profile_path, "w", encoding="utf-8") as f:
                    f.write(basic_profile)
                self.logger.info(f"Generated fallback author profile at {profile_path}")
            except Exception as e2:
                self.logger.error(f"Error generating fallback profile: {str(e2)}")
    
    def generate_page_article(self, page_type):
        """Generate a page article like 'About Us' or 'Privacy Policy' using AI with custom prompts"""
        self.logger.info(f"Generating {page_type} page in {self.language}")
        print(f"\nGenerating {page_type} page in {self.language}")
        
        # Create page directory if it doesn't exist
        page_dir = os.path.join(self.hugo_content_path, "page")
        os.makedirs(page_dir, exist_ok=True)
        
        # Create filename for the page
        filename = page_type.lower().replace(" ", "-") + ".md"
        page_path = os.path.join(page_dir, filename)
        
        # Skip if page already exists
        if os.path.exists(page_path):
            self.logger.info(f"{page_type} page already exists at {page_path}")
            print(f"{page_type} page already exists at {page_path}")
            return
        
        try:
            # Get current token (may rotate if needed)
            token = self.get_current_token()
            
            if self.sdk_type == "openai":
                from openai import OpenAI
                self.client = OpenAI(
                    base_url=self.endpoint,
                    api_key=token,
                )
            else:  # azure
                from azure.ai.inference import ChatCompletionsClient
                from azure.core.credentials import AzureKeyCredential
                self.client = ChatCompletionsClient(
                    endpoint=self.endpoint,
                    credential=AzureKeyCredential(token),
                )
            
            # Get prompt type from page type
            prompt_type = page_type.lower().replace(" ", "-")
            
            # Load custom prompt for this page type
            custom_prompt = self.load_custom_prompt(prompt_type)
            
            # Replace {placeholders} in prompt
            custom_prompt = self.replace_placeholders(custom_prompt, {})
            
            # Add language instruction
            page_prompt = f"Write in {self.language} language.\n\n" + custom_prompt
            
            # Load system message template
            system_message_template = self.load_system_prompt("page_article_system")
            
            # Fill in system message template
            system_message = system_message_template.replace("{language}", self.language)
            
            messages = [
                {
                    "role": "system", 
                    "content": system_message
                },
                {
                    "role": "user",
                    "content": page_prompt
                }
            ]
            
            page_content = self.retry_with_token_rotation(
                self.safe_api_call,
                messages,
                temperature=0.7,
                max_tokens=2000
            )
            
            if not page_content:
                self.logger.error(f"Failed to generate {page_type} page content")
                return False
            
            # Format with front matter
            current_date = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
            formatted_page = textwrap.dedent(f"""\
    ---
    title: "{page_type}"
    date: {current_date}
    lastmod: {current_date}
    draft: false
    description: "{page_type} for our website"
    layout: "page"
    ---
    
    {page_content}
    """)        
            # Apply heading cleanup to page content
            formatted_page = self.remove_h1_after_front_matter(formatted_page)
            
            # Save the page
            with open(page_path, "w", encoding="utf-8") as f:
                f.write(formatted_page)
            self.logger.info(f"{page_type} page saved to {page_path}")
            print(f"{page_type} page saved to {page_path}")
            
            return True
        except Exception as e:
            self.logger.error(f"Error generating {page_type} page: {str(e)}")
            print(f"Error generating {page_type} page: {str(e)}")
            return False
    
    def save_article(self, article, keyword):
        """Save the generated article to the Hugo content folder using dynamic niche path"""
        if not article:
            return False
        
        # Create a valid filename from the keyword
        filename = re.sub(r'[^a-zA-Z0-9]', '-', keyword.lower()) + ".md"
        
        # Create niche directory if it doesn't exist (using active_niche for dynamic path)
        niche_path = os.path.join(self.hugo_content_path, self.active_niche)
        os.makedirs(niche_path, exist_ok=True)
        article = self.remove_image_links_from_content(article)
        article = self.remove_meta_description_from_content(article)
        
        save_path = os.path.join(niche_path, filename)
        
        try:
            # Save to Hugo content niche directory
            with open(save_path, "w", encoding="utf-8") as f:
                f.write(article)
            self.logger.info(f"Article saved to {save_path}")
            print(f"Article saved to {save_path}")
            
            return True
        except Exception as e:
            self.logger.error(f"Error saving article: {str(e)}")
            print(f"Error saving article: {str(e)}")
            return False
    
    def run(self):
        """Run the GOHugoGUI Article Generator automatically in watch mode"""
        print("\n========================================")
        print("   Welcome to GOHugoGUI Generator")
        print("   Running in Automatic Watch Mode")
        print("========================================")
        
        # Step 1: Authenticate
        if not self.authenticate():
            return
        self.sync_niche_content_folders()
        
        # Generate standard pages first
        print("\n--- Generating Standard Pages ---")
        self.generate_page_article("About Us")
        self.generate_page_article("Privacy Policy")
        
        # Run in continuous watch mode
        while True:
            try:
                # Step 2: Load resources
                prompts = self.load_prompts()
                if not prompts:
                    self.logger.error("No prompts available. Please add prompts to prompt/blog/articles.txt")
                    print("No prompts available. Please add prompts to prompt/blog/articles.txt")
                    return
                    
                template = self.load_template()
                if not template:
                    self.logger.error("No template available. Please add a template to templates_md/blog/template.md")
                    print("No template available. Please add a template to templates_md/blog/template.md")
                    return
                
                # Step 3: Check for new keywords
                new_keywords = self.get_new_keywords()
                # Limit to only 2 new keywords
                if len(new_keywords) > 2:
                    new_keywords = new_keywords[:2]
                
                if not new_keywords:
                    print("Waiting for new keywords... Will check again in 17.290 seconds.")
                    time.sleep(17.290)
                    continue
                
                print(f"\nFound {len(new_keywords)} new keywords to process.")

                # Ensure personas are selected at start
                self.load_and_select_preferences()
                
                skipped_keywords = []
                successful_count = 0
                
                for i, keyword in enumerate(new_keywords, 1):
                    # Re-select personas for each article if needed
                    self.load_and_select_preferences()

                    print(f"\n--- Processing Article {i}/{len(new_keywords)} ---")
                    print(f"Keyword: {keyword}")
                    
                    # Select a random prompt from the available prompts
                    selected_prompt = random.choice(prompts)
                    print(f"Using prompt: {selected_prompt[:50]}...")
            
                    print("\nSetting audience and author reference persona...")
                    self.audience_reference, self.author_reference = self.load_and_select_preferences()
    
                    # Load writing tone and copywriting style
                    tone_name, tone_description = self.load_writing_tone()
                    copywriting_style, copywriting_description = self.load_copywriting_style()
                    writing_model_name, writing_model_description = self.load_writing_model()
            
                    print(f"Using writing tone: {tone_name}")
                    print(f"Using copywriting style: {copywriting_style}")
                    print(f"Using writing model: {writing_model_name}")
                    
                    # Generate and save the article
                    article = self.generate_article(keyword, selected_prompt, template)
                    if article:
                        # Analyze cultural relevance
                        cultural_analysis = self.analyze_cultural_relevance(article)
                        
                        # Record cultural adaptation stats
                        self.record_cultural_adaptation(keyword, cultural_analysis)
                
                        # Record writing tone and style stats
                        self.record_writing_stats(keyword, tone_name, copywriting_style, writing_model_name)
                        
                        # Save the article
                        success = self.save_article(article, keyword)
                        if success:
                            # Mark keyword as processed
                            successful_count += 1
                    else:
                        skipped_keywords.append(keyword)
                        print(f"Skipping keyword: {keyword} - article does not meet the criteria")
                    
                    # Add a small delay to avoid rate limiting
                    if i < len(new_keywords):
                        time.sleep(5)  # Longer delay between articles
                
                print("\n========================================")
                print(f"   Generation Complete! {successful_count}/{len(new_keywords)} articles generated.")
                if skipped_keywords:
                    print(f"   {len(skipped_keywords)} keywords skipped: {', '.join(skipped_keywords[:5])}")
                    if len(skipped_keywords) > 5:
                        print(f"   ...and {len(skipped_keywords) - 5} more")
                print("   Continuing to watch for new keywords...")
                print("========================================")
                
                # Wait before checking for new keywords again
                time.sleep(30)
                
            except Exception as e:
                self.logger.error(f"Error in watch mode: {str(e)}")
                print(f"Error in watch mode: {str(e)}")
                print("Will retry in 5 minutes...")
                time.sleep(300)  # Wait 5 minutes before retrying after an error
    
    def run_once(self):
        """Run the GOHugoGUI Article Generator once, then exit"""
        print("\n========================================")
        print("   GOHugoGUI Generator - One-time Run")
        print("========================================")
        
        # Step 1: Authenticate
        if not self.authenticate():
            print("❌ Authentication failed. Cannot proceed with article generation.")
            return
        self.sync_niche_content_folders()
        
        # Set audience and author reference persona once at the beginning
        print("\nSetting audience and author reference persona...")
        self.audience_reference, self.author_reference = self.load_and_select_preferences()
    
        # Generate standard pages first
        print("\n--- Generating Standard Pages ---")
        self.generate_page_article("About Us")
        self.generate_page_article("Privacy Policy")
        
        # Step 2: Load resources
        prompts = self.load_prompts()
        if not prompts:
            self.logger.error("No prompts available. Please add prompts to prompt/blog/articles.txt")
            print("No prompts available. Please add prompts to prompt/blog/articles.txt")
            return
            
        template = self.load_template()
        if not template:
            self.logger.error("No template available. Please add a template to templates_md/blog/template.md")
            print("No template available. Please add a template to templates_md/blog/template.md")
            return
        
        # Step 3: Find niche with new keywords
        active_niche, new_keywords = self.find_niche_with_new_keywords()
        
        if not active_niche or not new_keywords:
            print("No new keywords found")
            print("No new keywords found. Exiting.")
            return
        
        print(f"\n✅ Processing niche: {active_niche}")
        print(f"Found {len(new_keywords)} new keywords to process.")
        
        # Limit to only 2 new keywords
        if len(new_keywords) > 2:
            new_keywords = new_keywords[:2]
            print(f"Limited to {len(new_keywords)} keywords for this run.")
        
        # Ensure personas are selected at start
        self.load_and_select_preferences()
        
        skipped_keywords = []
        successful_count = 0
        
        for i, keyword in enumerate(new_keywords, 1):
            # Re-select personas for each article if needed
            self.load_and_select_preferences()
    
            print(f"\n--- Processing Article {i}/{len(new_keywords)} ---")
            print(f"Niche: {active_niche}")
            print(f"Keyword: {keyword}")
            
            # Select a random prompt from the available prompts
            selected_prompt = random.choice(prompts)
            print(f"Using prompt: {selected_prompt[:50]}...")
            
            print("\nSetting audience and author reference persona...")
            self.audience_reference, self.author_reference = self.load_and_select_preferences()
    
            # Load writing tone and copywriting style
            tone_name, tone_description = self.load_writing_tone()
            copywriting_style, copywriting_description = self.load_copywriting_style()
            writing_model_name, writing_model_description = self.load_writing_model()
            
            print(f"Using writing tone: {tone_name}")
            print(f"Using copywriting style: {copywriting_style}")
            print(f"Using writing model: {writing_model_name}")
    
            # Generate and save the article
            article = self.generate_article(keyword, selected_prompt, template)
            if article:
                # Validate and improve articles
                print("Validating and improving article quality...")
                article = self.validate_and_improve_article(article, keyword)
    
                # Analyze cultural relevance
                cultural_analysis = self.analyze_cultural_relevance(article)
                
                # Record cultural adaptation stats
                self.record_cultural_adaptation(keyword, cultural_analysis)
                
                # Record writing tone and style stats
                self.record_writing_stats(keyword, tone_name, copywriting_style, writing_model_name)
                
                # Save the article
                success = self.save_article(article, keyword)
                if success:
                    # Mark keyword as processed
                    successful_count += 1
            else:
                skipped_keywords.append(keyword)
                print(f"Skipping keywords: {keyword} - the article does not meet the criteria")
            
            # Add a small delay to avoid rate limiting
            if i < len(new_keywords):
                time.sleep(5)  # Longer delay between articles
        
        print("\n========================================")
        print(f"   Generation Complete! {successful_count}/{len(new_keywords)} articles generated.")
        print(f"   Active niche: {active_niche}")
        if skipped_keywords:
            print(f"   {len(skipped_keywords)} keywords are skipped: {', '.join(skipped_keywords[:5])}")
            if len(skipped_keywords) > 5:
                print(f"   ...and {len(skipped_keywords) - 5} more")
        
        # Show next niche info
        remaining_niches = [n for n in self.available_niches if n != active_niche]
        if remaining_niches:
            print(f"   Next run will check niches: {', '.join(remaining_niches)}")
        else:
            print("   All niches have been processed in this cycle.")
        
        print("========================================")

def main():
    # First check the license before proceeding with anything else
    args = parse_args()
    if not check_license(args):
        sys.exit(1)

    print("License check passed, continuing with script...")

    generator = None
    try:
        generator = AGCArticleReviser()

        # Setup auto-encryption
        setup_auto_encryption(generator)

        if args.watch:
            # Watch mode with polling for local development
            generator.run()
        else:
            # Default mode: run-once for GitHub Actions
            generator.run_once()
    except KeyboardInterrupt:
        print("\n🔒 Encrypting tokens before exit...")
        if 'generator' in locals() and generator is not None:
            generator.auto_encrypt_tokens_on_exit()
        print("✅ Tokens encrypted. Goodbye!")
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        if 'generator' in locals() and generator is not None:
            generator.auto_encrypt_tokens_on_exit()

if __name__ == "__main__":
    main()