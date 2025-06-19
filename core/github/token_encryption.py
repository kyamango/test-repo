import os
import base64
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class TokenEncryption:
    def __init__(self, project_path):
        self.project_path = project_path
        
        # Updated untuk struktur baru: key dan salt disimpan di core/tools/config/
        self.config_dir = os.path.join(project_path, "core", "tools", "config")
        self.key_file = os.path.join(self.config_dir, ".key")
        self.salt_file = os.path.join(self.config_dir, ".salt")
        
        # Ensure config directory exists
        os.makedirs(self.config_dir, exist_ok=True)
        
        # Generate or load encryption key
        self._setup_encryption()
        
        # If setup failed, try recovery
        if self.cipher_suite is None:
            print("🔄 Attempting key recovery...")
            self.recover_encryption_key()
    
    def _setup_encryption(self):
        """Setup encryption key with improved consistency"""
        try:
            # Check if we already have a working key file
            if os.path.exists(self.key_file):
                try:
                    with open(self.key_file, 'rb') as f:
                        key = f.read()
                    self.cipher_suite = Fernet(key)
                    print("✅ Loaded existing encryption key")
                    return
                except Exception as e:
                    print(f"⚠️ Existing key file corrupted: {e}")
                    # Continue to generate new key
            
            # Generate machine-specific key
            machine_id = self._get_machine_id()
            
            # Load or generate salt with better consistency
            if os.path.exists(self.salt_file):
                with open(self.salt_file, 'rb') as f:
                    salt = f.read()
            else:
                # Use consistent salt for project
                salt = b'gohugo_salt_2024_v1'  # Fixed salt for consistency
                with open(self.salt_file, 'wb') as f:
                    f.write(salt)
            
            # Generate key
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(machine_id.encode()))
            self.cipher_suite = Fernet(key)
            
            # Save the key
            with open(self.key_file, 'wb') as f:
                f.write(key)
            
            print("✅ Generated new encryption key")
            
        except Exception as e:
            print(f"⚠️ Encryption setup error: {e}")
            # Try PAT recovery as last resort
            if self.recover_pat_token():
                print("✅ Encryption setup via PAT recovery")
            else:
                self.cipher_suite = None
    
    def _get_machine_id(self):
        """Get machine-specific identifier"""
        try:
            # Try multiple sources for machine ID
            machine_sources = [
                lambda: os.environ.get('COMPUTERNAME', ''),
                lambda: os.environ.get('USERNAME', ''),
                lambda: os.environ.get('HOSTNAME', ''),
                lambda: str(os.path.getmtime(self.project_path)),
                lambda: str(hash(os.path.abspath(self.project_path)))
            ]
            
            machine_id = ""
            for source in machine_sources:
                try:
                    machine_id += str(source())
                except:
                    continue
            
            return machine_id or "default_key_gohugo_2024_v2"
            
        except:
            return "default_key_gohugo_2024_v2"
    
    def encrypt_token(self, token):
        """Encrypt a token string"""
        if not token or not token.strip():
            return ""
        
        try:
            if self.cipher_suite:
                encrypted = self.cipher_suite.encrypt(token.encode())
                return base64.b64encode(encrypted).decode()
            else:
                # Fallback: simple base64 encoding (not secure)
                return base64.b64encode(token.encode()).decode()
        except Exception as e:
            print(f"❌ Encryption error for token: {e}")
            return token  # Return original if encryption fails
    
    def decrypt_token(self, encrypted_token):
        """Decrypt a token string with better error handling and key recovery"""
        if not encrypted_token or not encrypted_token.strip():
            return ""
        
        try:
            # First check if it's already plain text (GitHub token format)
            if encrypted_token.startswith(('ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_')):
                return encrypted_token
            
            if self.cipher_suite:
                # Try current cipher suite first
                try:
                    decoded = base64.b64decode(encrypted_token.encode())
                    decrypted = self.cipher_suite.decrypt(decoded)
                    return decrypted.decode()
                except Exception as fernet_error:
                    # If current cipher fails, try key recovery
                    print(f"⚠️ Current cipher failed, attempting key recovery...")
                    
                    # Try to recover with different key generation methods
                    recovery_success = self._try_key_recovery(encrypted_token)
                    if recovery_success:
                        try:
                            decoded = base64.b64decode(encrypted_token.encode())
                            decrypted = self.cipher_suite.decrypt(decoded)
                            return decrypted.decode()
                        except:
                            pass
                    
                    # If Fernet fails completely, try simple base64 decode
                    try:
                        return base64.b64decode(encrypted_token.encode()).decode()
                    except:
                        # Last resort: return original (might be corrupted encryption)
                        return encrypted_token
            else:
                # No cipher suite, try simple base64 decode
                try:
                    return base64.b64decode(encrypted_token.encode()).decode()
                except:
                    return encrypted_token
                    
        except Exception as e:
            # Silent handling - return original if all else fails
            return encrypted_token
    
    def _try_key_recovery(self, test_token):
        """Try different key generation methods to recover the correct key"""
        try:
            # Load existing salt
            if os.path.exists(self.salt_file):
                with open(self.salt_file, 'rb') as f:
                    salt = f.read()
            else:
                salt = b'gohugo_salt_2024'  # Default salt
            
            # Try different machine ID generation methods
            recovery_methods = [
                self._get_machine_id,
                lambda: "default_key_gohugo_2024_v2",
                lambda: os.environ.get('COMPUTERNAME', 'default') + str(hash(os.path.abspath(self.project_path))),
                lambda: str(os.path.getmtime(self.project_path)),
            ]
            
            for method in recovery_methods:
                try:
                    machine_id = method()
                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=salt,
                        iterations=100000,
                    )
                    key = base64.urlsafe_b64encode(kdf.derive(machine_id.encode()))
                    test_cipher = Fernet(key)
                    
                    # Test with the provided token
                    try:
                        decoded = base64.b64decode(test_token.encode())
                        test_cipher.decrypt(decoded)
                        # If successful, update the cipher suite
                        self.cipher_suite = test_cipher
                        # Save the working key
                        with open(self.key_file, 'wb') as f:
                            f.write(key)
                        return True
                    except:
                        continue
                        
                except:
                    continue
            
            return False
            
        except:
            return False
    
    def recover_pat_token(self):
        """Special recovery for PAT token using the provided encrypted token"""
        try:
            # The encrypted token from token_pat.txt
            encrypted_pat = "Z0FBQUFBQm9TXzJqd2cxOFpidGx6cjUtQjJUbGpVNFNxTklWZ3pGMHMyTzNiZTJQanhoOFJJYzJobHRrWWJRc215SUNPVy05R1hadjBjaUVKVmVGaDc0b1J5NHVvNURQRHRGSUFzeTVqd0tHZUMzcWdycFpCa3FyMFhacGFKLTRZd2VYX3ZzaDRKeHo="
            
            # Try different approaches to decrypt this specific token
            # Method 1: Try with simpler machine ID
            simple_machine_ids = [
                "default_key_gohugo_2024",
                "GOHugo_project_key",
                str(hash("GOHugo")),
            ]
            
            for machine_id in simple_machine_ids:
                try:
                    # Use a simpler salt
                    salt = b'simple_salt_2024'
                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=salt,
                        iterations=100000,
                    )
                    key = base64.urlsafe_b64encode(kdf.derive(machine_id.encode()))
                    test_cipher = Fernet(key)
                    
                    # Test decryption
                    decoded = base64.b64decode(encrypted_pat.encode())
                    decrypted = test_cipher.decrypt(decoded)
                    decrypted_text = decrypted.decode()
                    
                    # Check if it looks like a valid GitHub token
                    if decrypted_text.startswith('ghp_') and len(decrypted_text) == 40:
                        print(f"✅ PAT token recovery successful with key: {machine_id}")
                        self.cipher_suite = test_cipher
                        # Save the working key and salt
                        with open(self.key_file, 'wb') as f:
                            f.write(key)
                        with open(self.salt_file, 'wb') as f:
                            f.write(salt)
                        return True
                        
                except Exception as e:
                    continue
            
            return False
            
        except Exception as e:
            print(f"❌ PAT recovery error: {e}")
            return False

    def is_encrypted(self, token_string):
        """Check if a token string is encrypted with improved detection"""
        try:
            # Basic checks
            if not token_string or len(token_string) < 10:
                return False
            
            # Check if it looks like GitHub token (starts with ghp_, gho_, etc.)
            # These are definitely plain text
            if token_string.startswith(('ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_')):
                return False
            
            # Check if it looks like Fernet encrypted token (starts with gAAAAA)
            if token_string.startswith('gAAAAA'):
                return True
            
            # Check if it's a long base64-like string
            if len(token_string) > 100 and self._is_base64(token_string):
                return True
            
            # Additional check: try to decode as base64 and check if result looks encrypted
            try:
                decoded = base64.b64decode(token_string.encode())
                # If decoded length is significantly different from original, likely encrypted
                if len(decoded) > 50 and len(decoded) != len(token_string):
                    return True
            except:
                pass
                
            return False
                
        except:
            return False
    
    def _is_base64(self, s):
        """Check if string is valid base64"""
        try:
            return base64.b64encode(base64.b64decode(s)).decode() == s
        except:
            return False

    def recover_encryption_key(self):
        """Try to recover encryption key from existing encrypted tokens"""
        try:
            # This is a recovery method - try different key generation approaches
            recovery_methods = [
                self._get_machine_id,
                lambda: "default_key_gohugo_2024_v2",
                lambda: os.environ.get('COMPUTERNAME', 'default'),
                lambda: str(hash(os.path.abspath(self.project_path))),
            ]
            
            # Load salt if exists
            if os.path.exists(self.salt_file):
                with open(self.salt_file, 'rb') as f:
                    salt = f.read()
            else:
                # Try common salts
                salt = b'gohugo_salt_2024'
            
            for method in recovery_methods:
                try:
                    machine_id = method()
                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=salt,
                        iterations=100000,
                    )
                    key = base64.urlsafe_b64encode(kdf.derive(machine_id.encode()))
                    test_cipher = Fernet(key)
                    
                    # Test with a known encrypted token (first line from tokens.txt)
                    test_token = "Z0FBQUFBQm9TXzJqZnJiVktOZm9FUGVRNzBFQ0hzbTUxZmhmckNPdE5nUkJEYmpuVkF4UF9fOHYzMVhMdWlHYkU5eFktZHFFNTJCWDhXRXdzZ0QyRWc4anp0U0ppTzMyMHgtaDAyYjZRZ3JYLVV2VjR0Z3p4VFRJVjRGd2VucXduekI2dGxDdHl0MFg="
                    
                    try:
                        decoded = base64.b64decode(test_token.encode())
                        decrypted = test_cipher.decrypt(decoded)
                        # If successful, this is the right key
                        self.cipher_suite = test_cipher
                        
                        # Save the working key
                        with open(self.key_file, 'wb') as f:
                            f.write(key)
                        
                        print(f"✅ Successfully recovered encryption key using method: {method.__name__ if hasattr(method, '__name__') else 'lambda'}")
                        return True
                    except:
                        continue
                        
                except Exception as e:
                    continue
            
            print("❌ Could not recover encryption key with any method")
            return False
            
        except Exception as e:
            print(f"❌ Error during key recovery: {e}")
            return False

class TokenManager:
    def __init__(self, project_path):
        self.project_path = project_path
        self.encryptor = TokenEncryption(project_path)
    
    def save_token(self, file_path, token, encrypt=True):
        """Save token to file with optional encryption"""
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            if encrypt and token:
                token_to_save = self.encryptor.encrypt_token(token)
            else:
                token_to_save = token
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(token_to_save)
            
            return True
        except Exception as e:
            print(f"❌ Error saving token: {e}")
            return False
    
    def load_token(self, file_path):
        """Load and decrypt token from file"""
        try:
            if not os.path.exists(file_path):
                return ""
            
            with open(file_path, 'r', encoding='utf-8') as f:
                token_data = f.read().strip()
            
            if not token_data:
                return ""
            
            # Check if encrypted and decrypt if needed
            if self.encryptor.is_encrypted(token_data):
                return self.encryptor.decrypt_token(token_data)
            else:
                return token_data
                
        except Exception as e:
            print(f"❌ Error loading token: {e}")
            return ""
    
    def migrate_existing_tokens(self):
        """Migrate existing plain text tokens to encrypted format"""
        token_files = [
            os.path.join(self.project_path, "token", "tokens.txt"),
            os.path.join(self.project_path, "token", "tokens.default.txt"),
            os.path.join(self.project_path, "token", "PAT", "token_pat.txt")
        ]
        
        migrated = []
        for file_path in token_files:
            if os.path.exists(file_path):
                try:
                    # Read all lines from file
                    with open(file_path, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                    
                    # Process each line individually
                    modified_lines = []
                    file_changed = False
                    
                    for line in lines:
                        original_line = line.rstrip('\n\r')  # Remove line endings
                        
                        # Skip empty lines and comments
                        if not original_line or original_line.startswith('#'):
                            modified_lines.append(line)  # Keep original formatting
                            continue
                        
                        # Check if this token is already encrypted
                        if self.encryptor.is_encrypted(original_line):
                            modified_lines.append(line)  # Already encrypted, keep as is
                        else:
                            # Encrypt this plain text token
                            encrypted_token = self.encryptor.encrypt_token(original_line)
                            modified_lines.append(encrypted_token + '\n')
                            file_changed = True
                    
                    # Write back to file if any changes were made
                    if file_changed:
                        with open(file_path, 'w', encoding='utf-8') as f:
                            f.writelines(modified_lines)
                        migrated.append(file_path)
                        print(f"✅ Encrypted tokens in: {os.path.relpath(file_path, self.project_path)}")
                        
                except Exception as e:
                    print(f"❌ Error migrating {file_path}: {e}")
        
        return migrated
    
    def encrypt_all_tokens_in_file(self, file_path):
        """Encrypt all plain text tokens in a specific file"""
        if not os.path.exists(file_path):
            return False
        
        try:
            # Read all lines
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            # Process each line
            modified_lines = []
            tokens_encrypted = 0
            
            for line in lines:
                original_line = line.rstrip('\n\r')
                
                # Skip empty lines and comments
                if not original_line or original_line.startswith('#'):
                    modified_lines.append(line)
                    continue
                
                # Check if already encrypted
                if self.encryptor.is_encrypted(original_line):
                    modified_lines.append(line)  # Keep as is
                else:
                    # Encrypt plain text token
                    encrypted_token = self.encryptor.encrypt_token(original_line)
                    modified_lines.append(encrypted_token + '\n')
                    tokens_encrypted += 1
            
            # Write back if changes were made
            if tokens_encrypted > 0:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.writelines(modified_lines)
                print(f"✅ Encrypted {tokens_encrypted} tokens in {os.path.basename(file_path)}")
                return True
            else:
                print(f"ℹ️ All tokens in {os.path.basename(file_path)} are already encrypted")
                return False
                
        except Exception as e:
            print(f"❌ Error encrypting tokens in {file_path}: {e}")
            return False
    
    def decrypt_all_tokens_in_file(self, file_path):
        """Decrypt all encrypted tokens in a specific file (for temporary editing)"""
        if not os.path.exists(file_path):
            return False
        
        try:
            # Read all lines
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            # Process each line
            modified_lines = []
            tokens_decrypted = 0
            successful_decryptions = 0
            
            for line_num, line in enumerate(lines, 1):
                original_line = line.rstrip('\n\r')
                
                # Skip empty lines and comments
                if not original_line or original_line.startswith('#'):
                    modified_lines.append(line)
                    continue
                
                # Check if encrypted
                if self.encryptor.is_encrypted(original_line):
                    # Decrypt encrypted token
                    decrypted_token = self.encryptor.decrypt_token(original_line)
                    
                    # Verify decryption was successful
                    if decrypted_token and decrypted_token != original_line and not self.encryptor.is_encrypted(decrypted_token):
                        modified_lines.append(decrypted_token + '\n')
                        tokens_decrypted += 1
                        successful_decryptions += 1
                    else:
                        # Decryption failed, keep original but warn
                        print(f"⚠️ Failed to decrypt token on line {line_num}, keeping encrypted")
                        modified_lines.append(line)
                        tokens_decrypted += 1  # Count as processed
                else:
                    modified_lines.append(line)  # Keep plain text as is
            
            # Write back if changes were made
            if successful_decryptions > 0:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.writelines(modified_lines)
                print(f"✅ Successfully decrypted {successful_decryptions}/{tokens_decrypted} tokens in {os.path.basename(file_path)}")
                return True
            elif tokens_decrypted > 0:
                print(f"⚠️ Found {tokens_decrypted} encrypted tokens in {os.path.basename(file_path)} but decryption failed")
                return False
            else:
                print(f"ℹ️ No encrypted tokens found in {os.path.basename(file_path)}")
                return False
                
        except Exception as e:
            print(f"❌ Error decrypting tokens in {file_path}: {e}")
            return False
    
    def get_token_status(self, file_path):
        """Get encryption status of tokens in a file"""
        if not os.path.exists(file_path):
            return {"encrypted": 0, "plain": 0, "total": 0}
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            encrypted_count = 0
            plain_count = 0
            
            for line in lines:
                line_clean = line.strip()
                if line_clean and not line_clean.startswith('#'):
                    if self.encryptor.is_encrypted(line_clean):
                        encrypted_count += 1
                    else:
                        plain_count += 1
            
            return {
                "encrypted": encrypted_count,
                "plain": plain_count,
                "total": encrypted_count + plain_count
            }
            
        except Exception as e:
            print(f"❌ Error checking status of {file_path}: {e}")
            return {"encrypted": 0, "plain": 0, "total": 0}
    
    def get_encryption_info(self):
        """Get information about encryption setup"""
        return {
            "config_dir": self.encryptor.config_dir,
            "key_file_exists": os.path.exists(self.encryptor.key_file),
            "salt_file_exists": os.path.exists(self.encryptor.salt_file),
            "encryption_enabled": self.encryptor.cipher_suite is not None
        }
    
    def test_decryption_capability(self):
        """Test if decryption is working properly"""
        try:
            # Test with a sample token
            test_token = "ghp_test_token_1234567890"
            
            # Encrypt it
            encrypted = self.encryptor.encrypt_token(test_token)
            
            # Decrypt it
            decrypted = self.encryptor.decrypt_token(encrypted)
            
            # Verify
            return decrypted == test_token, encrypted, decrypted
            
        except Exception as e:
            return False, str(e), ""