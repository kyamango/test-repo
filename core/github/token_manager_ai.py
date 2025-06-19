#!/usr/bin/env python3
"""
AGC Token Management CLI - FIXED VERSION
Updated for directory structure: GOHugo/core/tools/

Usage:
    python core/tools/token_manager_ai.py --status
    python core/tools/token_manager_ai.py --view
    python core/tools/token_manager_ai.py --encrypt
    python core/tools/token_manager_ai.py --decrypt-temp
    python core/tools/token_manager_ai.py --test-decrypt
    python core/tools/token_manager_ai.py --diagnose
"""

import os
import sys
import argparse
from pathlib import Path

# Add the current directory to path for imports
current_dir = Path(__file__).parent.absolute()
sys.path.insert(0, str(current_dir))

try:
    from token_encryption import TokenManager
except ImportError as e:
    print(f"❌ Error importing TokenManager: {e}")
    print("Make sure token_encryption.py is in the same directory as this script")
    sys.exit(1)

def get_base_dir():
    """Get the base directory of the project (GOHugo root)"""
    current_dir = Path(__file__).parent.absolute()
    
    # Dari core/tools/, naik 2 level untuk mencapai GOHugo/
    if current_dir.name == "tools" and current_dir.parent.name == "core":
        return str(current_dir.parent.parent)
    
    # Jika dipanggil dari tempat lain, cari directory GOHugo
    search_dir = current_dir
    while search_dir.parent != search_dir:  # Sampai root
        if (search_dir / "core" / "tools").exists() and (search_dir / "token").exists():
            return str(search_dir)
        search_dir = search_dir.parent
    
    # Fallback: asumsi struktur relatif
    potential_base = current_dir.parent.parent
    if (potential_base / "token").exists():
        return str(potential_base)
    
    print(f"⚠️ Warning: Could not determine base directory. Using: {str(current_dir.parent.parent)}")
    return str(current_dir.parent.parent)

def diagnose_encryption(base_path):
    """Diagnose encryption system issues"""
    print("🔍 Diagnosing encryption system...")
    print(f"📁 Base path: {base_path}")
    
    try:
        token_manager = TokenManager(base_path)
        
        # If cipher_suite is None, try recovery
        if token_manager.encryptor.cipher_suite is None:
            print("🔄 Cipher suite not initialized, attempting recovery...")
            if token_manager.encryptor.recover_encryption_key():
                print("✅ Key recovery successful!")
            else:
                print("❌ Key recovery failed - you may need to re-encrypt tokens")
        
        # Test encryption capability
        print("\n🧪 Testing encryption/decryption capability:")
        success, encrypted, decrypted = token_manager.test_decryption_capability()
        
        if success:
            print("✅ Basic encryption/decryption test: PASSED")
            print(f"   Original: ghp_test_token_1234567890")
            print(f"   Encrypted: {encrypted[:30]}...{encrypted[-10:]}")
            print(f"   Decrypted: {decrypted}")
        else:
            print("❌ Basic encryption/decryption test: FAILED")
            print(f"   Error: {encrypted}")
        
        # Test with actual encrypted tokens from tokens.txt
        print("\n🔬 Testing actual encrypted tokens:")
        sample_encrypted_tokens = [
            "Z0FBQUFBQm9TXzJqZnJiVktOZm9FUGVRNzBFQ0hzbTUxZmhmckNPdE5nUkJEYmpuVkF4UF9fOHYzMVhMdWlHYkU5eFktZHFFNTJCWDhXRXdzZ0QyRWc4anp0U0ppTzMyMHgtaDAyYjZRZ3JYLVV2VjR0Z3p4VFRJVjRGd2VucXduekI2dGxDdHl0MFg=",
            "Z0FBQUFBQm9TXzJqQy13QkU5TXhpUVVaaVpRYWRKTjRBVVhVUTNCcWtVVVNsSlc2UTRERmZqd01NUmNsdmlTMFdFb0VhZjM2MnhnNVd5MVZyZXZ5X2pSOWRlUjgtSWxESGNwbXB4cmlaWEFOX21OSjRlVHR0ODFfOS1mcFVjbDVGd1ZrTUx6WFlpZFg="
        ]
        
        for i, token in enumerate(sample_encrypted_tokens, 1):
            try:
                decrypted = token_manager.encryptor.decrypt_token(token)
                if decrypted and decrypted != token and len(decrypted) > 20:
                    masked = decrypted[:8] + "..." + decrypted[-4:]
                    print(f"   Token {i}: Successfully decrypted → {masked} ✅")
                else:
                    print(f"   Token {i}: Decryption failed ❌")
            except Exception as e:
                print(f"   Token {i}: Error during decryption: {str(e)[:50]} ❌")

        
        # Check encryption setup
        print("\n🔧 Encryption setup:")
        enc_info = token_manager.get_encryption_info()
        print(f"   📁 Config dir: {enc_info['config_dir']}")
        print(f"   🔑 Key file exists: {'✅' if enc_info['key_file_exists'] else '❌'}")
        print(f"   🧂 Salt file exists: {'✅' if enc_info['salt_file_exists'] else '❌'}")
        print(f"   🔒 Encryption enabled: {'✅' if enc_info['encryption_enabled'] else '❌'}")
        
        # Test real tokens
        print("\n📄 Testing actual token files:")
        token_files = [
            ("tokens.txt", os.path.join(base_path, "token", "tokens.txt")),
            ("tokens.default.txt", os.path.join(base_path, "token", "tokens.default.txt")),
            ("PAT/token_pat.txt", os.path.join(base_path, "token", "PAT", "token_pat.txt"))
        ]
        
        for file_name, token_file in token_files:
            print(f"\n   📄 {file_name}:")
            if os.path.exists(token_file):
                try:
                    with open(token_file, "r", encoding="utf-8") as f:
                        lines = f.readlines()
                    
                    test_count = 0
                    success_count = 0
                    
                    for i, line in enumerate(lines[:5], 1):  # Test first 5 tokens
                        line_clean = line.strip()
                        if line_clean and not line_clean.startswith("#"):
                            test_count += 1
                            
                            # Check encryption status
                            is_encrypted = token_manager.encryptor.is_encrypted(line_clean)
                            
                            # Try to decrypt
                            decrypted = token_manager.encryptor.decrypt_token(line_clean)
                            
                            if is_encrypted and decrypted and decrypted != line_clean:
                                print(f"      Token {i}: Encrypted → Decrypted ✅")
                                success_count += 1
                            elif not is_encrypted and decrypted == line_clean:
                                print(f"      Token {i}: Plain text ✅")
                                success_count += 1
                            else:
                                print(f"      Token {i}: Decryption issue ❌")
                                print(f"         Is encrypted: {is_encrypted}")
                                print(f"         Original: {line_clean[:20]}...")
                                print(f"         Decrypted: {decrypted[:20] if decrypted else 'None'}...")
                    
                    print(f"      Summary: {success_count}/{test_count} tokens OK")
                    
                except Exception as e:
                    print(f"      ❌ Error reading file: {e}")
            else:
                print(f"      File not found")
        
        # Provide recommendations
        print(f"\n💡 Recommendations:")
        if not enc_info['encryption_enabled']:
            print("   - Encryption system is not properly initialized")
            print("   - Try running: python core/tools/setup_encryption.py")
        elif not success:
            print("   - Basic encryption test failed")
            print("   - Check if cryptography library is properly installed")
            print("   - Try: pip install cryptography")
        else:
            print("   - Encryption system appears to be working correctly")
            print("   - The 'Decryption error:' messages are likely cosmetic")
        
    except Exception as e:
        print(f"❌ Error during diagnosis: {str(e)}")
        import traceback
        traceback.print_exc()

def encrypt_tokens(base_path):
    """Encrypt all plain text tokens"""
    print("🔒 Encrypting tokens...")
    print(f"📁 Base path: {base_path}")
    
    try:
        token_manager = TokenManager(base_path)
        
        token_files = [
            os.path.join(base_path, "token", "tokens.txt"),
            os.path.join(base_path, "token", "tokens.default.txt"),
            os.path.join(base_path, "token", "PAT", "token_pat.txt")
        ]
        
        total_files_changed = 0
        total_tokens_encrypted = 0
        
        for token_file in token_files:
            if os.path.exists(token_file):
                relative_path = os.path.relpath(token_file, base_path)
                print(f"\n📄 Processing {relative_path}...")
                
                # Count tokens before encryption
                status_before = token_manager.get_token_status(token_file)
                
                if token_manager.encrypt_all_tokens_in_file(token_file):
                    total_files_changed += 1
                    total_tokens_encrypted += status_before['plain']
                elif status_before['total'] > 0:
                    print(f"   ℹ️ All {status_before['total']} tokens already encrypted")
                else:
                    print(f"   ℹ️ No tokens found in file")
            else:
                relative_path = os.path.relpath(token_file, base_path)
                print(f"\n📄 {relative_path}: File not found, skipping...")
        
        print(f"\n{'='*50}")
        if total_files_changed > 0:
            print(f"✅ Successfully encrypted {total_tokens_encrypted} tokens in {total_files_changed} files")
        else:
            print("ℹ️ No plain text tokens found to encrypt")
        
        # Show final status
        print("\n📊 Final encryption status:")
        check_token_status(base_path, show_header=False)
        
    except Exception as e:
        print(f"❌ Error during encryption: {str(e)}")
        import traceback
        traceback.print_exc()

def decrypt_tokens_temporary(base_path):
    """Temporarily decrypt tokens for editing with better error handling"""
    print("🔓 Temporarily decrypting tokens for editing...")
    print(f"📁 Base path: {base_path}")
    
    try:
        token_manager = TokenManager(base_path)
        
        # First, test decryption capability
        print("🧪 Testing decryption capability...")
        success, _, _ = token_manager.test_decryption_capability()
        
        if not success:
            print("❌ Decryption test failed! Cannot proceed safely.")
            print("💡 Try running: python core/tools/token_manager_ai.py --diagnose")
            return
        
        print("✅ Decryption test passed, proceeding...")
        
        token_files = [
            os.path.join(base_path, "token", "tokens.txt"),
            os.path.join(base_path, "token", "tokens.default.txt"),
            os.path.join(base_path, "token", "PAT", "token_pat.txt")
        ]
        
        decrypted_files = []
        total_tokens_decrypted = 0
        failed_decryptions = []
        
        for token_file in token_files:
            if os.path.exists(token_file):
                relative_path = os.path.relpath(token_file, base_path)
                print(f"\n📄 Processing {relative_path}...")
                
                # Count encrypted tokens before decryption
                status_before = token_manager.get_token_status(token_file)
                
                if status_before['encrypted'] > 0:
                    # Make backup before decryption
                    backup_file = token_file + ".backup"
                    import shutil
                    shutil.copy2(token_file, backup_file)
                    print(f"   📋 Created backup: {os.path.basename(backup_file)}")
                
                if token_manager.decrypt_all_tokens_in_file(token_file):
                    decrypted_files.append(token_file)
                    total_tokens_decrypted += status_before['encrypted']
                elif status_before['total'] > 0:
                    if status_before['encrypted'] > 0:
                        failed_decryptions.append((relative_path, status_before['encrypted']))
                    else:
                        print(f"   ℹ️ All {status_before['total']} tokens already in plain text")
                else:
                    print(f"   ℹ️ No tokens found in file")
        
        print(f"\n{'='*50}")
        
        if decrypted_files:
            print(f"✅ Successfully decrypted tokens in {len(decrypted_files)} files:")
            for file_path in decrypted_files:
                relative_path = os.path.relpath(file_path, base_path)
                print(f"   - {relative_path}")
            
            print(f"\n⚠️ WARNING: Tokens are now in PLAIN TEXT!")
            print(f"   🔒 Remember to encrypt them again before committing to git!")
            print(f"   🚀 Use: python core/tools/token_manager_ai.py --encrypt")
            
        if failed_decryptions:
            print(f"\n⚠️ Some decryptions failed:")
            for file_path, count in failed_decryptions:
                print(f"   - {file_path}: {count} tokens could not be decrypted")
            print(f"   💡 Backup files created - restore if needed")
            
        if not decrypted_files and not failed_decryptions:
            print("ℹ️ No encrypted tokens found to decrypt")
            
    except Exception as e:
        print(f"❌ Error during decryption: {str(e)}")
        import traceback
        traceback.print_exc()

def fix_encryption_keys(base_path):
    """Fix encryption keys by trying to recover from existing encrypted tokens"""
    print("🔧 Attempting to fix encryption keys...")
    print(f"📁 Base path: {base_path}")
    
    try:
        token_manager = TokenManager(base_path)
        
        # Try PAT recovery first
        if token_manager.encryptor.recover_pat_token():
            print("✅ Successfully recovered encryption key from PAT token!")
            
            # Test with other tokens
            test_tokens = [
                "Z0FBQUFBQm9TXzJqZnJiVktOZm9FUGVRNzBFQ0hzbTUxZmhmckNPdE5nUkJEYmpuVkF4UF9fOHYzMVhMdWlHYkU5eFktZHFFNTJCWDhXRXdzZ0QyRWc4anp0U0ppTzMyMHgtaDAyYjZRZ3JYLVV2VjR0Z3p4VFRJVjRGd2VucXduekI2dGxDdHl0MFg=",
                "Z0FBQUFBQm9TXzJqQy13QkU5TXhpUVVaaVpRYWRKTjRBVVhVUTNCcWtVVVNsSlc2UTRERmZqd01NUmNsdmlTMFdFb0VhZjM2MnhnNVd5MVZyZXZ5X2pSOWRlUjgtSWxESGNwbXB4cmlaWEFOX21OSjRlVHR0ODFfOS1mcFVjbDVGd1ZrTUx6WFlpZFg="
            ]
            
            success_count = 0
            for i, token in enumerate(test_tokens, 1):
                decrypted = token_manager.encryptor.decrypt_token(token)
                if decrypted and decrypted != token and decrypted.startswith('ghp_'):
                    print(f"✅ Test token {i}: Successfully decrypted")
                    success_count += 1
                else:
                    print(f"❌ Test token {i}: Decryption failed")
            
            if success_count > 0:
                print(f"🎉 Key recovery successful! {success_count}/{len(test_tokens)} tokens working")
                return True
            else:
                print("❌ Key recovery failed - no tokens could be decrypted")
                return False
        else:
            print("❌ Could not recover encryption key from PAT token")
            return False
            
    except Exception as e:
        print(f"❌ Error during key recovery: {e}")
        return False

def view_tokens(base_path):
    """View masked tokens for verification"""
    print("👁️ Viewing tokens (masked for security)...")
    print(f"📁 Base path: {base_path}")
    
    try:
        token_manager = TokenManager(base_path)
        
        token_files = [
            ("tokens.txt", os.path.join(base_path, "token", "tokens.txt")),
            ("tokens.default.txt", os.path.join(base_path, "token", "tokens.default.txt")),
            ("PAT/token_pat.txt", os.path.join(base_path, "token", "PAT", "token_pat.txt"))
        ]
        
        total_tokens = 0
        
        for file_name, token_file in token_files:
            print(f"\n📄 token/{file_name}:")
            
            if os.path.exists(token_file):
                try:
                    with open(token_file, "r", encoding="utf-8") as f:
                        lines = f.readlines()
                    
                    valid_tokens = 0
                    for i, line in enumerate(lines, 1):
                        line_clean = line.strip()
                        if line_clean and not line_clean.startswith("#"):
                            # Decrypt to get actual token
                            decrypted = token_manager.encryptor.decrypt_token(line_clean)
                            if decrypted:
                                # Create masked version
                                if len(decrypted) > 12:
                                    masked = decrypted[:8] + "..." + decrypted[-4:]
                                else:
                                    masked = decrypted[:4] + "..." + decrypted[-2:]
                                
                                # Check encryption status
                                is_encrypted = token_manager.encryptor.is_encrypted(line_clean)
                                status = "🔒 Encrypted" if is_encrypted else "🔓 Plain text"
                                
                                print(f"   {valid_tokens + 1}. {masked} ({status})")
                                valid_tokens += 1
                    
                    if valid_tokens == 0:
                        print("   (No valid tokens found)")
                    else:
                        print(f"   📊 Total: {valid_tokens} tokens")
                        total_tokens += valid_tokens
                        
                except Exception as e:
                    print(f"   ❌ Error reading file: {str(e)}")
            else:
                print("   (File not found)")
        
        print(f"\n{'='*40}")
        print(f"📈 TOTAL TOKENS ACROSS ALL FILES: {total_tokens}")
        
    except Exception as e:
        print(f"❌ Error viewing tokens: {str(e)}")
        import traceback
        traceback.print_exc()

def check_token_status(base_path, show_header=True):
    """Check encryption status of all tokens"""
    if show_header:
        print("🔍 Checking token encryption status...")
        print(f"📁 Base path: {base_path}")
    
    try:
        token_manager = TokenManager(base_path)
        
        token_files = [
            ("tokens.txt", os.path.join(base_path, "token", "tokens.txt")),
            ("tokens.default.txt", os.path.join(base_path, "token", "tokens.default.txt")),
            ("PAT/token_pat.txt", os.path.join(base_path, "token", "PAT", "token_pat.txt"))
        ]
        
        total_encrypted = 0
        total_plain = 0
        files_found = 0
        
        for file_name, token_file in token_files:
            if show_header:
                print(f"\n📄 token/{file_name}:")
            
            if os.path.exists(token_file):
                files_found += 1
                status = token_manager.get_token_status(token_file)
                
                if show_header:
                    print(f"   🔒 Encrypted: {status['encrypted']}")
                    print(f"   🔓 Plain text: {status['plain']}")
                    print(f"   📊 Total tokens: {status['total']}")
                
                if status['plain'] > 0:
                    if show_header:
                        print(f"   ⚠️ WARNING: {status['plain']} tokens are not encrypted!")
                elif status['total'] > 0:
                    if show_header:
                        print(f"   ✅ All tokens are encrypted")
                else:
                    if show_header:
                        print(f"   ℹ️ No tokens found in file")
                
                total_encrypted += status['encrypted']
                total_plain += status['plain']
            else:
                if show_header:
                    print("   (File not found)")
        
        # Summary
        if show_header:
            print(f"\n{'='*40}")
            print(f"📊 SUMMARY:")
        print(f"   🔒 Total encrypted: {total_encrypted}")
        print(f"   🔓 Total plain text: {total_plain}")
        print(f"   📈 Total tokens: {total_encrypted + total_plain}")
        print(f"   📁 Files found: {files_found}/3")
        
        if total_plain > 0:
            print(f"\n⚠️ ACTION NEEDED: {total_plain} tokens need encryption!")
            print("   🚀 Run: python core/tools/token_manager_ai.py --encrypt")
        elif total_encrypted > 0:
            print(f"\n✅ SECURE: All {total_encrypted} tokens are encrypted!")
        else:
            print(f"\nℹ️ No tokens found in any files")
        
        # Show encryption info
        enc_info = token_manager.get_encryption_info()
        if show_header:
            print(f"\n🔧 Encryption Setup:")
            print(f"   📁 Config dir: {enc_info['config_dir']}")
            print(f"   🔑 Key file exists: {'✅' if enc_info['key_file_exists'] else '❌'}")
            print(f"   🧂 Salt file exists: {'✅' if enc_info['salt_file_exists'] else '❌'}")
            print(f"   🔒 Encryption enabled: {'✅' if enc_info['encryption_enabled'] else '❌'}")
        
    except Exception as e:
        print(f"❌ Error checking token status: {str(e)}")
        import traceback
        traceback.print_exc()

def force_encrypt_specific_file(base_path, filename):
    """Force encrypt a specific file"""
    try:
        token_manager = TokenManager(base_path)
        token_file = os.path.join(base_path, "token", filename)
        
        if not os.path.exists(token_file):
            print(f"❌ File not found: token/{filename}")
            return
        
        print(f"🔒 Force encrypting: token/{filename}")
        print(f"📁 Full path: {token_file}")
        
        # Show status before
        status_before = token_manager.get_token_status(token_file)
        print(f"📊 Before encryption:")
        print(f"   🔒 Encrypted: {status_before['encrypted']}")
        print(f"   🔓 Plain text: {status_before['plain']}")
        
        success = token_manager.encrypt_all_tokens_in_file(token_file)
        
        # Show status after
        status_after = token_manager.get_token_status(token_file)
        print(f"📊 After encryption:")
        print(f"   🔒 Encrypted: {status_after['encrypted']}")
        print(f"   🔓 Plain text: {status_after['plain']}")
        
        if success:
            tokens_encrypted = status_before['plain']
            print(f"✅ Successfully encrypted {tokens_encrypted} tokens in {filename}")
        else:
            print(f"ℹ️ No changes needed for {filename} (all tokens already encrypted)")
            
    except Exception as e:
        print(f"❌ Error force encrypting {filename}: {str(e)}")
        import traceback
        traceback.print_exc()

def main():
    parser = argparse.ArgumentParser(
        description="AGC Token Management CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python core/tools/token_manager_ai.py --status
  python core/tools/token_manager_ai.py --view  
  python core/tools/token_manager_ai.py --encrypt
  python core/tools/token_manager_ai.py --decrypt-temp
  python core/tools/token_manager_ai.py --test-decrypt
  python core/tools/token_manager_ai.py --force-encrypt tokens.txt
        """
    )
    
    parser.add_argument("--encrypt", action="store_true", 
                       help="Encrypt all plain text tokens")
    parser.add_argument("--decrypt-temp", action="store_true", 
                       help="Temporarily decrypt tokens for editing")
    parser.add_argument("--view", action="store_true", 
                       help="View masked tokens")
    parser.add_argument("--status", action="store_true", 
                       help="Check encryption status")
    parser.add_argument("--test-decrypt", action="store_true",
                       help="Test decryption functionality")
    parser.add_argument("--force-encrypt", metavar="FILENAME", 
                       help="Force encrypt specific file (e.g., tokens.txt)")
    parser.add_argument("--base-path", 
                       help="Base path of the project (auto-detected if not specified)")
    parser.add_argument("--diagnose", action="store_true",
                   help="Diagnose encryption system issues")
    parser.add_argument("--fix-keys", action="store_true",
                   help="Attempt to fix encryption keys by recovering from existing tokens")
    
    args = parser.parse_args()
    
    # Get base path
    base_path = args.base_path if args.base_path else get_base_dir()
    
    if not os.path.exists(base_path):
        print(f"❌ Base path not found: {base_path}")
        sys.exit(1)
    
    # Verify directory structure
    token_dir = os.path.join(base_path, "token")
    tools_dir = os.path.join(base_path, "core", "tools")
    
    if not os.path.exists(token_dir):
        print(f"❌ Token directory not found: {token_dir}")
        print("   Please ensure you're running from the correct directory")
        sys.exit(1)
    
    print(f"🏠 Project base path: {base_path}")
    print(f"📁 Token directory: {token_dir}")
    print(f"🛠️ Tools directory: {tools_dir}")
    
    # Execute commands
    try:
        if args.encrypt:
            encrypt_tokens(base_path)
        elif args.decrypt_temp:
            decrypt_tokens_temporary(base_path)
        elif args.view:
            view_tokens(base_path)
        elif args.force_encrypt:
            force_encrypt_specific_file(base_path, args.force_encrypt)
        elif args.status:
            check_token_status(base_path)
        elif args.diagnose:
            diagnose_encryption(base_path)
        elif args.fix_keys:
            if fix_encryption_keys(base_path):
                print("\n🔄 Now trying to decrypt tokens...")
                decrypt_tokens_temporary(base_path)
            else:
                print("\n💡 Key recovery failed. You may need to:")
                print("   1. Restore from backup if available")
                print("   2. Re-encrypt with new keys (will lose old encrypted data)")
        else:
            # Default: show status and help
            check_token_status(base_path)
            print(f"\n{'='*50}")
            print("📋 Available commands:")
            print("  --status           Check encryption status of all tokens")
            print("  --view             View masked tokens for verification")
            print("  --encrypt          Encrypt all plain text tokens")
            print("  --decrypt-temp     Temporarily decrypt tokens for editing")
            print("  --test-decrypt     Test decryption functionality")
            print("  --force-encrypt    Force encrypt specific file")
            print("\n💡 Tip: Use --help for detailed usage information")
            
    except KeyboardInterrupt:
        print(f"\n\n🔒 Interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()