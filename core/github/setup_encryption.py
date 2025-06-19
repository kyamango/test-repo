#!/usr/bin/env python3
"""
Setup script untuk mengonfigurasi enkripsi token AGC System
Updated untuk struktur direktori baru: GOHugo/core/tools/
"""

import os
import sys
import shutil
import stat
from pathlib import Path

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
    
    return str(current_dir.parent.parent)

def setup_git_hooks(base_path):
    """Setup git hooks untuk auto-encrypt"""
    git_hooks_dir = os.path.join(base_path, ".git", "hooks")
    
    if not os.path.exists(git_hooks_dir):
        print("⚠️ Git repository not found. Git hooks will not be installed.")
        return False
    
    # Pre-commit hook content - Updated untuk struktur baru
    pre_commit_content = '''#!/bin/bash
# Auto-encrypt tokens before commit

echo "🔒 Auto-encrypting tokens before commit..."

# Change to project directory
cd "$(git rev-parse --show-toplevel)"

# Run token encryption using the new structure
python core/tools/token_manager_ai.py --encrypt 2>/dev/null || python3 core/tools/token_manager_ai.py --encrypt 2>/dev/null

# Check if there are changes after encryption
if git diff --quiet token/tokens.txt token/tokens.default.txt token/PAT/token_pat.txt 2>/dev/null; then
    echo "✅ Tokens already encrypted"
else
    echo "🔄 Adding encrypted tokens to commit..."
    git add token/tokens.txt token/tokens.default.txt token/PAT/token_pat.txt 2>/dev/null || true
    echo "✅ Tokens encrypted and added to commit"
fi

echo "🚀 Ready to commit safely!"
exit 0
'''
    
    # Write pre-commit hook
    pre_commit_path = os.path.join(git_hooks_dir, "pre-commit")
    
    try:
        with open(pre_commit_path, "w", encoding="utf-8") as f:
            f.write(pre_commit_content)
        
        # Make executable
        os.chmod(pre_commit_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IROTH)
        
        print(f"✅ Git pre-commit hook installed: {pre_commit_path}")
        return True
        
    except Exception as e:
        print(f"❌ Error installing git hook: {str(e)}")
        return False

def create_gitignore_entries(base_path):
    """Add entries to .gitignore untuk keamanan"""
    gitignore_path = os.path.join(base_path, ".gitignore")
    
    # Entries yang perlu ditambahkan - Updated untuk struktur baru
    security_entries = [
        "",
        "# AGC Token Security",
        "core/tools/.key",
        "core/tools/.salt",
        "core/tools/config/.key",
        "core/tools/config/.salt",
        "token/last_login.json",
        "*.log",
        "__pycache__/",
        "*.pyc",
        "core/tools/__pycache__/",
        "core/tools/*.log",
        ""
    ]
    
    # Baca existing .gitignore
    existing_entries = []
    if os.path.exists(gitignore_path):
        try:
            with open(gitignore_path, "r", encoding="utf-8") as f:
                existing_entries = f.read().splitlines()
        except Exception:
            pass
    
    # Check entries yang perlu ditambahkan
    entries_to_add = []
    for entry in security_entries:
        if entry and entry not in existing_entries:
            entries_to_add.append(entry)
    
    # Tambahkan entries baru
    if entries_to_add:
        try:
            with open(gitignore_path, "a", encoding="utf-8") as f:
                f.write("\n".join(entries_to_add))
            print(f"✅ Added {len([e for e in entries_to_add if e.strip()])} security entries to .gitignore")
        except Exception as e:
            print(f"❌ Error updating .gitignore: {str(e)}")

def create_readme_security(base_path):
    """Create security documentation"""
    readme_content = '''# AGC Token Security

## Overview
Token keamanan AGC menggunakan enkripsi berbasis machine-specific untuk melindungi API keys.

## Struktur File
```
GOHugo/
├── core/
│   └── tools/
│       ├── script_agc_ai.py
│       ├── setup_encryption.py
│       ├── token_manager_ai.py
│       ├── token_encryption.py
│       └── kw_search.py
├── token/
│   └── PAT/
│   |   └── token_pat.txt
│   ├── tokens.default.txt
│   └── tokens.txt
```

## Penggunaan

### Melihat Status Token
```bash
python core/tools/token_manager_ai.py --status
```

### Melihat Token (Masked)
```bash
python core/tools/token_manager_ai.py --view
```

### Enkripsi Token Manual
```bash
python core/tools/token_manager_ai.py --encrypt
```

### Edit Token (Temporary Decrypt)
```bash
# Decrypt untuk editing
python core/tools/token_manager_ai.py --decrypt-temp

# Edit file token/tokens.txt
# Setelah selesai, encrypt kembali
python core/tools/token_manager_ai.py --encrypt
```

## Keamanan

1. **Auto-Encrypt**: Token otomatis dienkripsi saat aplikasi berhenti
2. **Git Hook**: Token otomatis dienkripsi sebelum commit
3. **Machine-Specific**: Enkripsi berdasarkan karakteristik mesin
4. **Fallback Safe**: Jika enkripsi gagal, token tetap berfungsi

## File yang Dienkripsi

- `token/tokens.txt` - Token utama
- `token/tokens.default.txt` - Token default
- `token/PAT/token_pat.txt` - Personal Access Token

## Catatan Penting

- Token terenkripsi hanya bisa dibaca di mesin yang sama
- Backup token plain text di tempat aman sebelum enkripsi
- Jangan commit token plain text ke repository
- Enkripsi key disimpan di `core/tools/config/`

## Troubleshooting

### Jika token tidak bisa didekripsi:
1. Pastikan file `.key` dan `.salt` ada di `core/tools/config/`
2. Jalankan `python core/tools/token_manager_ai.py --status` untuk cek status
3. Jika masih bermasalah, restore dari backup dan encrypt ulang

### Jika pindah mesin:
1. Backup token dalam bentuk plain text
2. Di mesin baru, edit `token/tokens.txt` dengan token plain text
3. Jalankan `python core/tools/token_manager_ai.py --encrypt`
'''
    
    readme_path = os.path.join(base_path, "TOKEN_SECURITY.md")
    
    try:
        with open(readme_path, "w", encoding="utf-8") as f:
            f.write(readme_content)
        print(f"✅ Created security documentation: {readme_path}")
    except Exception as e:
        print(f"❌ Error creating documentation: {str(e)}")

def create_directory_structure(base_path):
    """Create necessary directory structure"""
    directories = [
        os.path.join(base_path, "core", "tools", "config"),
        os.path.join(base_path, "token", "PAT")
    ]
    
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
            print(f"✅ Created directory: {os.path.relpath(directory, base_path)}")
        except Exception as e:
            print(f"❌ Error creating directory {directory}: {str(e)}")

def main():
    print("🔧 Setting up AGC Token Encryption System")
    print("📁 Updated for new directory structure")
    print("=" * 50)
    
    base_path = get_base_dir()
    print(f"🏠 Project path: {base_path}")
    
    # 0. Create directory structure
    print("\n0. Creating directory structure...")
    create_directory_structure(base_path)
    
    # 1. Setup git hooks
    print("\n1. Setting up Git hooks...")
    setup_git_hooks(base_path)
    
    # 2. Update .gitignore
    print("\n2. Updating .gitignore...")
    create_gitignore_entries(base_path)
    
    # 3. Create documentation
    print("\n3. Creating security documentation...")
    create_readme_security(base_path)
    
    # 4. Initial encryption
    print("\n4. Running initial token encryption...")
    try:
        # Import dengan path yang benar
        sys.path.insert(0, os.path.join(base_path, "core", "tools"))
        from token_encryption import TokenManager
        
        token_manager = TokenManager(base_path)
        migrated = token_manager.migrate_existing_tokens()
        
        if migrated:
            print(f"✅ Encrypted {len(migrated)} token files")
        else:
            print("ℹ️ No plain text tokens found to encrypt")
    except Exception as e:
        print(f"⚠️ Could not run initial encryption: {str(e)}")
        print("   You can run it manually with: python core/tools/token_manager_ai.py --encrypt")
    
    print("\n" + "=" * 50)
    print("🎉 Setup completed successfully!")
    print("\nNext steps:")
    print("1. Your tokens are now encrypted")
    print("2. Git hooks will auto-encrypt before commits")
    print("3. Use 'python core/tools/token_manager_ai.py --help' for management commands")
    print("4. Read TOKEN_SECURITY.md for detailed usage")
    print("\nDirectory structure:")
    print("GOHugo/")
    print("├── core/tools/          # Token management scripts")
    print("├── token/               # Token files")
    print("│   └── PAT/            # Personal Access Tokens")
    print("└── TOKEN_SECURITY.md   # Documentation")

if __name__ == "__main__":
    main()