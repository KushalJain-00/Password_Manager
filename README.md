# 🔐 Secure Password Manager

A production-ready, terminal-based password manager with military-grade encryption and professional user interface. One master password protects all your credentials with zero-knowledge architecture.

![Python Version](https://img.shields.io/badge/python-3.7%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Security](https://img.shields.io/badge/security-AES--128-red)
![Status](https://img.shields.io/badge/status-production--ready-success)

## ✨ Features

### 🔒 Security
- **Military-Grade Encryption** - AES-128 via Fernet symmetric encryption
- **PBKDF2 Key Derivation** - 100,000 iterations for maximum security
- **Timing Attack Protection** - Constant-time password comparison with `hmac.compare_digest`
- **Zero-Knowledge Architecture** - Your master password is never stored
- **UUID-Based Identification** - Globally unique entry IDs, no collision risk

### 💻 User Experience
- **Double-Click Launcher** - Windows batch file for easy startup
- **Professional UI** - Beautiful banner, clean layout, smooth animations
- **Platform-Specific Input** - Windows password masking with asterisks
- **Clear Visual Feedback** - Color-coded success/error messages
- **Smooth Transitions** - Screen clearing and typewriter effects

### 🎯 Functionality
- **Add Passwords** - Store website, username, password, and notes
- **View All** - List all stored credentials with organized display
- **Search** - Find passwords by website or username
- **Delete** - Remove entries with confirmation dialog
- **Encrypted Storage** - All data encrypted before saving to disk

## 🖼️ Preview

```
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║           🔐  SECURE PASSWORD MANAGER  🔐                ║
║                        v2.0                              ║
║                                                          ║
║          Your passwords. Encrypted. Safe.                ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝

  📊  Vault Status: 5 password(s) stored

  ────────────────────────────────────────────────────

  MAIN MENU

    1. Add New Password
    2. View All Passwords
    3. Search Passwords
    4. Delete Password
    5. Exit

  ────────────────────────────────────────────────────
```

## 🚀 Quick Start

### Prerequisites
- Python 3.7 or higher
- pip package manager

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/YOUR-USERNAME/password-manager.git
   cd password-manager
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**

   **Windows (Easy):**
   ```bash
   # Double-click PasswordManager.bat
   ```

   **Or run directly:**
   ```bash
   python password_manager.py
   ```

   **Linux/Mac:**
   ```bash
   python3 password_manager.py
   ```

### First Time Setup

On first run, you'll create your **master password**:

```
Requirements:
  • At least 8 characters
  • One uppercase letter (A-Z)
  • One lowercase letter (a-z)
  • One number (0-9)
  • One special character (!@#$...)
```

⚠️ **CRITICAL:** If you forget your master password, your data **CANNOT** be recovered!

## 📖 Usage Guide

### Adding a Password

1. Select **"1. Add New Password"** from menu
2. Enter website/service name (e.g., "github.com")
3. Enter username/email
4. Enter password (hidden with asterisks)
5. Add optional notes
6. Password saved and encrypted automatically ✅

### Viewing Passwords

```
  [1] GITHUB.COM
      Username : kushal@gmail.com
      Password : MySecurePass123!
      Notes    : Work account
      ID       : 3f4a9b2c...
  ────────────────────────────────────────────────────
```

### Searching

Enter any part of a website name or username to find matching entries.

### Deleting

Select entry by number, confirm deletion with "yes" (requires full word for safety).

## 🔧 Technical Details

### Encryption Specification

| Component | Implementation |
|-----------|---------------|
| **Symmetric Encryption** | Fernet (AES-128 CBC + HMAC) |
| **Key Derivation** | PBKDF2-HMAC-SHA256, 100,000 iterations |
| **Master Password Hash** | PBKDF2-HMAC-SHA256 with random 32-byte salt |
| **Password Comparison** | Constant-time with `hmac.compare_digest()` |
| **Entry IDs** | UUID4 (128-bit random identifiers) |

### File Structure

```
password-manager/
├── password_manager.py      # Main application
├── PasswordManager.bat      # Windows launcher
├── test_password_manager.py # Unit tests
├── requirements.txt         # Python dependencies
├── .gitignore              # Git ignore rules
├── vault.json              # Encrypted password storage (auto-created)
└── master.key              # Master password hash (auto-created)
```

### Data Storage

**vault.json** - Encrypted with Fernet
```json
// Encrypted format (example - actual data is binary)
gAAAAABh3R7f8KqY9Zx4m2k...
```

**master.key** - Master password verification
```json
{
  "salt": "hex_encoded_32_byte_salt",
  "hash": "hex_encoded_password_hash"
}
```

## 🛡️ Security Features

### What Makes This Secure?

1. **Military-Grade Encryption**
   - AES-128 is approved by NSA for TOP SECRET data
   - Fernet provides authenticated encryption (detects tampering)

2. **Proper Key Derivation**
   - PBKDF2 with 100,000 iterations slows brute-force attacks
   - Each password derivation takes ~100ms (intentionally slow)

3. **Timing Attack Protection**
   - Uses `hmac.compare_digest()` for constant-time comparison
   - Prevents attackers from deducing password through timing analysis

4. **Zero-Knowledge Architecture**
   - Master password never stored in any form
   - Only a salted hash for verification
   - Even with both files, data is useless without master password

5. **UUID Entry IDs**
   - No collision risk from deletions
   - Cryptographically secure random identifiers

### What This Protects Against

| Attack Type | Protection |
|-------------|-----------|
| Brute Force | ✅ 100,000 iteration PBKDF2 |
| Dictionary Attack | ✅ Password strength requirements |
| Rainbow Tables | ✅ Unique random salt per password |
| Timing Attacks | ✅ Constant-time comparison |
| File Theft | ✅ Strong encryption, no plaintext |
| Tampering | ✅ Authenticated encryption (HMAC) |

### What This Does NOT Protect Against

- ❌ **Keyloggers/Malware** - If your system is compromised, no password manager can help
- ❌ **Shoulder Surfing** - Be aware of your surroundings when entering passwords
- ❌ **Forgotten Master Password** - Zero-knowledge = zero recovery possible

## 🧪 Testing

Run the test suite:

```bash
# Install pytest if needed
pip install pytest

# Run tests
pytest test_password_manager.py -v

# Expected output
test_password_manager.py::test_hash_password_same_input_same_hash PASSED
test_password_manager.py::test_verify_master_password PASSED
test_password_manager.py::test_key_derivation_same_password_same_key PASSED
test_password_manager.py::test_save_and_load PASSED
test_password_manager.py::test_search_passwords PASSED
...

========================== 10 passed ==========================
```

## 📋 Requirements

```
cryptography>=41.0.0  # Fernet encryption
```

**Optional for development:**
```
pytest>=7.4.0        # Testing framework
```

## 🎨 Customization

### Change Terminal Colors (Windows)

Edit `PasswordManager.bat`:
```batch
color 0A   ← Current (green text)
color 0B   ← Cyan text
color 0C   ← Red text
color 0E   ← Yellow text
```

### Add Custom Icon

1. Right-click `PasswordManager.bat` → Create Shortcut
2. Right-click Shortcut → Properties → Change Icon
3. Select any `.ico` file
4. Place shortcut on desktop!

## 🐛 Troubleshooting

### "Module 'cryptography' not found"
```bash
pip install cryptography
```

### "Can't open file password_manager.py"
Make sure `PasswordManager.bat` and `password_manager.py` are in the same folder.

### Forgot Master Password
Unfortunately, there is **no recovery option**. This is by design (zero-knowledge security).

You'll need to:
1. Delete `master.key` and `vault.json`
2. Start fresh with a new master password
3. Re-add all your passwords

### Vault Won't Decrypt
Possible causes:
- Wrong master password
- Corrupted vault file
- File tampered with

The vault file includes integrity checking and will refuse to decrypt if tampered.

## 🗺️ Roadmap

**Completed ✅**
- [x] Master password authentication
- [x] Add/View/Search/Delete passwords
- [x] Encrypted storage
- [x] Professional UI
- [x] Windows batch launcher
- [x] Unit tests

**Future Enhancements 🚀**
- [ ] Password strength meter
- [ ] Random password generator
- [ ] Copy password to clipboard
- [ ] Export/Import functionality
- [ ] Password expiry warnings
- [ ] Two-factor authentication
- [ ] Browser extension
- [ ] Cloud sync (with zero-knowledge)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Areas for Contribution
- Password generator implementation
- Clipboard integration
- Additional tests
- Documentation improvements
- Cross-platform enhancements
- UI/UX improvements

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **cryptography** library by the Python Cryptographic Authority
- Inspired by LastPass, 1Password, and Bitwarden
- Built to demonstrate secure password storage principles

## 👨‍💻 Author

**Kushal Jain**
- GitHub: [@KushalJain-00](https://github.com/KushalJain-00)
- LinkedIn: [Kushal Jain](https://www.linkedin.com/in/kushal-jain-855293376)
- Email: harshilkushal100@gmail.com

## ⚠️ Disclaimer

This password manager is provided as-is for educational and personal use. While it implements industry-standard security practices, use at your own risk. For critical passwords, consider using established commercial solutions like Bitwarden, 1Password, or LastPass.

## 📊 Project Stats

- **Lines of Code:** ~460
- **Functions:** 20+
- **Security Features:** 5 layers
- **Test Coverage:** Core functionality
- **Development Time:** ~8 hours
- **Status:** Production Ready

## ⭐ Support

If you find this project helpful:
- Star this repository ⭐
- Share with friends
- Report bugs via [Issues](https://github.com/YOUR-USERNAME/password-manager/issues)
- Contribute improvements

---

**🔐 Your passwords. Encrypted. Safe. Always.** 🔐

*Remember: A password manager is only as secure as your master password. Choose wisely!*
