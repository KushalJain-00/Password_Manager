# Changelog

All notable changes to this project will be documented in this file.

## [2.0.0] - 2026-02-18

### Added
- 🎨 Professional UI with banner and clean layout
- ✨ Screen clearing for better user experience
- ⌨️ Typewriter effect on startup and exit
- 📊 Vault status indicator showing password count
- 🎯 Press Enter to continue after each action
- 🗑️ Number-based deletion (easier than UUID)
- ⚠️ Enhanced delete confirmation showing full entry details
- 💫 Smooth exit animation with vault locking message
- 🪟 Windows batch file launcher for double-click execution
- 🎨 Color-coded helper functions (success, error, warning, info)

### Changed
- Improved menu layout with better spacing
- Enhanced visual feedback throughout application
- Better error messages with consistent formatting
- Reorganized code with helper functions for UI elements

### Security
- ✅ Maintained PBKDF2 with 100,000 iterations
- ✅ Timing attack protection with hmac.compare_digest
- ✅ UUID-based entry identification
- ✅ Platform-specific secure password input

## [1.0.0] - 2026-02-13

### Added
- 🔐 Master password authentication system
- 🔑 Password storage with encryption (Fernet/AES-128)
- ➕ Add new password entries
- 👀 View all stored passwords
- 🔍 Search passwords by website or username
- 🗑️ Delete password entries
- 💾 Encrypted vault storage (vault.json)
- 🔐 Master password hash storage (master.key)
- 🧪 Unit tests for core functionality
- 🪟 Windows-specific password input with asterisks

### Security Features
- AES-128 encryption via Fernet
- PBKDF2-HMAC-SHA256 key derivation with 100,000 iterations
- Constant-time password comparison (timing attack protection)
- Random 32-byte salt for master password
- UUID4 for entry identification (no collision risk)
- Zero-knowledge architecture (master password never stored)

### Technical
- Python 3.7+ compatibility
- Cross-platform support (Windows/Linux/Mac)
- Comprehensive error handling
- Encrypted file I/O
- Platform-specific secure input

## [0.1.0] - 2026-02-13 (Initial Development)

### Added
- Basic password storage concept
- Encryption research and implementation
- Initial file structure
- Core security patterns

---

## Version Numbering

This project follows [Semantic Versioning](https://semver.org/):
- **MAJOR** version for incompatible changes
- **MINOR** version for new functionality (backwards compatible)
- **PATCH** version for backwards compatible bug fixes

## Future Releases

### [3.0.0] - Planned
- Password generator
- Password strength meter
- Clipboard integration
- Export/import functionality

### [3.1.0] - Planned
- Password expiry warnings
- Backup and restore
- Change master password feature

### [4.0.0] - Future
- Two-factor authentication
- Browser extension
- Cloud sync with zero-knowledge encryption
