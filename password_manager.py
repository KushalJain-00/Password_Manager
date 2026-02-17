import os
import sys
import json
import time
import hashlib
import base64
import hmac
import uuid
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
#=================================================================GETPASS Workaround===========================================================
# Windows-specific password input with hidden characters
if sys.platform == "win32":
    import msvcrt
    
    def secure_input(prompt=""):
        """Read password input without echoing (Windows)"""
        if prompt:
            print(prompt, end="", flush=True)
        password = ""
        while True:
            char = msvcrt.getch()
            if char == b'\r' or char == b'\n':  # Enter key
                print()  # New line after input
                break
            elif char == b'\x08':  # Backspace
                if password:
                    password = password[:-1]
                    print('\b \b', end="", flush=True)
            else:
                password += char.decode('utf-8')
                print('*', end="", flush=True)
        return password
else:
    from getpass import getpass
    def secure_input(prompt=""):
        """Fall back to getpass on non-Windows systems"""
        return getpass(prompt)
#=================================================================Global=================================================================
VAULT_FILE = 'vault.json'
MASTER_FILE = 'master.key'
SALT_SIZE = 32

def clear_screen():
    os.system('cls' if sys.platform == "win32" else 'clear')

def print_slow(text , delay = 0.02):
    for char in text:
        print(char , end = "" , flush = True)
        time.sleep(delay)
    print()

def print_banner():
    clear_screen()
    banner = """
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║           🔐  SECURE PASSWORD MANAGER  🔐                ║
║                        v2.0                              ║
║                                                          ║
║          Your passwords. Encrypted. Safe.                ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
"""
    print(banner)

def print_separator():
    print("-"*60)

def print_success(msg):
    print(f"\n  ✅  {msg}")

def print_error(msg):
    print(f"\n  ❌  {msg}")

def print_warning(msg):
    print(f"\n  ⚠️   {msg}")

def print_info(msg):
    print(f"\n  ℹ️   {msg}")

def press_enter():
    """Wait for user to press Enter"""
    input("\n  Press Enter to continue...")
"""=================================================================Master Password Class================================================================="""
class MasterPassword:
    def __init__(self, password, salt):

        self.password = password
        self.salt = salt
#=================================================================Hash Password=================================================================
    def hash_password(self, password=None, salt=None):
        pwd = password if password is not None else self.password
        slt = salt if salt is not None else self.salt
        return hashlib.pbkdf2_hmac('sha256' , pwd.encode('utf-8') , slt , 100000)
#=================================================================Verify Password=================================================================
    def verify_master_password(self, password):
        if not os.path.exists(MASTER_FILE):
            return False
        try:
            with open(MASTER_FILE , "r") as f:
                data = json.load(f)
            salt = bytes.fromhex(data['salt'])
            stored_hash = bytes.fromhex(data['hash'])
            temp_mp = MasterPassword(password, salt)
            password_hash = temp_mp.hash_password()

            return hmac.compare_digest(password_hash, stored_hash)
        
        except Exception as e:
            print_error(f"Error verifying password: {e}")
            return False
#=================================================================Create Master Password=================================================================    
    def create_master_password(self):
        clear_screen()
        print_banner()
        print("  🔐  FIRST TIME SETUP")
        print_separator()
        print("""
            Welcome to Secure Password Manager!

            You need to create a MASTER PASSWORD.
            This is the ONE password that protects all your others.

            ⚠️  WARNING: If you forget this password,
                your data CANNOT be recovered!

            Requirements:
                • At least 8 characters
                • One uppercase letter  (A-Z)
                • One lowercase letter  (a-z)
                • One number            (0-9)
                • One special character (!@#$...)
            """)
        print_separator()

        while True:
            password = secure_input("Enter master password: ")
            check = all([len(password) >= 8,
                         any(c.islower() for c in password),
                         any(c.isupper() for c in password),
                         any(c.isdigit() for c in password), 
                         any(not c.isalnum() for c in password)]) 
            
            if not check: 
                print_error("Password does not meet requirements. Try again.")
                continue
            confirm = secure_input("Confirm master password: ")
            if password != confirm:
                print_error("Passwords don't match!")
                continue

            salt = os.urandom(SALT_SIZE)
            password_hash = self.hash_password(password , salt)
            data = {
                'salt': salt.hex(),
                'hash': password_hash.hex()
            }
            with open(MASTER_FILE , "w") as f:
                json.dump(data , f)
            print_success("Master password created successfully!")
            return password
#=================================================================Login=================================================================
    def login(self):
        clear_screen()
        print_banner()
        print("  🔑  LOGIN")
        print_separator()
        print("\nEnter your master password to unlock your vault.\n")

        attempts = 3
        while attempts > 0:
            password = secure_input("Enter master password: ")               
            if self.verify_master_password(password):
                print_success("Login successful!")
                return password
            else:
                attempts -= 1
                if attempts > 0:
                    print_error(f"Incorrect password! {attempts} attempt(s) remaining.")
                else:
                    print_error("Too many failed attempts. Exiting for security.")
                    return None
        return None
"""=================================================================Encryption Class================================================================="""
class Encryption:   
    def __init__(self, password, salt):

        self.password = password
        self.salt = salt
#=================================================================Derive Key=================================================================
    def derive_key(self):

        kdf = PBKDF2HMAC(algorithm = hashes.SHA256(), length = 32, salt = self.salt, iterations = 100000)
        key = base64.urlsafe_b64encode(kdf.derive(self.password.encode()))
        
        return key
#=================================================================Get Encryption Key=================================================================    
    def get_encryption_key(self):

        with open(MASTER_FILE, 'r') as f:
            data = json.load(f)
    
        self.salt = bytes.fromhex(data['salt'])
        key = self.derive_key()
        
        return Fernet(key)
"""=================================================================Vault Class================================================================="""    
class Vault:
    def __init__(self, fernet, vault = None):

        self.fernet = fernet
        self.vault = vault if vault is not None else []
#=================================================================Load Vault=================================================================
    def load_vault(self):
        if not os.path.exists(VAULT_FILE):
            return []
        try:
            with open(VAULT_FILE , "rb") as f:
                encrypted_data = f.read()
            decrypted_data = self.fernet.decrypt(encrypted_data)
            vault = json.loads(decrypted_data.decode("utf-8"))
            return vault
        except InvalidToken:
            print_error("Error: Unable to decrypt vault — wrong master password or corrupted vault.")
            return None
        except Exception as e:
            print_error(f"Error loading vault: {e}")
            return None
#=================================================================Save Vault=================================================================    
    def save_vault(self):

        try:
            json_data = json.dumps(self.vault , indent = 2)
            encrypted_data = self.fernet.encrypt(json_data.encode('utf-8'))
            with open(VAULT_FILE , "wb") as f:
                f.write(encrypted_data)
            print_success("Vault saved successfully!")
        except Exception as e:
            print(f"Error saving vault: {e}")
"""=================================================================Password Manager Class================================================================="""
class PasswordManager:
    def __init__(self , vault , fernet):

        self.vault = vault
        self.fernet = fernet
#=================================================================Add Password=================================================================    
    def add_password(self):
        clear_screen()
        print_banner()
        print("  ➕  ADD NEW PASSWORD")
        print_separator()
        print()

        website = input("\nWebsite/Service: ").strip()
        if not website:
            print_error("Website cannot be empty!")
            press_enter()
            return
        username = input("Username/Email: ").strip()
        if not username:
            print_error("Username cannot be empty!")
            press_enter()
            return
        password = secure_input("Password: ")
        if not password:
            print_error("Password cannot be empty!")
            press_enter()
            return
        notes = input("Notes (optional): ").strip()

        entry = {
            'id' : str(uuid.uuid4()),
            'website' : website,
            'username' : username,
            'password' : password,
            'notes' : notes
        }
        self.vault.append(entry)
        vault_obj = Vault(self.fernet , self.vault)
        vault_obj.save_vault()

        print_success(f"Password for '{website}' saved successfully!")
        press_enter()
#=================================================================View Password=================================================================
    def view_passwords(self):
        clear_screen()
        print_banner()
        print("  🔍  ALL PASSWORDS")
        print_separator()

        if not self.vault:
            print_warning("No passwords stored yet!")
            press_enter()
            return

        print(f"\n  Total entries: {len(self.vault)}\n")
        print_separator()

        for i, entry in enumerate(self.vault, 1):
            print(f"\n  [{i}] {entry['website'].upper()}")
            print(f"      Username : {entry['username']}")
            print(f"      Password : {entry['password']}")
            if entry['notes']:
                print(f"      Notes    : {entry['notes']}")
            print(f"      ID       : {entry['id'][:8]}...")
            print_separator()

        press_enter()
#=================================================================Search Password=================================================================  
    def search_passwords(self):

        clear_screen()
        print_banner()
        print("  🔎  SEARCH PASSWORDS")
        print_separator()
        print()

        if not self.vault:
            print_warning("No passwords stored yet!")
            press_enter()
            return
        query = input("\nEnter website or username to search: ").strip().lower()
        if not query:
            print_error("Search query cannot be empty!")
            press_enter()
            return
        results = [entry for entry in self.vault if query in entry['website'].lower() or query in entry['username'].lower()]
        print()
        print_separator()
        if results:
            print(f"\n  ✅  Found {len(results)} result(s) for '{query}':\n")
            print_separator()
            for i, entry in enumerate(results, 1):
                print(f"\n  [{i}] {entry['website'].upper()}")
                print(f"      Username : {entry['username']}")
                print(f"      Password : {entry['password']}")
                if entry['notes']:
                    print(f"      Notes    : {entry['notes']}")
                print_separator()
        else:
            print_warning(f"No results found for '{query}'")
        press_enter()
#=================================================================Delete Password=================================================================  
    def delete_password(self):

        clear_screen()
        print_banner()
        print("  🗑️   DELETE PASSWORD")
        print_separator()
        if not self.vault:
            print_warning("No passwords stored yet!")
            press_enter()
            return
        
        print(f"\n  Total entries: {len(self.vault)}\n")
        print_separator()
        for i, entry in enumerate(self.vault, 1):
            print(f"  [{i}] {entry['website']} | {entry['username']}")
        print_separator()
        print()

        try:
            entry_id = input("\nEnter ID to delete (0 to cancel): ").strip()
            if entry_id == '0':
                print_error("Deletion cancelled.")
                press_enter()
                return
            index = int(entry_id) - 1
            if index < 0 or index >= len(self.vault):
                print_error("Invalid ID")
                press_enter()
                return
            entry = self.vault[index]
            print(f"\n  ⚠️  You are about to delete:")
            print(f"      Website  : {entry['website']}")
            print(f"      Username : {entry['username']}")
            if entry['notes']:
                print(f"      Notes    : {entry['notes']}")
            print()
            confirm = input("  Are you sure? (yes/no): ").strip().lower()
            if confirm == 'yes':
                self.vault.remove(entry)
                vault_obj = Vault(self.fernet , self.vault)
                vault_obj.save_vault()
                print_success(f"Password for {entry['website']} deleted!")
            else:
                print_info("Deletion cancelled.")
        except ValueError:
            print_error("Invalid input!")
        press_enter()
"""=================================================================Main Menu================================================================="""
def main_menu(vault , fernet):
    pm = PasswordManager(vault , fernet)
    while True:
        clear_screen()
        print_banner()
        print(f"  📊  Vault Status: {len(vault)} password(s) stored")
        print()
        print_separator()
        print("""
            MAIN MENU

                1. Add New Password
                2. View All Passwords
                3. Search Passwords
                4. Delete Password
                5. Exit
            """)
        print_separator()
        print()

        choice = input("\nEnter your choice: ").strip()
        if choice == '1':
            pm.add_password()
        elif choice == '2':
            pm.view_passwords()
        elif choice == '3':
            pm.search_passwords()
        elif choice == '4':
            pm.delete_password()
        elif choice == '5':
            clear_screen()
            print_banner()
            print_slow("  👋  Locking vault and exiting...", delay=0.04)
            time.sleep(1)
            clear_screen()
            break
        else:
            print_error("Invalid choice!")
            time.sleep(1)
"""=================================================================Main Function================================================================="""
def main():
    print("\n" + "="*60)
    print("🔐 SECURE PASSWORD MANAGER v1.0")
    print("="*60)

    if not os.path.exists(MASTER_FILE):
        mp = MasterPassword("", b"")
        master_password = mp.create_master_password()
        if not master_password:
            return
    else:
        mp = MasterPassword("", b"")
        master_password = mp.login()
        if not master_password:
            return
    enc = Encryption(master_password, b"")
    fernet = enc.get_encryption_key()
    vault_obj = Vault(fernet)
    vault = vault_obj.load_vault()
    if vault is None:
        print_error("Failed to load vault. Exiting.")
        time.sleep(2)
        return
    main_menu(vault , fernet)

if __name__ == "__main__":
    main()