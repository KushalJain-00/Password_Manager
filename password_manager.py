import os
import sys
import json
import hashlib
import base64
import hmac
import time
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
            print(f"❌ Error verifying password: {e}")
            return False
#=================================================================Create Master Password=================================================================    
    def create_master_password(self):
        print("\n" + "="*60)
        print("🔐 CREATE MASTER PASSWORD")
        print("="*60)
        print("\nThis password will protect ALL your passwords.")
        print("⚠️  If you forget it, you CANNOT recover your data!")
        print("\nRequirements:")
        print("  • At least 8 characters")
        print("  • Mix of letters, numbers, symbols")
        print("  • Use at least one uppercase letter, one lowercase letter, and one number")
        print()

        while True:
            password = secure_input("Enter master password: ")
            check = all([len(password) >= 8,
                         any(c.islower() for c in password),
                         any(c.isupper() for c in password),
                         any(c.isdigit() for c in password), 
                         any(not c.isalnum() for c in password)]) 
            
            if not check: 
                print("❌ Password does not meet requirements. Try again.\n") 
                continue
            confirm = secure_input("Confirm master password: ")
            if password != confirm:
                print("❌ Passwords don't match!")
                continue

            salt = os.urandom(SALT_SIZE)
            password_hash = self.hash_password(password , salt)
            data = {
                'salt': salt.hex(),
                'hash': password_hash.hex()
            }
            with open(MASTER_FILE , "w") as f:
                json.dump(data , f)
            print("✅ Master password created successfully!")
            return password
#=================================================================Login=================================================================
    def login(self):
        print("\n" + "="*60)
        print("🔑 LOGIN")
        print("="*60)

        attempts = 3
        while attempts > 0:
            password = secure_input("Enter master password: ")               
            if self.verify_master_password(password):
                print("✅ Login successful!")
                return password
            else:
                attempts -= 1
                if attempts > 0:
                    print(f"❌ Incorrect password! {attempts} attempt(s) remaining.")
                else:
                    print("❌ Too many failed attempts. Exiting for security.")
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
            print("❌ Error: Unable to decrypt vault — wrong master password or corrupted vault.")
            return None
        except Exception as e:
            print(f"❌ Error loading vault: {e}")
            return None
#=================================================================Save Vault=================================================================    
    def save_vault(self):

        try:
            json_data = json.dumps(self.vault , indent = 2)
            encrypted_data = self.fernet.encrypt(json_data.encode('utf-8'))
            with open(VAULT_FILE , "wb") as f:
                f.write(encrypted_data)
            print("✅ Vault saved successfully!")
        except Exception as e:
            print(f"❌ Error saving vault: {e}")
"""=================================================================Password Manager Class================================================================="""
class PasswordManager:
    def __init__(self , vault , fernet):

        self.vault = vault
        self.fernet = fernet
#=================================================================Add Password=================================================================    
    def add_password(self):
        print("\n" + "="*60)
        print("➕ ADD PASSWORD")
        print("="*60)

        website = input("\nWebsite/Service: ").strip()
        if not website:
            print("❌ Website cannot be empty!")
            return
        username = input("Username/Email: ").strip()
        if not username:
            print("❌ Username cannot be empty!")
            return
        password = secure_input("Password: ")
        if not password:
            print("❌ Password cannot be empty!")
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
#=================================================================View Password=================================================================
    def view_passwords(self):
        if not self.vault:
            print("\n⚠️  No passwords stored yet!")
            return
        print("\n" + "="*60)
        print("🔍 VIEW PASSWORDS")
        print("="*60)

        for entry in self.vault:
            print(f"\nID: {entry['id']}")
            print(f"Website: {entry['website']}")
            print(f"Username: {entry['username']}")
            print(f"Password: {entry['password']}")
            if entry['notes']:
                print(f"Notes: {entry['notes']}")
#=================================================================Search Password=================================================================  
    def search_passwords(self):
        if not self.vault:
            print("\n⚠️  No passwords stored yet!")
            return
        
        query = input("\nEnter website or username to search: ").strip().lower()
        if not query:
            print("❌ Search query cannot be empty!")
            return
        results = [entry for entry in self.vault if query in entry['website'].lower() or query in entry['username'].lower()]
        if results:
            print(f"\n✅ Found {len(results)} matching entries:")
            for entry in results:
                print(f"\nID: {entry['id']}")
                print(f"Website: {entry['website']}")
                print(f"Username: {entry['username']}")
                print(f"Password: {entry['password']}")
                if entry['notes']:
                    print(f"Notes: {entry['notes']}")
        else:
            print("\n⚠️  No matching entries found!")
#=================================================================Delete Password=================================================================  
    def delete_password(self):
        if not self.vault:
            print("\n⚠️  No passwords stored yet!")
            return
        self.view_passwords()

        try:
            entry_id = input("\nEnter ID to delete (0 to cancel): ").strip()
            if entry_id == '0':
                print("❌ Deletion cancelled.")
                return
            entry = next((e for e in self.vault if e['id'] == entry_id) , None)
            if not entry:
                print("❌ Invalid ID!")
                return
            confirm = input(f"Are you sure you want to delete entry for {entry['website']}? (y/n): ").strip().lower()
            if confirm == 'y':
                self.vault.remove(entry)
                vault_obj = Vault(self.fernet , self.vault)
                vault_obj.save_vault()
                print(f"✅ Password for {entry['website']} deleted!")
            else:
                print("❌ cancelled.")
        except ValueError:
            print("❌ Invalid input!")
"""=================================================================Main Menu================================================================="""
def main_menu(vault , fernet):
    while True:
        print("\n" + "="*60)
        print("🔐 PASSWORD MANAGER")
        print("="*60)
        print("\n1. Add Password")
        print("2. View All Passwords")
        print("3. Search Password")
        print("4. Delete Password")
        print("5. Exit")

        choice = input("\nEnter your choice: ").strip()
        pm = PasswordManager(vault , fernet)

        if choice == '1':
            pm.add_password()
        elif choice == '2':
            pm.view_passwords()
        elif choice == '3':
            pm.search_passwords()
        elif choice == '4':
            pm.delete_password()
        elif choice == '5':
            print("\n👋 Goodbye! Your passwords are secure.")
            break
        else:
            print("❌ Invalid choice!")
"""=================================================================Main Function================================================================="""
def main():
    print("\n" + "="*60)
    print("🔐 SECURE PASSWORD MANAGER v1.0")
    print("="*60)

    if not os.path.exists(MASTER_FILE):
        print("\n👋 Welcome! Let's set up your password manager.")
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

        print("\n❌ Failed to load vault. Exiting.")
        return
    
    print(f"\n✅ Loaded {len(vault)} password(s)")

    main_menu(vault , fernet)

if __name__ == "__main__":
    main()