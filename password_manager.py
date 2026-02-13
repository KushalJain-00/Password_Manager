import os
import json
import hashlib
import base64
import time
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
#=================================================================Global=================================================================
Vault_File = 'vault.json'
Master_File = 'master.key'
SALT_SIZE = 32
"""=================================================================Master Password Class================================================================="""
class MasterPassword:
    def __init__(self , password , salt):

        self.password = password
        self.salt = salt
#=================================================================Hash Password=================================================================
    def hash_password(self , password , salt):
        return hashlib.pbkdf2_hmac('sha256' , password.encode('utf-8') , salt , 100000)
#=================================================================Verify Password=================================================================
    def verify_master_password(self , password):
        if not os.path.exists(Master_File):
            return False
        try:
            with open(Master_File , "r") as f:
                data = json.load(f)
            salt = bytes.fromhex(data['salt'])
            stored_hash = bytes.fromhex(data['hash'])
            password_hash = self.hash_password(password , salt)

            return password_hash == stored_hash
        
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
            password = getpass("Enter master password: ")
            check = all([len(password) >= 8,
                         any(c.islower() for c in password),
                         any(c.isupper() for c in password),
                         any(c.isdigit() for c in password), 
                         any(not c.isalnum() for c in password)]) 
            
            if not check: 
                print("❌ Password does not meet requirements. Try again.\n") 
                continue
            confirm = getpass("Confirm master password: ")
            if password != confirm:
                print("❌ Passwords don't match!")
                continue

            salt = os.urandom(SALT_SIZE)
            password_hash = self.hash_password(password , salt)
            data = {
                'salt': salt.hex(),
                'hash': password_hash.hex()
            }
            with open(Master_File , "w") as f:
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
            password = getpass("Enter master password: ")               
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
    def __init__(self , password , salt):

        self.password = password
        self.salt = salt
#=================================================================Derive Key=================================================================
    def derive_key(self , password , salt):

        kdf = PBKDF2HMAC(algorithm = hashes.SHA256(), length = 32, salt = salt, iterations = 100000)
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        
        return key
#=================================================================Get Encryption Key=================================================================    
    def get_encryption_key(self , password):

        with open(Master_File, 'r') as f:
            data = json.load(f)
    
        salt = bytes.fromhex(data['salt'])
        key = self.derive_key(password, salt)
        
        return Fernet(key)
"""=================================================================Vault Class================================================================="""    
class Vault:
    def __init__(self , fernet):

        self.fernet = fernet
#=================================================================Load Vault=================================================================
    def load_vault(self , fernet):
        if not os.path.exists(Vault_File):
            return []
        try:
            with open(Vault_File , "rb") as f:
                encrypted_data = f.read()
            
            decrypted_data = fernet.decrypt(encrypted_data)

            vault = json.loads(decrypted_data.decode("utf-8"))
            return vault
        
        except Exception as e:
            print(f"❌ Error loading vault: {e}")
            return []
#=================================================================Save Vault=================================================================    
    def save_vault(self , vault , fernet):

        try:
            json_data = json.dumps(vault , indent = 2)
            encrypted_data = fernet.encrypt(json_data.encode('utf-8'))
            with open(Vault_File , "wb") as f:
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
    def add_password(self , vault , fernet):
        print("\n" + "="*60)
        print("➕ ADD PASSWORD")
        print("="*60)

        website = input("\nWebsite/Service:").strip()
        if not website:
            print("❌ Website cannot be empty!")
            return
        username = input("Username/Email:").strip()
        if not username:
            print("❌ Username cannot be empty!")
            return
        password = getpass("Password:")
        if not password:
            print("❌ Password cannot be empty!")
            return
        notes = input("Notes (optional):").strip()

        entry = {
            'id' : len(vault) + 1,
            'website' : website,
            'username' : username,
            'password' : password,
            'notes' : notes
        }
        vault.append(entry)
        Vault.save_vault(vault , fernet)
#=================================================================View Password=================================================================
    def view_passwords(self , vault):
        if not vault:
            print("\n⚠️  No passwords stored yet!")
            return
        print("\n" + "="*60)
        print("🔍 VIEW PASSWORDS")
        print("="*60)

        for entry in vault:
            print(f"\nID: {entry['id']}")
            print(f"Website: {entry['website']}")
            print(f"Username: {entry['username']}")
            print(f"Password: {entry['password']}")
            if entry['notes']:
                print(f"Notes: {entry['notes']}")
#=================================================================Search Password=================================================================  
    def search_passwords(self , vault):
        if not vault:
            print("\n⚠️  No passwords stored yet!")
            return
        
        query = input("\nEnter website or username to search: ").strip().lower()
        if not query:
            print("❌ Search query cannot be empty!")
            return
        results = [entry for entry in vault if query in entry['website'].lower() or query in entry['username'].lower()]
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
    def delete_password(self , vault , fernet):
        if not vault:
            print("\n⚠️  No passwords stored yet!")
            return
        self.view_passwords(vault)

        try:
            entry_id = int(input("\nEnter ID to delete (0 to cancel): "))
            if entry_id == 0:
                print("❌ Deletion cancelled.")
                return
            entry = next((e for e in Vault if e['id'] == entry_id) , None)
            if not entry:
                print("❌ Invalid ID!")
                return
            confirm = input(f"Are you sure you want to delete entry for {entry['website']}? (y/n): ").strip().lower()
            if confirm == 'y':
                vault.remove(entry)
                Vault.save_vault(vault , fernet)
                print(f"✅ Password for {entry['website']} deleted!")
            else:
                print("❌ cancelled.")
        except ValueError:
            print("❌ Invalid input!")
"""=================================================================Main Menu================================================================="""
def main_menu(vault , fernet):
    print("\n" + "="*60)
    print("🔐 PASSWORD MANAGER")
    print("="*60)
    print("\n1. Add Password")
    print("2. View All Passwords")
    print("3. Search Password")
    print("4. Delete Password")
    print("5. Exit")

    choice = input("\nEnter your choice: ").strip()

    if choice == '1':
        PasswordManager.add_password(vault, fernet)
    elif choice == '2':
        PasswordManager.view_passwords(vault)
    elif choice == '3':
        PasswordManager.search_passwords(vault)
    elif choice == '4':
        PasswordManager.delete_password(vault, fernet)
    elif choice == '5':
        print("\n👋 Goodbye! Your passwords are secure.")
        return
    else:
        print("❌ Invalid choice!")
"""=================================================================Main Function================================================================="""
def main():
    print("\n" + "="*60)
    print("🔐 SECURE PASSWORD MANAGER v1.0")
    print("="*60)

    if not os.path.exists(Master_File):
        print("\n👋 Welcome! Let's set up your password manager.")
        master_password = MasterPassword.create_master_password(self = None)
        if not master_password:
            return
    else:
        master_password = MasterPassword.login()
        if not master_password:
            return
    
    fernet = Encryption.get_encryption_key(master_password)
    vault = Vault.load_vault(fernet)
    print(f"\nLoaded {len(vault)} password(s)")

    main_menu(vault , fernet)

if __name__ == "__main__":
    main()