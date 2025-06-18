import os
import sys
import sqlite3
import string
import random
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
import base64

class PasswordVault:
    def __init__(self):
        self.key = None
        self.cipher = None
        self.db_path = "vault.db"
        self.setup_database()

    def setup_database(self):
        """Initialize the SQLite database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables if they don't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS master (
                id INTEGER PRIMARY KEY,
                salt BLOB,
                key BLOB
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY,
                site_name TEXT NOT NULL,
                username TEXT NOT NULL,
                password BLOB NOT NULL,
                notes TEXT
            )
        ''')
        
        conn.commit()
        conn.close()

    def generate_key(self, master_password: str, salt: bytes = None) -> bytes:
        """Generate encryption key from master password"""
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        return salt, key

    def setup_master_password(self, master_password: str):
        """Set up the master password for first time use"""
        salt, key = self.generate_key(master_password)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('INSERT INTO master (salt, key) VALUES (?, ?)', (salt, key))
        conn.commit()
        conn.close()
        
        self.key = key
        self.cipher = Fernet(key)

    def verify_master_password(self, master_password: str) -> bool:
        """Verify the master password and set up encryption"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT salt, key FROM master WHERE id = 1')
        result = cursor.fetchone()
        conn.close()

        if not result:
            return False

        salt, stored_key = result
        _, key = self.generate_key(master_password, salt)
        
        if key == stored_key:
            self.key = key
            self.cipher = Fernet(key)
            return True
        return False

    def add_credentials(self, site_name: str, username: str, password: str, notes: str = ""):
        """Add new credentials to the vault"""
        if not self.cipher:
            raise Exception("Master password not verified")

        encrypted_password = self.cipher.encrypt(password.encode())
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO credentials (site_name, username, password, notes) VALUES (?, ?, ?, ?)',
            (site_name, username, encrypted_password, notes)
        )
        conn.commit()
        conn.close()

    def get_credentials(self, site_name: str = None):
        """Retrieve credentials from the vault"""
        if not self.cipher:
            raise Exception("Master password not verified")

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if site_name:
            cursor.execute('SELECT * FROM credentials WHERE site_name LIKE ?', (f'%{site_name}%',))
        else:
            cursor.execute('SELECT * FROM credentials')
            
        credentials = cursor.fetchall()
        conn.close()

        decrypted_credentials = []
        for cred in credentials:
            id_, site, username, encrypted_password, notes = cred
            password = self.cipher.decrypt(encrypted_password).decode()
            decrypted_credentials.append({
                'id': id_,
                'site_name': site,
                'username': username,
                'password': password,
                'notes': notes
            })
        
        return decrypted_credentials

    def update_credentials(self, cred_id: int, site_name: str, username: str, password: str, notes: str):
        """Update existing credentials"""
        if not self.cipher:
            raise Exception("Master password not verified")

        encrypted_password = self.cipher.encrypt(password.encode())
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE credentials SET site_name=?, username=?, password=?, notes=? WHERE id=?',
            (site_name, username, encrypted_password, notes, cred_id)
        )
        conn.commit()
        conn.close()

    def delete_credentials(self, cred_id: int):
        """Delete credentials from the vault"""
        if not self.cipher:
            raise Exception("Master password not verified")

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM credentials WHERE id=?', (cred_id,))
        conn.commit()
        conn.close()

    def export_vault(self, export_path: str):
        """Export vault to an encrypted file"""
        if not self.cipher:
            raise Exception("Master password not verified")

        credentials = self.get_credentials()
        export_data = self.cipher.encrypt(str(credentials).encode())
        
        with open(export_path, 'wb') as f:
            f.write(export_data)

    @staticmethod
    def generate_password(length: int = 12):
        """Generate a strong random password"""
        chars = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(chars) for _ in range(length))

def print_menu():
    """Display the main menu"""
    print("\n======== Password Vault ========")
    print("1. Login")
    print("2. Add New Password")
    print("3. View All")
    print("4. Search")
    print("5. Update")
    print("6. Delete")
    print("7. Export")
    print("8. Generate Password")
    print("9. Exit")
    return input("Enter your choice: ")

def main():
    vault = PasswordVault()
    logged_in = False

    while True:
        choice = print_menu()

        if not logged_in and choice != '1' and choice != '9':
            print("\nPlease login first!")
            continue

        if choice == '1':
            if not logged_in:
                conn = sqlite3.connect(vault.db_path)
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM master')
                has_master = cursor.fetchone()[0] > 0
                conn.close()

                if not has_master:
                    print("\nFirst time setup - Create a master password")
                    master_pass = getpass("Enter new master password: ")
                    confirm_pass = getpass("Confirm master password: ")
                    
                    if master_pass == confirm_pass:
                        vault.setup_master_password(master_pass)
                        logged_in = True
                        print("Master password set successfully!")
                    else:
                        print("Passwords don't match!")
                else:
                    master_pass = getpass("Enter master password: ")
                    if vault.verify_master_password(master_pass):
                        logged_in = True
                        print("Login successful!")
                    else:
                        print("Invalid master password!")
            else:
                print("Already logged in!")

        elif choice == '2':
            site = input("Enter site name: ")
            username = input("Enter username: ")
            password = getpass("Enter password (or press enter to generate): ")
            if not password:
                password = vault.generate_password()
                print(f"Generated password: {password}")
            notes = input("Enter notes (optional): ")
            
            vault.add_credentials(site, username, password, notes)
            print("Credentials added successfully!")

        elif choice == '3':
            credentials = vault.get_credentials()
            if credentials:
                print("\nAll stored credentials:")
                for cred in credentials:
                    print(f"\nID: {cred['id']}")
                    print(f"Site: {cred['site_name']}")
                    print(f"Username: {cred['username']}")
                    print(f"Password: {cred['password']}")
                    if cred['notes']:
                        print(f"Notes: {cred['notes']}")
            else:
                print("No credentials found!")

        elif choice == '4':
            search_term = input("Enter site name to search: ")
            credentials = vault.get_credentials(search_term)
            if credentials:
                print("\nSearch results:")
                for cred in credentials:
                    print(f"\nID: {cred['id']}")
                    print(f"Site: {cred['site_name']}")
                    print(f"Username: {cred['username']}")
                    print(f"Password: {cred['password']}")
                    if cred['notes']:
                        print(f"Notes: {cred['notes']}")
            else:
                print("No matching credentials found!")

        elif choice == '5':
            cred_id = input("Enter credential ID to update: ")
            try:
                cred_id = int(cred_id)
                site = input("Enter new site name: ")
                username = input("Enter new username: ")
                password = getpass("Enter new password (or press enter to generate): ")
                if not password:
                    password = vault.generate_password()
                    print(f"Generated password: {password}")
                notes = input("Enter new notes (optional): ")
                
                vault.update_credentials(cred_id, site, username, password, notes)
                print("Credentials updated successfully!")
            except ValueError:
                print("Invalid credential ID!")

        elif choice == '6':
            cred_id = input("Enter credential ID to delete: ")
            try:
                cred_id = int(cred_id)
                vault.delete_credentials(cred_id)
                print("Credentials deleted successfully!")
            except ValueError:
                print("Invalid credential ID!")

        elif choice == '7':
            export_path = input("Enter export file path (ending in .vault): ")
            if not export_path.endswith('.vault'):
                export_path += '.vault'
            vault.export_vault(export_path)
            print(f"Vault exported to {export_path}")

        elif choice == '8':
            length = input("Enter password length (default is 12): ")
            try:
                length = int(length)
            except ValueError:
                length = 12
            password = vault.generate_password(length)
            print(f"Generated password: {password}")

        elif choice == '9':
            print("Goodbye!")
            sys.exit(0)

        else:
            print("Invalid choice!")

if __name__ == "__main__":
    main()
