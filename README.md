# Secure Password Vault CLI

A secure command-line password manager that allows users to store, retrieve, and manage their passwords using encryption.

## Features

1. Master Password Authentication
2. Add New Credentials
3. Search Credentials
4. Update or Delete Credentials
5. Password Encryption using Fernet
6. Export to Encrypted File
7. Password Generator
8. CLI Interface

## Setup

1. Install requirements:
```bash
pip install -r requirements.txt
```

2. Run the application:
```bash
python password_vault.py
```

## Usage

1. First time users will need to set up a master password
2. Use the menu options to:
   - Add new passwords
   - View stored passwords
   - Search for specific passwords
   - Update existing passwords
   - Delete passwords
   - Export vault
   - Generate secure passwords

## Security

- All passwords are encrypted using Fernet (symmetric encryption)
- Master password is required to access the vault
- Data is stored in an SQLite database with encryption
#   S e c u r e - P a s s w o r d - V a u l t - C L I - V e r s i o n -  
 