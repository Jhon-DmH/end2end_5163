
# Secure File Transfer System

## Overview
This project is a programming assignment for FIT5163 at Monash University. The main purpose is to develop a secure file transfer system that enables users to safely upload and download files over untrusted networks and servers.

## Features
1. **End-to-End Encryption**: 
   
2. **File Integrity Verification**:

3. **User Roles and Permissions**:

4. **Authentication & Communication**:


## Project Structure

```
│
├── README.md                   # Project overview and instructions
├── requirements.txt            # Python dependencies
├── main.py                     # Entry point for running the application
│
├── client/                     # Client-side GUI and logic
│   ├── __pycache__/            
│   ├── admin_window.py         # Admin interface
│   ├── login.py                # Login dialog
│   └── main_window.py          # Main client window
│
├── controller/                 # Server- and client-side controllers
│   ├── __pycache__/            
│   ├── utils/                  # Shared controller utilities
│   ├── cryptoController.py     # Cryptographic operations
│   ├── fileController.py       # File transfer control
│   ├── hashController.py       # Hashing operations
│   └── userController.py       # User management
│
├── data/                       # Persistent data storage
│   ├── user1/                  # Folder for user1’s files
│   ├── user2/                  # Folder for user2’s files
│   ├── file_hashes.json        # Stored file hash records
│   └── users.csv               # Registered user list
│
├── keys/                       # Key storage (asymmetric & symmetric keys)
│
├── server/                     # Old server code(not used),the new server.py is based on this  
│
├── temp_client/                # Temporary client crypto,you can find encrypted file here
├── temp_server/                # Temporary server crypto,you can find encrypted file here
│
├── upload_file/                # Example uploads
│   └── test1.txt
│
├── utils/                      # Cryptographic and general utilities
│   ├── __pycache__/            
│   ├── __init__.py
│   ├── asymmetric_crypto.py    # RSA,etc.
│   ├── symmetric_crypto.py     # AES,etc.
│   ├── crypto_utils.py         # API of the whole crypto functions
│   ├── encryption.py           # Encryption/decryption wrappers
│   ├── fileTransport.py        # Chunking and network transport
│   ├── hash_utils.py           # Hashing helpers
│   ├── integrity.py            # Integrity checks
│   ├── key_management.py       # Key generation/storage
│   ├── message.py              # Not used
│   └── auth.py                 # Authentication
│
├── server.py                   # Launches the server
│
├── test_client.py              # Client-side tests
├── test_crypto.py              # Crypto module tests
├── test_decrypt.py             # Decryption tests
├── test_encrypt.py             # Encryption tests
├── test_server.py              # Server-side tests
└── test.py                     # General test suite            
```    

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/Jhon-DmH/end2end_5163.git
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the system(server):
   ```bash
   python server.py
   ```
4. Run the system(client):
   ```bash
   python main.py
   ```   

## Usage
1. **Login**: Authenticate as either an admin or regular user.
2. **Upload/Download Files**: Users can upload/download files depending on their permissions.
3. **Verify Integrity**: Use the file integrity check feature after every file transfer.

## Test Accounts info
| Username | Password | Role |
|----------|----------|------|
| user1    | 22222222 | User |
| user2    | 12345678 | User |
| admin    | admin123 | Admin |
