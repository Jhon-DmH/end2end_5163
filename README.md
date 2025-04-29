
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
end2end_5163/
│
├── README.md                  
├── requirements.txt           # Python dependencies
├── main.py                    
│
├── server/                    
│   ├── __init__.py
│   ├── server.py              
│   └── file_controller.py        
│
├── client/                    
│   ├── __init__.py
│   ├── client.py              
│   └── file_controller.py        
│
└── utils/                     
    ├── __init__.py
    ├── encryption.py          
    ├── hash_utils.py          
    └── auth.py                
```    

## Installation
1. Clone the repository:
   ```bash
   git clone <repository-url>
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the system:
   ```bash
   python secure_transfer.py
   ```

## Usage
1. **Login**: Authenticate as either an admin or regular user.
2. **Upload/Download Files**: Users can upload/download files depending on their permissions.
3. **Verify Integrity**: Use the file integrity check feature after every file transfer.

