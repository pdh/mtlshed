# wtph

what the ph? Kinda like [certstrap](https://github.com/square/certstrap) but dumberer.

A command-line utility for creating and managing X.509 certificates with secure keychain storage for sensitive data.

## Features
- Create CA (Certificate Authority) certificates
- Generate server certificates
- Add and remove client certificates
- Generate secure passphrases for client certificates
- PFX (PKCS#12) format support for client certificates
- Secure storage of certificates and passwords in system keychain
- Certificate and password retrieval capabilities

## Usage

### Create Initial CA and Server Certificates
```bash
python cert_manager.py create \
    --output-dir ./certs \
    --server-cn server.example.com \
    --client-names client1 client2 \
    --word-list-file wordlist.txt
```

### Add New Client Certificate
```bash
python cert_manager.py add \
    --output-dir ./certs \
    --client-names newclient \
    --client-passwords "optional-password"
```

### Remove Client Certificate
```bash
python cert_manager.py remove \
    --output-dir ./certs \
    --client-names client1
```

### List All Certificates
```bash
python cert_manager.py list \
    --output-dir ./certs
```

### Get Certificate Details
```bash
python cert_manager.py info \
    --output-dir ./certs \
    --name client1
```

### Retrieve Client Certificate Password
```bash
python cert_manager.py get-password \
    --name client1
```

## Keychain Storage
The utility uses the system's native keychain (Keychain Access on macOS) to securely store:
- Client certificate private keys
- Certificate data
- Client certificate passwords

### Stored Data Format
Each certificate entry in the keychain contains:
```json
{
    "private_key": "PEM-encoded private key",
    "certificate": "PEM-encoded certificate",
    "password": "certificate password"
}
```

## Requirements
- Python 3.x
- cryptography library
- keyring library (for keychain access)

## Installation
```bash
pip install cryptography keyring
```

## Security Features
- Secure storage using system keychain
- Encrypted storage of private keys
- Password-protected client certificates
- Automatic master key management
- Access control through system keychain

## Security Notes
- Store CA private keys securely
- Use strong passphrases for client certificates
- Keep certificate files in a secure location
- System keychain provides additional security layer
- Access to stored credentials requires system authentication