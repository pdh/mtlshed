import keyring
from cryptography.fernet import Fernet
import json
import base64


class CertificateKeychain:
    def __init__(self, service_name="certificate_manager"):
        self.service_name = service_name
        # Get or create encryption key from keychain
        master_key = keyring.get_password(self.service_name, "master_key")
        if not master_key:
            master_key = base64.b64encode(Fernet.generate_key()).decode()
            keyring.set_password(self.service_name, "master_key", master_key)
        self.fernet = Fernet(base64.b64decode(master_key.encode()))

    def store_certificate(self, cert_name, cert_data):
        """
        Store certificate data securely in keychain
        cert_data should be a dict containing private_key, certificate, and password
        """
        # Encrypt the certificate data
        encrypted_data = self.fernet.encrypt(json.dumps(cert_data).encode())
        keyring.set_password(
            self.service_name, cert_name, base64.b64encode(encrypted_data).decode()
        )

    def get_certificate(self, cert_name):
        """Retrieve certificate data from keychain"""
        encrypted_data = keyring.get_password(self.service_name, cert_name)
        if encrypted_data:
            encrypted_bytes = base64.b64decode(encrypted_data.encode())
            decrypted_data = self.fernet.decrypt(encrypted_bytes)
            return json.loads(decrypted_data)
        return None

    def remove_certificate(self, cert_name):
        """Remove certificate from keychain"""
        try:
            keyring.delete_password(self.service_name, cert_name)
            return True
        except keyring.errors.PasswordDeleteError:
            return False
