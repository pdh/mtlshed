import keyring
from cryptography.fernet import Fernet
import json
import base64
import hvac
import json
import yaml
from typing import Optional


class CertStoreConfig:
    def __init__(self, config_path: str):
        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)

    @property
    def store_type(self) -> str:
        return self.config.get("store_type", "keychain")

    @property
    def output_dir(self) -> str:
        return self.config.get("output_dir", ".")

    @property
    def vault_config(self) -> Optional[dict]:
        return self.config.get("vault", None)


def create_cert_store(config: CertStoreConfig):
    """Create certificate store based on config"""
    if config.store_type == "vault":
        return VaultCertificateStore(
            url=config.vault_config["url"],
            token=config.vault_config["token"],
            mount_point=config.vault_config.get("mount_point", "secret"),
            path=config.vault_config.get("path", "certificates"),
        )
    else:
        return CertificateKeychain()


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


class VaultCertificateStore:
    def __init__(
        self,
        url="http://localhost:8200",
        token=None,
        mount_point="secret",
        path="certificates",
    ):
        """Initialize Vault certificate store

        Args:
            url: Vault server URL
            token: Vault authentication token
            mount_point: Secret engine mount point
            path: Base path for certificate storage
        """
        self.client = hvac.Client(url=url, token=token)
        self.mount_point = mount_point
        self.path = path

    def store_certificate(self, cert_name, cert_data):
        """Store certificate data in Vault

        Args:
            cert_name: Name/identifier for the certificate
            cert_data: Dictionary containing certificate details
        """
        # Encode certificate data as JSON
        try:
            self.client.secrets.kv.v2.create_or_update_secret(
                path=f"{self.path}/{cert_name}",
                mount_point=self.mount_point,
                secret=cert_data,
            )
            return True
        except Exception as e:
            print(f"Error storing certificate in Vault: {e}")
            return False

    def get_certificate(self, cert_name):
        """Retrieve certificate data from Vault

        Args:
            cert_name: Name/identifier of the certificate to retrieve
        """
        try:
            result = self.client.secrets.kv.v2.read_secret_version(
                path=f"{self.path}/{cert_name}", mount_point=self.mount_point
            )
            return result["data"]["data"] if result else None
        except Exception as e:
            print(f"Error retrieving certificate from Vault: {e}")
            return None

    def remove_certificate(self, cert_name):
        """Remove certificate data from Vault

        Args:
            cert_name: Name/identifier of the certificate to remove
        """
        try:
            self.client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=f"{self.path}/{cert_name}", mount_point=self.mount_point
            )
            return True
        except Exception as e:
            print(f"Error removing certificate from Vault: {e}")
            return False
