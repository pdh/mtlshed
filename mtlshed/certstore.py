import keyring
from cryptography.fernet import Fernet
import json
import hvac
import json
import yaml
import oci
from base64 import b64encode, b64decode

from typing import Optional


class CertStoreConfig:
        """
        """
        Initializes the class with a configuration file.
        Params:
            config_path str: The path to the configuration file.
    def __init__(self, config_path: str):
        """
        This class is used to configure the CertStore.
        Args:
            config_path str: The path to the configuration file.
        """
        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)

    @property
    def store_type(self) -> str:
        """
        Stores the type of the configuration.
        Yields:
            str: The type of the configuration.
        """
        return self.config.get("store_type", "keychain")

    @property
    def output_dir(self) -> str:
        """
        Returns the output directory path.
        Returns:
            str: The path to the output directory.
        """
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
    elif config.store_type == 'oci_vault':
        return OCIVaultCertificateStore(
            config_path=config.oci_vault_config.get('config_path'),
            vault_id=config.oci_vault_config['vault_id'],
            compartment_id=config.oci_vault_config['compartment_id']
        )
    else:
        return CertificateKeychain()


class CertificateKeychain:
    def __init__(self, service_name="certificate_manager"):
        """
        A class for managing certificates in a keychain using encryption.
        Args:
            service_name str: The name of the service used for keychain operations. Default is 'certificate_manager'.
        Returns:
            bool: True if the certificate was successfully removed, False if it did not exist.
        """
        self.service_name = service_name
        # Get or create encryption key from keychain
        master_key = keyring.get_password(self.service_name, "master_key")
        if not master_key:
            master_key = b64encode(Fernet.generate_key()).decode()
            keyring.set_password(self.service_name, "master_key", master_key)
        self.fernet = Fernet(b64decode(master_key.encode()))

    def store_certificate(self, cert_name, cert_data):
        """
        Store certificate data securely in keychain
        cert_data should be a dict containing private_key, certificate, and password
        """
        # Encrypt the certificate data
        encrypted_data = self.fernet.encrypt(json.dumps(cert_data).encode())
        keyring.set_password(
            self.service_name, cert_name, b64encode(encrypted_data).decode()
        )

    def get_certificate(self, cert_name):
        """Retrieve certificate data from keychain"""
        encrypted_data = keyring.get_password(self.service_name, cert_name)
        if encrypted_data:
            encrypted_bytes = b64decode(encrypted_data.encode())
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

class OCIVaultCertificateStore:
    def __init__(self, config_path=None, vault_id=None, compartment_id=None):
        """Initialize OCI Vault certificate store

        Args:
            config_path: Path to OCI config file
            vault_id: OCI Vault OCID
            compartment_id: OCI Compartment OCID
        """
        self.config = (
            oci.config.from_file(config_path) if config_path else oci.config.from_file()
        )
        self.vault_client = oci.vault.VaultsClient(self.config)
        self.secrets_client = oci.secrets.SecretsClient(self.config)
        self.vault_id = vault_id
        self.compartment_id = compartment_id

    def store_certificate(self, cert_name, cert_data):
        """Store certificate data in OCI Vault

        Args:
            cert_name: Name/identifier for the certificate
            cert_data: Dictionary containing certificate details
        """
        try:
            # Convert certificate data to string
            secret_content = b64encode(json.dumps(cert_data).encode()).decode()

            # Create secret
            create_secret_details = oci.vault.models.CreateSecretDetails(
                compartment_id=self.compartment_id,
                secret_content=oci.vault.models.Base64SecretContentDetails(
                    content=secret_content
                ),
                vault_id=self.vault_id,
                key_id=self.vault_id,  # Using vault ID as key ID
                secret_name=f"cert_{cert_name}",
            )

            self.secrets_client.create_secret(create_secret_details)
            return True
        except Exception as e:
            print(f"Error storing certificate in OCI Vault: {e}")
            return False

    def get_certificate(self, cert_name):
        """Retrieve certificate data from OCI Vault

        Args:
            cert_name: Name/identifier of the certificate to retrieve
        """
        try:
            # Get secret
            secret = self.secrets_client.get_secret_bundle(
                secret_id=f"cert_{cert_name}"
            )

            # Decode and return certificate data
            secret_content = secret.data.secret_bundle_content.content
            return json.loads(b64decode(secret_content).decode())
        except Exception as e:
            print(f"Error retrieving certificate from OCI Vault: {e}")
            return None

    def remove_certificate(self, cert_name):
        """Remove certificate data from OCI Vault

        Args:
            cert_name: Name/identifier of the certificate to remove
        """
        try:
            # Schedule secret deletion
            self.secrets_client.schedule_secret_deletion(secret_id=f"cert_{cert_name}")
            return True
        except Exception as e:
            print(f"Error removing certificate from OCI Vault: {e}")
            return False
