from typing import List, Optional, Dict, Any
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509 import Certificate, Name
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from datetime import datetime, timedelta
import os
import secrets
import base64
import json
import argparse


from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Button, Static, Input, Label, DataTable
from textual.screen import Screen
from textual.binding import Binding
from textual.widgets import Header, Footer

from mtlshed.certstore import CertificateKeychain, CertStoreConfig, create_cert_store
from mtlshed.options import parse_args


class DefaultArgs:
    def __init__(self) -> None:
        """
        Initializes an instance of the class with default values for various configuration parameters related to certificate generation or management.
        """
        self.config: Optional[str] = None
        self.country: str = "US"
        self.state: str = "State"
        self.locality: str = "Locality"
        self.org: str = "Organization"
        self.org_unit: str = "Dev"
        self.email: str = "test@example.com"
        self.output_dir: str = "./certs"
        self.key_size: int = 2048
        self.valid_days: int = 365
        self.word_list_file: Optional[str] = None
        self.command: Optional[str] = None
        self.server_cn: str = "server.local"
        self.client_names: List[str] = ["test-client"]
        self.client_passwords: Optional[List[str]] = None
        self.name: Optional[str] = None


def generate_passphrase(
    word_list: List[str],
    num_words: int = 6,
    separator: str = "-",
    capitalize: bool = True,
) -> str:
    words: List[str] = [secrets.choice(word_list) for _ in range(num_words)]
    if capitalize:
        words = [word.capitalize() for word in words]
    return separator.join(words)


def create_key_pair(key_size: int) -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def create_cert_name(cn: str, args: DefaultArgs) -> Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.COUNTRY_NAME, args.country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, args.state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, args.locality),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, args.org),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, args.org_unit),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, args.email),
        ]
    )


def create_certificate(
    private_key: RSAPrivateKey,
    subject_name: Name,
    issuer_name: Name,
    issuer_key: Optional[RSAPrivateKey] = None,
    is_ca: bool = False,
    valid_days: int = 365,
) -> Certificate:
    if issuer_key is None:
        issuer_key = private_key

    public_key: RSAPublicKey = private_key.public_key()
    builder: x509.CertificateBuilder = x509.CertificateBuilder()

    builder = builder.subject_name(subject_name)
    builder = builder.issuer_name(issuer_name)
    builder = builder.not_valid_before(datetime.utcnow())
    builder = builder.not_valid_after(datetime.utcnow() + timedelta(days=valid_days))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)

    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )

    certificate: Certificate = builder.sign(
        private_key=issuer_key, algorithm=hashes.SHA256()
    )

    return certificate


def save_key(key: RSAPrivateKey, filename: str, password: Optional[str] = None) -> None:
    encryption = (
        serialization.BestAvailableEncryption(password.encode())
        if password
        else serialization.NoEncryption()
    )

    with open(filename, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption,
            )
        )


def save_cert(cert: Certificate, filename: str) -> None:
    with open(filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def save_pfx(
    key: RSAPrivateKey,
    cert: Certificate,
    ca_cert: Certificate,
    filename: str,
    password: str,
) -> None:
    pfx_data: bytes = pkcs12.serialize_key_and_certificates(
        name=b"client-cert",
        key=key,
        cert=cert,
        cas=[ca_cert],
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode()),
    )
    with open(filename, "wb") as f:
        f.write(pfx_data)


def add_client(
    client_name: str,
    args: DefaultArgs,
    ca_cert: Certificate,
    ca_key: RSAPrivateKey,
    words: List[str],
    passwd: Optional[str] = None,
) -> None:
    """Add a new client certificate with keychain storage"""
    password = passwd or generate_passphrase(words)

    client_key = create_key_pair(args.key_size)
    client_name_obj = create_cert_name(client_name, args)
    client_cert = create_certificate(
        client_key,
        client_name_obj,
        create_cert_name("CA", args),
        ca_key,
        valid_days=args.valid_days,
    )

    # Store in keychain
    cert_store = CertificateKeychain()
    cert_data: Dict[str, str] = {
        "private_key": client_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode(),
        "certificate": client_cert.public_bytes(serialization.Encoding.PEM).decode(),
        "password": password,
    }
    cert_store.store_certificate(client_name, cert_data)

    # Save client certificate as PFX
    pfx_path = os.path.join(args.output_dir, f"{client_name}.pfx")
    save_pfx(client_key, client_cert, ca_cert, pfx_path, password)
    print(f"Created {pfx_path} with password: {password}")


def remove_client(args: DefaultArgs) -> None:
    """Remove a client certificate"""
    cert_store = CertificateKeychain()
    pfx_path: str = os.path.join(args.output_dir, f"{args.client_names[0]}.pfx")

    # Remove from keychain
    if cert_store.remove_certificate(args.client_names[0]):
        print(f"Removed certificate from keychain: {args.client_names[0]}")

    # Remove PFX file
    if os.path.exists(pfx_path):
        os.remove(pfx_path)
        print(f"Removed client certificate file: {pfx_path}")
    else:
        print(f"Client certificate file not found: {pfx_path}")


def get_cert_info(cert: Certificate) -> Dict[str, Any]:
    """Extract readable information from certificate"""
    subject = cert.subject
    issuer = cert.issuer
    info: Dict[str, Any] = {
        "subject": {attr.oid._name: attr.value for attr in subject},
        "issuer": {attr.oid._name: attr.value for attr in issuer},
        "serial_number": cert.serial_number,
        "not_valid_before": cert.not_valid_before,
        "not_valid_after": cert.not_valid_after,
        "is_ca": False,
    }

    try:
        basic_constraints = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        )
        info["is_ca"] = basic_constraints.value.ca
    except x509.extensions.ExtensionNotFound:
        pass

    return info


def load_certificate(cert_path: str) -> Certificate:
    """Load a certificate from file"""
    with open(cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def list_certificates(output_dir: str) -> List[str]:
    """List all certificates in the directory"""
    certs: List[str] = []
    for filename in os.listdir(output_dir):
        if filename.endswith((".crt", ".pfx")):
            name = os.path.splitext(filename)[0]
            certs.append(name)
    return sorted(certs)


def get_client_password(
    cert_store: CertificateKeychain, client_name: str
) -> Optional[str]:
    """Retrieve client certificate password from keychain"""
    cert_data = cert_store.get_certificate(client_name)
    if cert_data and "password" in cert_data:
        return cert_data["password"]
    return None


def encrypt_for_recipient(public_key_path: str, data: Dict[str, Any]) -> str:
    """Encrypt data with recipient's public key"""
    with open(public_key_path, "rb") as f:
        public_key: RSAPublicKey = serialization.load_pem_public_key(f.read())

    data_bytes = json.dumps(data).encode()
    encrypted = public_key.encrypt(
        data_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return base64.b64encode(encrypted).decode()


def export_client_cert(
    cert_store: CertificateKeychain, client_name: str, public_key_path: str
) -> Optional[str]:
    """Export encrypted client certificate details"""
    # Get client cert data from keychain
    cert_data: Optional[Dict[str, Any]] = cert_store.get_certificate(client_name)
    if not cert_data:
        return None

    # Encrypt for recipient
    return encrypt_for_recipient(public_key_path, cert_data)


def decrypt_certificate(encrypted_data: str, private_key_path: str) -> Dict[str, Any]:
    """Decrypt certificate data using private key"""
    # Load private key
    with open(private_key_path, "rb") as f:
        private_key: RSAPrivateKey = serialization.load_pem_private_key(
            f.read(), password=None  # Add password parameter if key is encrypted
        )

    # Decrypt data
    encrypted_bytes: bytes = base64.b64decode(encrypted_data)
    decrypted_data: bytes = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return json.loads(decrypted_data.decode())


class CertificateManager:
        """
        """
        Initializes a new instance of the class.
        Args:
            args object: An object containing various arguments for the class initialization.
            cert_store object: An object representing the certificate store to be used.
    def __init__(self, args, cert_store):
        """
        This class handles various certificate management operations such as creating, loading, listing, exporting, and decrypting certificates.
        Args:
            args Namespace: Namespace containing command-line arguments for configuration.
            cert_store CertificateStore: Object responsible for storing and retrieving certificate data.
        """
        self.args = args
        self.cert_store = cert_store
        self.output_dir = args.output_dir
        self.words = self._load_word_list()

    def _load_word_list(self):
        """Load word list from file if specified"""
        if self.args.word_list_file:
            with open(self.args.word_list_file, "r") as f:
                return [line.strip() for line in f.readlines()]
        return []

    def list_certs(self):
        """
        Handle list command
        """
        print("\nAvailable certificates:")
        print("----------------------")
        for cert_name in list_certificates(self.output_dir):
            print(cert_name)

    def get_password(self):
        """
        Handle get-password command
        Args:
            self object: The instance of the class.
        Returns:
            None: This method does not return a value.
        """
        password = get_client_password(self.cert_store, self.args.name)
        if password:
            print(f"Password for {self.args.name}: {password}")
        else:
            print(f"No password found for client: {self.args.name}")

    def show_info(self):
        """
        Handle info command
        Args:
            self object: The instance of the class.
        """
        cert_path = self._get_cert_path()
        if not cert_path:
            # Try getting from cert store for client certs
            cert_data = self.cert_store.get_certificate(self.args.name)
            if cert_data:
                print(f"\nCertificate details for: {self.args.name}")
                print("-" * 40)
                print(cert_data["certificate"])
            else:
                print(f"Certificate '{self.args.name}' not found")
            return

        if os.path.exists(cert_path):
            cert = load_certificate(cert_path)
            self._display_cert_info(cert)
        else:
            print(f"Certificate '{self.args.name}' not found")

    def export_cert(self):
        """
        Handle export command
        Params:
            self object: The instance of the class.
            args object: An object containing command-line arguments.
        Returns:
            None: No value is returned.
        """
        encrypted_data = export_client_cert(
            self.cert_store, self.args.name, self.args.public_key
        )
        if encrypted_data:
            with open(self.args.output, "w") as f:
                f.write(encrypted_data)
            print(
                f"Exported encrypted certificate data for {self.args.name} to {self.args.output}"
            )
        else:
            print(f"Client certificate not found: {self.args.name}")

    def decrypt_cert(self):
        """
        Handle decrypt command
        Params:
            self object: The instance of the class.
            input str: Path to the file containing encrypted certificate data.
            private_key str: Path to the private key file used for decryption.
        Returns:
            None: No value is returned.
        """
        try:
            with open(self.args.input, "r") as f:
                encrypted_data = f.read()
            cert_data = decrypt_certificate(encrypted_data, self.args.private_key)
            self._display_decrypted_data(cert_data)
        except Exception as e:
            print(f"Error decrypting certificate data: {e}")

    def create_certs(self):
        """Handle create command"""
        ca_cert, ca_key = self._create_ca()
        server_cert, server_key = self._create_server_cert(ca_cert, ca_key)

        # Store CA and server certificates
        self._store_ca_server_certs(ca_cert, ca_key, server_cert, server_key)

        if self.args.client_names:
            self._create_client_certs(ca_cert, ca_key)

    def _store_ca_server_certs(self, ca_cert, ca_key, server_cert, server_key):
        """
        Store CA and server certificates in cert store and also save them to the filesystem for compatibility
        Args:
            ca_cert Certificate: The CA certificate to be stored.
            ca_key PrivateKey: The CA private key to be stored.
            server_cert Certificate: The server certificate to be stored.
            server_key PrivateKey: The server private key to be stored.
        """
        ca_data = {
            "private_key": ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode(),
            "certificate": ca_cert.public_bytes(serialization.Encoding.PEM).decode(),
            "is_ca": True,
        }
        self.cert_store.store_certificate("ca", ca_data)

        server_data = {
            "private_key": server_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode(),
            "certificate": server_cert.public_bytes(
                serialization.Encoding.PEM
            ).decode(),
            "is_ca": False,
        }
        self.cert_store.store_certificate("server", server_data)

        # Also save to filesystem for compatibility
        save_cert(ca_cert, os.path.join(self.output_dir, "ca.crt"))
        save_key(ca_key, os.path.join(self.output_dir, "ca.key"))
        save_key(server_key, os.path.join(self.output_dir, "server.key"))
        save_cert(server_cert, os.path.join(self.output_dir, "server.crt"))

    def add_clients(self):
        """
        Handle the add command for adding clients.
        """
        ca_data = self.cert_store.get_certificate("ca")
        if not ca_data:
            print("CA certificate not found. Please run 'create' command first.")
            return

        ca_cert = x509.load_pem_x509_certificate(ca_data["certificate"].encode())
        ca_key = serialization.load_pem_private_key(
            ca_data["private_key"].encode(), password=None
        )

        self._create_client_certs(ca_cert, ca_key)

    def remove_clients(self):
        """
        Handle remove command
        Args:
            client_names list[str]: List of client names to be removed from the certificate store and their corresponding PFX files.
        """
        for client_name in self.args.client_names:
            if self.cert_store.remove_certificate(client_name):
                print(f"Removed certificate from store: {client_name}")

            # Also remove PFX file
            pfx_path = os.path.join(self.output_dir, f"{client_name}.pfx")
            if os.path.exists(pfx_path):
                os.remove(pfx_path)
                print(f"Removed client certificate file: {pfx_path}")

    def _create_ca(self):
        """
        Create CA certificate and key
        Args:
            self class: The instance of the class.
        Yields:
            tuple[bytes, bytes]: A tuple containing the CA certificate and key as bytes.
        """
        ca_key = create_key_pair(self.args.key_size)
        ca_name = create_cert_name("CA", self.args)
        ca_cert = create_certificate(
            ca_key, ca_name, ca_name, is_ca=True, valid_days=self.args.valid_days
        )
        return ca_cert, ca_key

    def _create_server_cert(self, ca_cert, ca_key):
        """
        Create server certificate
        Args:
            ca_cert unknown: Certificate of the Certificate Authority
            ca_key unknown: Key of the Certificate Authority
        Yields:
            unknown: None
        """
        server_key = create_key_pair(self.args.key_size)
        server_name = create_cert_name(self.args.server_cn, self.args)
        server_cert = create_certificate(
            server_key,
            server_name,
            create_cert_name("CA", self.args),
            ca_key,
            valid_days=self.args.valid_days,
        )

        # Save server certificates
        server_key_path = os.path.join(self.output_dir, "server.key")
        server_cert_path = os.path.join(self.output_dir, "server.crt")
        save_key(server_key, server_key_path)
        save_cert(server_cert, server_cert_path)

        return server_cert, server_key

    def _create_client_certs(self, ca_cert, ca_key):
        """
        Create client certificates
        Args:
            ca_cert string: CA certificate file path
            ca_key string: CA key file path
        """
        if self.args.client_names:
            for idx, client in enumerate(self.args.client_names):
                passwd = None
                if self.args.client_passwords:
                    passwd = self.args.client_passwords[idx]
                add_client(
                    client,
                    self.args,
                    ca_cert,
                    ca_key,
                    words=self.words,
                    passwd=passwd,
                )

    def _load_ca(self):
        """
        Load existing CA certificate and key
        Yields:
            Tuple[Optional[x509.Certificate], Optional[serialization.PrivateKey]]: A tuple containing the loaded CA certificate and key. If the certificate is not found, both values will be None.
        """
        ca_path = os.path.join(self.output_dir, "ca.crt")
        ca_key_path = os.path.join(self.output_dir, "ca.key")

        if not os.path.exists(ca_path):
            print("CA certificate not found. Please run 'create' command first.")
            return None, None

        with open(ca_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        with open(ca_key_path, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)

        return ca_cert, ca_key


class CertificateManagerScreen(Screen):
    """
    This class represents the main screen for certificate operations. It provides a user interface for managing certificates, including creating CA & server certificates, adding and removing clients, listing certificates, getting passwords, exporting and importing certificates, and decrypting certificates.
    """

    def compose(self) -> ComposeResult:
        """
        Create the UI layout
        Yields:
            Header: Yields a header component for the UI layout.
            Container: Yields a container component for the UI layout.
            Footer: Yields a footer component for the UI layout.
        """
        yield Header()
        yield Container(
            Horizontal(
                Vertical(
                    Label("Certificate Operations", classes="title"),
                    Button("Create CA & Server", id="create", variant="primary"),
                    Button("Add Client", id="add_client"),
                    Button("Remove Client", id="remove_client"),
                    Button("List Certificates", id="list"),
                    Button("Get Password", id="get_password"),
                    Button("Export Certificate", id="export"),
                    Button("Import Certificate", id="import"),
                    Button("Decrypt Certificate", id="decrypt"),
                    classes="sidebar",
                ),
                Vertical(
                    Static("Welcome to Certificate Manager", id="content"),
                    id="main_content",
                ),
            )
        )
        yield Footer()


class CreateCertScreen(Screen):
    """
    Screen for creating CA and server certificates
    """

    def compose(self) -> ComposeResult:
        """
        Create the certificate creation form
        Yields:
            Container: The certificate creation form as a Container widget.
        """
        yield Container(
            Label("Create CA and Server Certificates", classes="title"),
            Input(
                placeholder="Server Common Name", id="server_cn", value="server.local"
            ),
            Input(placeholder="Country", id="country", value="US"),
            Input(placeholder="State", id="state", value="State"),
            Input(placeholder="Locality", id="locality", value="Locality"),
            Input(placeholder="Organization", id="org", value="Organization"),
            Input(placeholder="Org Unit", id="org_unit", value="Dev"),
            Input(placeholder="Email", id="email", value="email@example.com"),
            Input(placeholder="Client Names (comma-separated)", id="client_names"),
            Button("Create Certificates", id="create_button", variant="primary"),
            Button("Back", id="back_button"),
        )


class CertListScreen(Screen):
    """
    Screen for listing certificates
    Yields:
        Container: A container with a title label, a data table, and a back button.
    """

    def compose(self) -> ComposeResult:
        """
        Composes a UI layout for the certificate list.
        Yields:
            Container: A container containing a title, a data table, and a button.
        """
        yield Container(
            Label("Certificate List", classes="title"),
            DataTable(id="cert_table"),
            Button("Back", id="back_button"),
        )

    def on_mount(self):
        """Load certificate list when screen is mounted"""
        table = self.query_one(DataTable)
        table.add_columns("Name", "Type", "Status")
        certs = list_certificates(self.app.cert_manager.output_dir)
        for cert in certs:
            cert_type = (
                "CA" if cert == "ca" else "Server" if cert == "server" else "Client"
            )
            table.add_row(cert, cert_type, "Valid")

class ExportCertScreen(Screen):
    """Screen for exporting certificates"""

    def compose(self) -> ComposeResult:
        yield Container(
            Label("Export Certificate", classes="title"),
            Input(placeholder="Enter client name", id="client_name"),
            Input(placeholder="Enter public key path", id="public_key_path"),
            Button("Export", id="export_button", variant="primary"),
            Button("Back", id="back_button"),
        )

class ImportCertScreen(Screen):
    """Screen for importing certificates"""

    def compose(self) -> ComposeResult:
        """
        Compose a UI for importing a certificate.
        Yields:
            Container: A container with UI components for importing a certificate.
        """
        yield Container(
            Label("Import Certificate", classes="title"),
            Input(placeholder="Enter encrypted data", id="encrypted_data"),
            Input(placeholder="Enter private key path", id="private_key_path"),
            Button("Import", id="import_button", variant="primary"),
            Button("Back", id="back_button"),
        )

class AddClientScreen(Screen):
    """Screen for adding a new client"""

    def compose(self) -> ComposeResult:
        yield Container(
            Label("Add New Client", classes="title"),
            Input(placeholder="Enter client name", id="client_name"),
            Input(placeholder="Enter password (optional)", id="client_password"),
            Button("Add Client", id="add_client_button", variant="primary"),
            Button("Back", id="back_button"),
        )

class RemoveClientScreen(Screen):
    """
    Screen for removing a client
    Yields:
        Container: Yields a ComposeResult containing a container with a title, input field, and buttons for removing a client or going back.
    """

    def compose(self) -> ComposeResult:
        yield Container(
            Label("Remove Client", classes="title"),
            Input(placeholder="Enter client name", id="client_name"),
            Button("Remove Client", id="remove_client_button", variant="primary"),
            Button("Back", id="back_button"),
        )

class GetPasswordScreen(Screen):
    """
    Screen for getting a client's password
    Yields:
        ComposeResult: A result that can be composed of UI components.
    """

    def compose(self) -> ComposeResult:
        yield Container(
            Label("Get Client Password", classes="title"),
            Input(placeholder="Enter client name", id="client_name"),
            Button("Get Password", id="get_password_button", variant="primary"),
            Button("Back", id="back_button"),
        )

class DecryptScreen(Screen):
    """Screen for decrypting certificate data"""

    def compose(self) -> ComposeResult:
        """
        Composes the UI components for the decrypt certificate screen.
        Yields:
            Container: A container with various UI components for the decrypt certificate screen.
        """
        yield Container(
            Label("Decrypt Certificate", classes="title"),
            Input(placeholder="Enter encrypted data", id="encrypted_data"),
            Input(placeholder="Enter private key path", id="private_key_path"),
            Button("Decrypt", id="decrypt_button", variant="primary"),
            Button("Back", id="back_button"),
        )

class CertificateManagerApp(App):
    """
    This is the main application class for the Certificate Manager. It handles the user interface and business logic for managing certificates.
    """

    CSS = """
    .sidebar { width: 30%; background: $panel; padding: 1; }
    #main_content { width: 70%; padding: 1; }
    .title { text-align: center; text-style: bold; margin: 1; }
    Button { margin: 1; width: 100%; }
    Input { margin: 1; }
    DataTable { height: auto; margin: 1; }
    """

    BINDINGS = [Binding("q", "quit", "Quit"), Binding("b", "go_back", "Back")]

    SCREENS = {
        "manager": CertificateManagerScreen,
        "create": CreateCertScreen,
        "list": CertListScreen,
        "export": ExportCertScreen,
        "import": ImportCertScreen,
        "add_client": AddClientScreen,
        "remove_client": RemoveClientScreen,
        "get_password": GetPasswordScreen,
        "decrypt": DecryptScreen
    }

    def __init__(self, cert_manager: CertificateManager):
        super().__init__()
        self.cert_manager = cert_manager

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """
        Handle button press events
        Args:
            event Button.Pressed: The button press event containing the button information.
        Returns:
            None: No value is returned.
        """
        button_id = event.button.id

        if button_id in self.SCREENS:
            self.push_screen(button_id)
        elif button_id == "back_button":
            self.pop_screen()
        elif button_id == "create_button":
            self._handle_create_certificates()
        elif button_id == "export_button":
            self._handle_export_certificate()
        elif button_id == "import_button":
            self._handle_import_certificate()
        elif button_id == "add_client_button":
            self._handle_add_client()
        elif button_id == "remove_client_button":
            self._handle_remove_client()
        elif button_id == "get_password_button":
            self._handle_get_password()
        elif button_id == "decrypt_button":
            self._handle_decrypt_certificate()

    def _handle_create_certificates(self):
        """
        Handle certificate creation from form data
        Params:
            screen Screen: The screen object containing the form data.
            args DefaultArgs: The arguments object initialized with form data.
            client_names str: The value of the client names input field.
        """
        screen = self.screen
        args = DefaultArgs()  # Create mock args with form data
        args.server_cn = screen.query_one("#server_cn").value
        args.country = screen.query_one("#country").value
        args.state = screen.query_one("#state").value
        args.locality = screen.query_one("#locality").value
        args.org = screen.query_one("#org").value
        args.org_unit = screen.query_one("#org_unit").value
        args.email = screen.query_one("#email").value

        client_names = screen.query_one("#client_names").value
        print("client-names", client_names)
        args.client_names = (
            [name.strip() for name in client_names.split(",")] if client_names else []
        )
        print("args.client-names?", client_names)
        self.cert_manager.args = args
        # Create certificates using the certificate manager
        self.cert_manager.create_certs()
        self.notify("Certificates created successfully")
        self.pop_screen()

    def _handle_export_certificate(self):
        """
        Handle certificate export
        """
        screen = self.screen
        client_name = screen.query_one("#client_name").value
        public_key_path = screen.query_one("#public_key_path").value
        
        if not client_name or not public_key_path:
            self.notify("Please enter both client name and public key path")
            return

        encrypted_data = export_client_cert(self.cert_manager.cert_store, client_name, public_key_path)
        if encrypted_data:
            output_path = f"{client_name}_exported.enc"
            with open(output_path, "w") as f:
                f.write(encrypted_data)
            self.notify(f"Certificate exported to {output_path}")
        else:
            self.notify("Failed to export certificate")

    def _handle_import_certificate(self):
        """
        Handle certificate import
        """
        screen = self.screen
        encrypted_data = screen.query_one("#encrypted_data").value
        private_key_path = screen.query_one("#private_key_path").value
        
        if not encrypted_data or not private_key_path:
            self.notify("Please enter both encrypted data and private key path")
            return

        try:
            cert_data = decrypt_certificate(encrypted_data, private_key_path)
            # Here you would typically store the imported certificate
            # For now, we'll just notify the user
            self.notify("Certificate imported successfully")
        except Exception as e:
            self.notify(f"Failed to import certificate: {str(e)}")

    def _handle_add_client(self):
        """
        Handle adding a new client
        """
        screen = self.screen
        client_name = screen.query_one("#client_name").value
        client_password = screen.query_one("#client_password").value

        if not client_name:
            self.notify("Please enter a client name")
            return

        try:
            self.cert_manager.args.client_names = [client_name]
            self.cert_manager.args.client_passwords = [client_password] if client_password else None
            self.cert_manager.add_clients()
            self.notify(f"Client {client_name} added successfully")
        except Exception as e:
            self.notify(f"Failed to add client: {str(e)}")

    def _handle_remove_client(self):
        """
        Handle removing a client
        Params:
            screen object: The screen object from which the client name will be retrieved.
        """
        screen = self.screen
        client_name = screen.query_one("#client_name").value

        if not client_name:
            self.notify("Please enter a client name")
            return

        try:
            self.cert_manager.args.client_names = [client_name]
            self.cert_manager.remove_clients()
            self.notify(f"Client {client_name} removed successfully")
        except Exception as e:
            self.notify(f"Failed to remove client: {str(e)}")

    def _handle_get_password(self):
        """
        Handle getting a client's password
        Params:
            self object: The instance of the class.
        Returns:
            void: This method does not return any value.
        """
        screen = self.screen
        client_name = screen.query_one("#client_name").value

        if not client_name:
            self.notify("Please enter a client name")
            return

        try:
            password = get_client_password(self.cert_manager.cert_store, client_name)
            if password:
                self.notify(f"Password for {client_name}: {password}")
            else:
                self.notify(f"No password found for client: {client_name}")
        except Exception as e:
            self.notify(f"Failed to get password: {str(e)}")

    def _handle_decrypt_certificate(self):
        """Handle decrypting certificate data"""
        screen = self.screen
        encrypted_data = screen.query_one("#encrypted_data").value
        private_key_path = screen.query_one("#private_key_path").value

        if not encrypted_data or not private_key_path:
            self.notify("Please enter both encrypted data and private key path")
            return

        try:
            cert_data = decrypt_certificate(encrypted_data, private_key_path)
            self.notify("Certificate decrypted successfully")
            # You might want to display the decrypted data in a more user-friendly way
        except Exception as e:
            self.notify(f"Failed to decrypt certificate: {str(e)}")

    def on_mount(self) -> None:
        """Set up the application on start"""
        self.push_screen("manager")


def run_tui(cert_manager):
    """Run the TUI application"""
    app = CertificateManagerApp(cert_manager)
    app.run()


def _main(args: argparse.Namespace):
    # args = parse_args()
    # Setup certificate store based on config
    if args.config:
        config = CertStoreConfig(args.config)
        cert_store = create_cert_store(config)
        args.output_dir = config.output_dir
    else:
        cert_store = CertificateKeychain()

    # Create manager instance
    manager = CertificateManager(args, cert_store)

    # Command dispatch dictionary
    commands = {
        "list": manager.list_certs,
        "get-password": manager.get_password,
        "info": manager.show_info,
        "export": manager.export_cert,
        "decrypt": manager.decrypt_cert,
        "create": manager.create_certs,
        "add": manager.add_clients,
        "remove": manager.remove_clients,
    }

    # Execute command
    if args.command in commands:
        commands[args.command]()
    else:
        print("Invalid command")


def main():
    args = parse_args()
    # Setup certificate store based on config
    if args.config:
        config = CertStoreConfig(args.config)
        cert_store = create_cert_store(config)
        output_dir = config.output_dir
    else:
        cert_store = CertificateKeychain()
        output_dir = args.output_dir

    os.makedirs(output_dir, exist_ok=True)

    # Create certificate manager instance
    cert_manager = CertificateManager(args, cert_store)
    # Run TUI if no command specified
    if args.command == "tui":
        run_tui(cert_manager)
    else:
        # Run CLI commands as before
        _main(args)


if __name__ == "__main__":
    main()
