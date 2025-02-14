from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import pkcs12
from datetime import datetime, timedelta
import os
import argparse
import secrets
import base64
import json
from wtph.certstore import CertificateKeychain, CertStoreConfig, create_cert_store


def generate_passphrase(word_list, num_words=6, separator="-", capitalize=True):
    # Generate passphrase
    words = [secrets.choice(word_list) for _ in range(num_words)]

    # Capitalize first letter if requested
    if capitalize:
        words = [word.capitalize() for word in words]

    # Join words with separator
    return separator.join(words)


def create_key_pair(key_size):
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def create_cert_name(cn, args):
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
    private_key, subject_name, issuer_name, issuer_key=None, is_ca=False, valid_days=365
):
    if issuer_key is None:
        issuer_key = private_key

    public_key = private_key.public_key()
    builder = x509.CertificateBuilder()

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

    certificate = builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())

    return certificate


def save_key(key, filename, password=None):
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


def save_cert(cert, filename):
    with open(filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def save_pfx(key, cert, ca_cert, filename, password):
    pfx_data = pkcs12.serialize_key_and_certificates(
        name=b"client-cert",
        key=key,
        cert=cert,
        cas=[ca_cert],
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode()),
    )
    with open(filename, "wb") as f:
        f.write(pfx_data)


def add_client(client_name, args, ca_cert, ca_key, words, passwd=None):
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
    cert_data = {
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


def remove_client(args):
    """Remove a client certificate"""
    cert_store = CertificateKeychain()
    pfx_path = os.path.join(args.output_dir, f"{args.client_names[0]}.pfx")

    # Remove from keychain
    if cert_store.remove_certificate(args.client_names[0]):
        print(f"Removed certificate from keychain: {args.client_names[0]}")

    # Remove PFX file
    if os.path.exists(pfx_path):
        os.remove(pfx_path)
        print(f"Removed client certificate file: {pfx_path}")
    else:
        print(f"Client certificate file not found: {pfx_path}")


def get_cert_info(cert):
    """Extract readable information from certificate"""
    subject = cert.subject
    issuer = cert.issuer
    info = {
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


def load_certificate(cert_path):
    """Load a certificate from file"""
    with open(cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def list_certificates(output_dir):
    """List all certificates in the directory"""
    certs = []
    for filename in os.listdir(output_dir):
        if filename.endswith((".crt", ".pfx")):
            name = os.path.splitext(filename)[0]
            certs.append(name)
    return sorted(certs)


def get_client_password(cert_store, client_name):
    """Retrieve client certificate password from keychain"""
    cert_data = cert_store.get_certificate(client_name)
    if cert_data and "password" in cert_data:
        return cert_data["password"]
    return None


def encrypt_for_recipient(public_key_path, data):
    """Encrypt data with recipient's public key"""
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    # Convert data to bytes
    data_bytes = json.dumps(data).encode()

    # Encrypt with public key
    encrypted = public_key.encrypt(
        data_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return base64.b64encode(encrypted).decode()


def export_client_cert(cert_store, client_name, public_key_path):
    """Export encrypted client certificate details"""
    # Get client cert data from keychain
    cert_data = cert_store.get_certificate(client_name)
    if not cert_data:
        return None

    # Encrypt for recipient
    return encrypt_for_recipient(public_key_path, cert_data)


def decrypt_certificate(encrypted_data, private_key_path):
    """Decrypt certificate data using private key"""
    # Load private key
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=None  # Add password parameter if key is encrypted
        )

    # Decrypt data
    encrypted_bytes = base64.b64decode(encrypted_data)
    decrypted_data = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return json.loads(decrypted_data.decode())


def add_common_args(parser):
    """Add common arguments to a parser"""
    parser.add_argument("-w", "--word-list-file", type=str, help="word list file")
    parser.add_argument("--output-dir", default=".", help="Directory for certificates")
    parser.add_argument(
        "--key-size", type=int, default=2048, help="RSA key size (default: 2048)"
    )
    parser.add_argument(
        "--valid-days", type=int, default=365, help="Certificate validity in days"
    )
    parser.add_argument("--country", default="US", help="Certificate country")
    parser.add_argument("--state", default="State", help="Certificate state/province")
    parser.add_argument("--locality", default="Locality", help="Certificate locality")
    parser.add_argument(
        "--org", default="Organization", help="Certificate organization"
    )
    parser.add_argument(
        "--org-unit", default="Dev", help="Certificate organizational unit"
    )
    parser.add_argument(
        "--email", default="email@example.com", help="Certificate email"
    )


def create_subparser_commands(subparsers):
    """Create all subparser commands"""
    commands = {
        "create": {"help": "Create initial CA and certificates"},
        "add": {"help": "Add a new client"},
        "remove": {"help": "Remove a client"},
        "list": {"help": "List all certificates"},
        "info": {"help": "Get detailed certificate information"},
        "get-password": {"help": "Get client certificate password"},
        "export": {"help": "Export encrypted client certificate"},
        "decrypt": {"help": "Decrypt certificate data"},
    }

    return {
        cmd: subparsers.add_parser(cmd, help=attrs["help"])
        for cmd, attrs in commands.items()
    }


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=str, help="Path to config file")

    subparsers = parser.add_subparsers(dest="command", help="Commands")
    parsers = create_subparser_commands(subparsers)

    # Add common arguments to relevant parsers
    for p in [parsers["create"], parsers["add"]]:
        add_common_args(p)

    # Add output-dir to relevant parsers
    for cmd in ["list", "info", "get-password"]:
        parsers[cmd].add_argument(
            "--output-dir", default=".", help="Directory with certificates"
        )

    # Add name argument to relevant parsers
    for cmd in ["info", "get-password", "export"]:
        parsers[cmd].add_argument(
            "--name", required=True, help=f"Certificate name for {cmd}"
        )

    # Add create-specific arguments
    parsers["create"].add_argument(
        "--server-cn", default="server.local", help="Server common name"
    )
    parsers["create"].add_argument(
        "--client-names", nargs="+", help="List of client names"
    )
    parsers["create"].add_argument(
        "--client-passwords", nargs="+", help="List of client passwords"
    )

    # Add client management arguments
    for p in [parsers["add"], parsers["remove"]]:
        p.add_argument(
            "--client-names", nargs="+", required=True, help="Client name to add/remove"
        )
    parsers["add"].add_argument(
        "--client-passwords", nargs="+", help="Client certificate password"
    )

    # Add export/decrypt specific arguments
    parsers["export"].add_argument(
        "--public-key", required=True, help="Recipient's public key file"
    )
    parsers["export"].add_argument(
        "--output", required=True, help="Output file for encrypted data"
    )
    parsers["decrypt"].add_argument(
        "--private-key", required=True, help="Path to private key file"
    )
    parsers["decrypt"].add_argument(
        "--input", required=True, help="Encrypted certificate file"
    )

    return parser.parse_args()


def main():
    args = parse_args()
    if args.config:
        config = CertStoreConfig(args.config)
        cert_store = create_cert_store(config)
        output_dir = config.output_dir
    else:
        cert_store = CertificateKeychain()
        output_dir = args.output_dir
    # cert_store = CertificateKeychain()
    os.makedirs(args.output_dir, exist_ok=True)
    words = []
    if args.word_list_file:
        with open(args.word_list_file, "r") as f:
            words = [line.strip() for line in f.readlines()]

    if args.command == "list":
        print("\nAvailable certificates:")
        print("----------------------")
        for cert_name in list_certificates(args.output_dir):
            print(cert_name)
    elif args.command == "get-password":
        password = get_client_password(cert_store, args.name)
        if password:
            print(f"Password for {args.name}: {password}")
        else:
            print(f"No password found for client: {args.name}")

    elif args.command == "info":
        cert_path = None
        if args.name == "ca":
            cert_path = os.path.join(args.output_dir, "ca.crt")
        elif args.name == "server":
            cert_path = os.path.join(args.output_dir, "server.crt")
        elif os.path.exists(os.path.join(args.output_dir, f"{args.name}.pfx")):
            print(
                f"Certificate '{args.name}' is in PFX format and requires password to read"
            )
            return

        if cert_path and os.path.exists(cert_path):
            cert = load_certificate(cert_path)
            info = get_cert_info(cert)

            print(f"\nCertificate details for: {args.name}")
            print("-" * 40)
            print(f"Subject:")
            for key, value in info["subject"].items():
                print(f"  {key}: {value}")
            print(f"\nIssuer:")
            for key, value in info["issuer"].items():
                print(f"  {key}: {value}")
            print(f"\nValidity:")
            print(f"  Not Before: {info['not_valid_before']}")
            print(f"  Not After: {info['not_valid_after']}")
            print(f"  Is CA: {info['is_ca']}")
            print(f"  Serial Number: {info['serial_number']}")
        else:
            print(f"Certificate '{args.name}' not found")
    elif args.command == "export":
        cert_store = CertificateKeychain()
        encrypted_data = export_client_cert(cert_store, args.name, args.public_key)
        if encrypted_data:
            with open(args.output, "w") as f:
                f.write(encrypted_data)
            print(
                f"Exported encrypted certificate data for {args.name} to {args.output}"
            )
        else:
            print(f"Client certificate not found: {args.name}")
    elif args.command == "decrypt":
        try:
            with open(args.input, "r") as f:
                encrypted_data = f.read()

            cert_data = decrypt_certificate(encrypted_data, args.private_key)
            print("\nDecrypted Certificate Data:")
            print("-" * 40)
            print(f"Certificate:")
            print(cert_data["certificate"])
            print(f"\nPrivate Key:")
            print(cert_data["private_key"])
            print(f"\nPassword: {cert_data['password']}")
        except Exception as e:
            print(f"Error decrypting certificate data: {e}")
    elif args.command == "create":
        # Create CA
        ca_key = create_key_pair(args.key_size)
        ca_name = create_cert_name("CA", args)
        ca_cert = create_certificate(
            ca_key, ca_name, ca_name, is_ca=True, valid_days=args.valid_days
        )

        # Create Server Certificate
        server_key = create_key_pair(args.key_size)
        server_name = create_cert_name(args.server_cn, args)
        server_cert = create_certificate(
            server_key, server_name, ca_name, ca_key, valid_days=args.valid_days
        )

        # Create Client Certificates
        if args.client_names:
            for idx, client in enumerate(args.client_names):
                passwd = None
                if args.client_passwords:
                    passwd = args.client_passwords[idx]
                add_client(
                    client,
                    args,
                    ca_cert,
                    ca_key,
                    words=words,
                    passwd=passwd,
                )  # TODO storage
        # Save CA and Server certificates
        ca_path = os.path.join(args.output_dir, "ca.crt")
        ca_key_path = os.path.join(args.output_dir, "ca.key")
        server_key_path = os.path.join(args.output_dir, "server.key")
        server_cert_path = os.path.join(args.output_dir, "server.crt")
        save_cert(ca_cert, ca_path)
        save_key(ca_key, ca_key_path)
        save_key(server_key, server_key_path)
        save_cert(server_cert, server_cert_path)

        print(f"Created {ca_path}, {server_key_path}, and {server_cert_path}")

    elif args.command == "add":
        # Load existing CA certificate and key
        ca_path = os.path.join(args.output_dir, "ca.crt")
        ca_key_path = os.path.join(args.output_dir, "ca.key")
        if not os.path.exists(ca_path):
            print("CA certificate not found. Please run 'create' command first.")
            return

        with open(ca_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        with open(ca_key_path, "rb") as f:
            ca_key = serialization.load_pem_private_key(
                f.read(),
                password=None,  # or provide password if key is encrypted
            )

        for idx, client in enumerate(args.client_names):
            passwd = None
            if args.client_passwords:
                passwd = args.client_passwords[idx]
            add_client(
                client,
                args,
                ca_cert,
                ca_key,
                words,
                passwd=passwd,
            )  # TODO storage

    elif args.command == "remove":
        remove_client(args)


if __name__ == "__main__":
    main()
