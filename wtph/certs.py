from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from datetime import datetime, timedelta
import os
import argparse
import secrets
from wtph.certstore import CertificateKeychain


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
    if cert_data and 'password' in cert_data:
        return cert_data['password']
    return None


def parse_args():
    parser = argparse.ArgumentParser()

    # Add subparsers for different commands
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Create command for initial setup
    create_parser = subparsers.add_parser(
        "create", help="Create initial CA and certificates"
    )
    add_parser = subparsers.add_parser("add", help="Add a new client")
    remove_parser = subparsers.add_parser("remove", help="Remove a client")
    list_parser = subparsers.add_parser("list", help="List all certificates")
    list_parser.add_argument(
        "--output-dir", default=".", help="Directory with certificates"
    )

    info_parser = subparsers.add_parser(
        "info", help="Get detailed certificate information"
    )
    info_parser.add_argument(
        "--output-dir", default=".", help="Directory with certificates"
    )
    info_parser.add_argument(
        "--name", required=True, help="Certificate name to inspect"
    )

    get_pass_parser = subparsers.add_parser("get-password", help="Get client certificate password")
    get_pass_parser.add_argument("--output-dir", default=".", help="Directory with certificates")
    get_pass_parser.add_argument("--name", required=True, help="Client name to get password for")

    # Add common arguments to all parsers
    for p in [create_parser, add_parser]:
        p.add_argument(
            "-w",
            "--word-list-file",
            type=str,
            help="word list file",
        )
        p.add_argument(
            "--output-dir",
            default=".",
            help="Directory to store generated certificates",
        )
        p.add_argument(
            "--key-size", type=int, default=2048, help="RSA key size (default: 2048)"
        )
        p.add_argument(
            "--valid-days",
            type=int,
            default=365,
            help="Certificate validity in days (default: 365)",
        )
        p.add_argument(
            "--country", default="US", help="Certificate country (default: US)"
        )
        p.add_argument("--state", default="State", help="Certificate state/province")
        p.add_argument("--locality", default="Locality", help="Certificate locality")
        p.add_argument("--org", default="Organization", help="Certificate organization")
        p.add_argument(
            "--org-unit", default="Dev", help="Certificate organizational unit"
        )
        p.add_argument(
            "--email", default="email@example.com", help="Certificate email address"
        )

    # Add specific arguments for create command
    create_parser.add_argument(
        "--server-cn", default="server.local", help="Server common name"
    )
    create_parser.add_argument("--client-names", nargs="+", help="List of client names")
    create_parser.add_argument(
        "--client-passwords", nargs="+", help="List of client certificate passwords"
    )

    # Add specific arguments for add/remove commands
    for p in [add_parser, remove_parser]:
        p.add_argument(
            "--client-names", nargs="+", required=True, help="Client name to add/remove"
        )
    add_parser.add_argument(
        "--client-passwords", nargs="+", help="Client certificate password"
    )

    return parser.parse_args()


def main():
    args = parse_args()
    cert_store = CertificateKeychain()
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
            print(f"Certificate '{args.name}' is in PFX format and requires password to read")
            return
        
        if cert_path and os.path.exists(cert_path):
            cert = load_certificate(cert_path)
            info = get_cert_info(cert)
            
            print(f"\nCertificate details for: {args.name}")
            print("-" * 40)
            print(f"Subject:")
            for key, value in info['subject'].items():
                print(f"  {key}: {value}")
            print(f"\nIssuer:")
            for key, value in info['issuer'].items():
                print(f"  {key}: {value}")
            print(f"\nValidity:")
            print(f"  Not Before: {info['not_valid_before']}")
            print(f"  Not After: {info['not_valid_after']}")
            print(f"  Is CA: {info['is_ca']}")
            print(f"  Serial Number: {info['serial_number']}")
        else:
            print(f"Certificate '{args.name}' not found")
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
