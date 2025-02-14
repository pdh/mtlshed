from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from datetime import datetime, timedelta
import os
import argparse
import secrets


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
    """Add a new client certificate"""
    if passwd:
        password = passwd
    else:
        password = generate_passphrase(words)

    client_key = create_key_pair(args.key_size)
    client_name_obj = create_cert_name(client_name, args)
    client_cert = create_certificate(
        client_key,
        client_name_obj,
        create_cert_name("CA", args),
        ca_key,
        valid_days=args.valid_days,
    )

    # Save client certificate as PFX
    pfx_path = os.path.join(args.output_dir, f"{client_name}.pfx")
    save_pfx(client_key, client_cert, ca_cert, pfx_path, password)
    print(f"Created {pfx_path} with password: {password}")


def remove_client(args):
    """Remove a client certificate"""
    pfx_path = os.path.join(args.output_dir, f"{args.client_names[0]}.pfx")
    if os.path.exists(pfx_path):
        os.remove(pfx_path)
        print(f"Removed client certificate: {pfx_path}")
    else:
        print(f"Client certificate not found: {pfx_path}")


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
            "--client-names", nargs='+', required=True, help="Client name to add/remove"
        )
    add_parser.add_argument(
        "--client-passwords", nargs='+', help="Client certificate password"
    )

    return parser.parse_args()


def main():
    args = parse_args()
    os.makedirs(args.output_dir, exist_ok=True)
    words = []
    if args.word_list_file:
        with open(args.word_list_file, 'r') as f:
            words = [line.strip() for line in f.readlines()]

    if args.command == "create":
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
                    client, args, ca_cert, ca_key, words=words, passwd=passwd,
                ) # TODO storage
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
                client, args, ca_cert, ca_key, words, passwd=passwd,
            ) # TODO storage

    elif args.command == "remove":
        remove_client(args)


if __name__ == "__main__":
    main()
