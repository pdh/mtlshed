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
    # Common words list (you can expand this or load from a file)
    # Using shorter common words that are easy to remember

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


def parse_args():
    parser = argparse.ArgumentParser()

    # TODO default to gen from /usr/share/dict/words?
    parser.add_argument(
        "-w",
        "--word-list-file",
        type=argparse.FileType("r"),
        help="word list file",
    )

    parser.add_argument(
        "--output-dir", default=".", help="Directory to store generated certificates"
    )
    parser.add_argument(
        "--key-size", type=int, default=2048, help="RSA key size (default: 2048)"
    )
    parser.add_argument(
        "--valid-days",
        type=int,
        default=365,
        help="Certificate validity in days (default: 365)",
    )

    # Certificate details
    parser.add_argument(
        "--country", default="US", help="Certificate country (default: US)"
    )
    parser.add_argument("--state", default="State", help="Certificate state/province")
    parser.add_argument("--locality", default="Locality", help="Certificate locality")
    parser.add_argument(
        "--org", default="Organization", help="Certificate organization"
    )
    parser.add_argument(
        "--org-unit", default="Dev", help="Certificate organizational unit"
    )
    parser.add_argument(
        "--email", default="email@example.com", help="Certificate email address"
    )

    # Server configuration
    parser.add_argument(
        "--server-cn", default="server.local", help="Server common name"
    )

    # Client configuration
    parser.add_argument(
        "--client-names",
        nargs="+",
        help="List of client names, --client-names bob jim",
    )
    parser.add_argument(
        "--client-passwords",
        nargs="+",
        help="List of client certificate passwords (must match number of clients)",
    )

    args_ = parser.parse_args()
    if args_.client_passwords and len(args_.client_passwords) != len(
        args_.client_names
    ):
        parser.error("Number of client passwords must match number of client names")

    if not args_.client_passwords and not args_.word_list_file:
        parser.error("if client passwords are unspecified a word list file is required")

    if not args_.client_passwords:
        with args_.word_list_file:
            words = [line.strip() for line in args_.word_list_file.readlines()]
        passwords = []
        for _ in range(len(args_.client_names)):
            passwords.append(generate_passphrase(words))
        args_.client_passwords = passwords

    return args_


def main():
    args_ = parse_args()
    os.makedirs(args_.output_dir, exist_ok=True)

    # Create CA
    ca_key = create_key_pair(args_.key_size)
    ca_name = create_cert_name("CA", args_)
    ca_cert = create_certificate(
        ca_key, ca_name, ca_name, is_ca=True, valid_days=args_.valid_days
    )

    # Create Server Certificate
    server_key = create_key_pair(args_.key_size)
    server_name = create_cert_name(args_.server_cn, args_)
    server_cert = create_certificate(
        server_key, server_name, ca_name, ca_key, valid_days=args_.valid_days
    )

    # Create Client Certificates
    for client_name, password in zip(args_.client_names, args_.client_passwords):
        client_key = create_key_pair(args_.key_size)
        client_name_obj = create_cert_name(client_name, args_)
        client_cert = create_certificate(
            client_key, client_name_obj, ca_name, ca_key, valid_days=args_.valid_days
        )

        # Save client certificate as PFX
        pfx_path = os.path.join(args_.output_dir, f"{client_name}.pfx")
        save_pfx(client_key, client_cert, ca_cert, pfx_path, password)
        print(f"Created {pfx_path} with password: {password}")

    # Save CA and Server certificates
    ca_path = os.path.join(args_.output_dir, "ca.crt")
    server_key_path = os.path.join(args_.output_dir, "server.key")
    server_cert_path = os.path.join(args_.output_dir, "server.crt")

    save_cert(ca_cert, ca_path)
    save_key(server_key, server_key_path)
    save_cert(server_cert, server_cert_path)

    print(f"Created {ca_path}, {server_key_path}, and {server_cert_path}")


if __name__ == "__main__":
    main()
