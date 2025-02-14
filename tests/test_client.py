# test_client_management.py
import pytest
import os
from mtlshed.certs import remove_client, main, create_key_pair, export_client_cert
from unittest.mock import patch, MagicMock
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from datetime import datetime, timedelta
import base64
import json


@pytest.fixture
def default_create(base_args):
    main(base_args)


def test_add_client(
    cert_store,
    temp_dir,
    base_args,
    default_create,
):
    # Test adding new client
    base_args.command = "add"
    base_args.client_names = ["newclient"]
    base_args.output_dir = temp_dir

    main(base_args)

    assert os.path.exists(os.path.join(temp_dir, "newclient.pfx"))


def test_remove_client(cert_store, temp_dir, base_args, default_create):

    client_cert_path = os.path.join(temp_dir, "client1.pfx")
    assert os.path.exists(client_cert_path)

    # Test removing client
    class RemoveArgs:
        command = "remove"
        client_names = ["client1"]
        output_dir = temp_dir

    remove_client(RemoveArgs())

    assert not os.path.exists(client_cert_path)


def test_remove_nonexistent_client(cert_store, temp_dir):
    class RemoveArgs:
        command = "remove"
        client_names = ["nonexistent"]
        output_dir = temp_dir

    remove_client(RemoveArgs())  # Should not raise exception


@pytest.mark.parametrize(
    "command,client_name,expected_result",
    [
        ("add", "newclient", True),
        ("remove", "newclient", False),
    ],
)
def test_client_operations_integration(
    cert_store,
    temp_dir,
    base_args,
    command,
    client_name,
    expected_result,
    default_create,
):
    # Perform operation
    base_args.command = command
    base_args.client_names = [client_name]
    base_args.output_dir = temp_dir

    main(base_args)

    client_cert_path = os.path.join(temp_dir, f"{client_name}.pfx")
    assert os.path.exists(client_cert_path) == expected_result


@pytest.fixture
def mock_certificates(tmp_path):
    """Fixture to create mock certificate files"""
    # Create a real test certificate for testing
    private_key = create_key_pair(2048)
    subject = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "test.local"),
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "State"),
            x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "Locality"),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "Org"),
            x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, "Unit"),
            x509.NameAttribute(x509.NameOID.EMAIL_ADDRESS, "test@example.com"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )

    ca_cert = tmp_path / "ca.crt"
    server_cert = tmp_path / "server.crt"
    client_pfx = tmp_path / "client1.pfx"

    # Write actual certificate in PEM format
    ca_cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    server_cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    client_pfx.write_bytes(b"mock client pfx")

    return tmp_path


@pytest.fixture
def mock_cert_info():
    """Fixture to provide mock certificate info"""
    return {
        "subject": {
            "commonName": "test.local",
            "countryName": "US",
            "stateOrProvinceName": "State",
            "localityName": "Locality",
            "organizationName": "Org",
            "organizationalUnitName": "Unit",
            "emailAddress": "test@example.com",
        },
        "issuer": {"commonName": "test.local"},
        "not_valid_before": "2025-02-13",
        "not_valid_after": "2026-02-13",
        "is_ca": False,
        "serial_number": 12345,
    }


def test_list_certificates(mock_certificates):
    """Test listing certificates"""
    from mtlshed.certs import list_certificates

    certs = list_certificates(mock_certificates)
    assert "ca" in certs
    assert "server" in certs
    assert "client1" in certs
    assert len(certs) == 3


@pytest.mark.parametrize("cert_name", ["ca", "server"])
def test_info_command(mock_certificates, mock_cert_info, cert_name):
    """Test getting certificate info"""
    from mtlshed.certs import get_cert_info, load_certificate

    with patch("mtlshed.certs.load_certificate") as mock_load:
        mock_cert = MagicMock()
        mock_cert.subject = x509.Name(
            [
                x509.NameAttribute(
                    x509.oid.NameOID.COMMON_NAME,
                    mock_cert_info["subject"]["commonName"],
                )
            ]
        )
        mock_cert.issuer = x509.Name(
            [
                x509.NameAttribute(
                    x509.oid.NameOID.COMMON_NAME, mock_cert_info["issuer"]["commonName"]
                )
            ]
        )
        mock_load.return_value = mock_cert

        cert_path = mock_certificates / f"{cert_name}.crt"
        cert = load_certificate(cert_path)
        info = get_cert_info(cert)

        assert info["subject"]["commonName"] == mock_cert_info["subject"]["commonName"]
        assert info["issuer"]["commonName"] == mock_cert_info["issuer"]["commonName"]


def test_get_password(cert_store):
    """Test password retrieval"""
    test_cert_data = {
        "private_key": "test_key",
        "certificate": "test_cert",
        "password": "TestPass123",
    }

    # Store certificate with password
    cert_store.store_certificate("test-client", test_cert_data)

    # Test password retrieval
    from mtlshed.certs import get_client_password

    password = get_client_password(cert_store, "test-client")
    assert password == "TestPass123"


def test_get_nonexistent_password(cert_store):
    """Test retrieving password for non-existent certificate"""
    from mtlshed.certs import get_client_password

    password = get_client_password(cert_store, "nonexistent-client")
    assert password is None


def test_list_empty_directory(tmp_path):
    """Test listing certificates in empty directory"""
    from mtlshed.certs import list_certificates

    certs = list_certificates(tmp_path)
    assert len(certs) == 0


def test_info_nonexistent_certificate(mock_certificates):
    """Test getting info for non-existent certificate"""
    from mtlshed.certs import load_certificate

    with pytest.raises(FileNotFoundError):
        load_certificate(mock_certificates / "nonexistent.crt")


@pytest.fixture
def mock_recipient_key(tmp_path):
    """Fixture to provide a test recipient key pair"""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Save public key to temp file
    pub_key_path = tmp_path / "recipient.pub"
    with open(pub_key_path, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    return {
        "private_key": private_key,
        "public_key": public_key,
        "public_key_path": pub_key_path,
    }


def test_export_certificate(cert_store, mock_recipient_key, tmp_path):
    """Test exporting encrypted certificate data"""
    # Store test certificate data
    test_cert_data = {
        "private_key": "test_private_key",
        "certificate": "test_certificate",
        "password": "test_password",
    }
    cert_store.store_certificate("test-client", test_cert_data)

    # Export encrypted data
    output_path = tmp_path / "test-client.enc"
    encrypted_data = export_client_cert(
        cert_store, "test-client", mock_recipient_key["public_key_path"]
    )

    assert encrypted_data is not None

    # Verify data can be decrypted
    decrypted_data = mock_recipient_key["private_key"].decrypt(
        base64.b64decode(encrypted_data),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    recovered_cert_data = json.loads(decrypted_data.decode())
    assert recovered_cert_data == test_cert_data


def test_export_nonexistent_certificate(cert_store, mock_recipient_key):
    """Test exporting non-existent certificate"""
    encrypted_data = export_client_cert(
        cert_store, "nonexistent-client", mock_recipient_key["public_key_path"]
    )
    assert encrypted_data is None
