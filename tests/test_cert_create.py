# test_cert_creation.py
import pytest
import os
from cryptography import x509
from wtph.certs import (
    create_certificate,
    create_key_pair,
    create_cert_name,
    save_cert,
    main,
)


def test_create_key_pair():
    key = create_key_pair(2048)
    assert key.key_size == 2048


def test_create_cert_name(base_args):
    name = create_cert_name("test.local", base_args)
    assert isinstance(name, x509.Name)
    attributes = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    assert attributes[0].value == "test.local"


def test_create_certificate(base_args):
    private_key = create_key_pair(2048)
    subject_name = create_cert_name("test.local", base_args)
    issuer_name = create_cert_name("CA", base_args)

    cert = create_certificate(
        private_key=private_key,
        subject_name=subject_name,
        issuer_name=issuer_name,
        is_ca=False,
        valid_days=365,
    )

    assert isinstance(cert, x509.Certificate)
    assert cert.subject == subject_name
    assert cert.issuer == issuer_name


def test_save_cert(temp_dir):
    private_key = create_key_pair(2048)
    cert = create_certificate(
        private_key=private_key,
        subject_name=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "test")]),
        issuer_name=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "test")]),
    )

    cert_path = os.path.join(temp_dir, "test.crt")
    save_cert(cert, cert_path)

    assert os.path.exists(cert_path)
    with open(cert_path, "rb") as f:
        loaded_cert = x509.load_pem_x509_certificate(f.read())
    assert isinstance(loaded_cert, x509.Certificate)


@pytest.mark.parametrize(
    "command,client_names,expected_files",
    [
        ("create", ["client1"], ["ca.crt", "server.key", "server.crt", "client1.pfx"]),
        (
            "create",
            ["client1", "client2"],
            ["ca.crt", "server.key", "server.crt", "client1.pfx", "client2.pfx"],
        ),
    ],
)
def test_main_create(
    temp_dir,
    word_list_file,
    command,
    client_names,
    expected_files,
    monkeypatch,
    mock_config,
):
    class MockArgs:
        def __init__(self):
            self.config = mock_config
            self.command = command
            self.output_dir = temp_dir
            self.key_size = 2048
            self.valid_days = 365
            self.country = "US"
            self.state = "State"
            self.locality = "Locality"
            self.org = "TestOrg"
            self.org_unit = "TestUnit"
            self.email = "test@example.com"
            self.server_cn = "server.local"
            self.client_names = client_names
            self.word_list_file = word_list_file
            self.client_passwords = None

    def mock_parse_args():
        return MockArgs()

    monkeypatch.setattr("wtph.certs.parse_args", mock_parse_args)

    main()

    for expected_file in expected_files:
        assert os.path.exists(os.path.join(temp_dir, expected_file))
