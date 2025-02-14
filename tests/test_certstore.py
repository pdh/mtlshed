def test_store_certificate(cert_store):
    """Test storing a certificate"""
    test_cert_data = {
        "private_key": "test_private_key",
        "certificate": "test_certificate",
        "password": "test_password",
    }

    cert_store.store_certificate("test_cert", test_cert_data)
    retrieved = cert_store.get_certificate("test_cert")
    assert retrieved == test_cert_data


def test_remove_certificate(cert_store):
    """Test removing a certificate"""
    test_cert_data = {
        "private_key": "test_private_key",
        "certificate": "test_certificate",
        "password": "test_password",
    }

    # Store and then remove
    cert_store.store_certificate("test_cert", test_cert_data)
    assert cert_store.remove_certificate("test_cert") == True
    assert cert_store.get_certificate("test_cert") is None


def test_nonexistent_certificate(cert_store):
    """Test retrieving a non-existent certificate"""
    assert cert_store.get_certificate("nonexistent") is None
