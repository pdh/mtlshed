# test_client_management.py
import pytest
import os
from wtph.certs import remove_client, main


@pytest.fixture
def default_create(base_args, monkeypatch):
    def mock_parse_args():
        return base_args

    monkeypatch.setattr("wtph.certs.parse_args", mock_parse_args)

    main()


def test_add_client(temp_dir, base_args, default_create, monkeypatch):

    # Test adding new client
    base_args.command = "add"
    base_args.client_names = ["newclient"]
    base_args.output_dir = temp_dir

    monkeypatch.setattr("wtph.certs.parse_args", lambda: base_args)
    main()

    assert os.path.exists(os.path.join(temp_dir, "newclient.pfx"))


def test_remove_client(temp_dir, base_args, default_create, monkeypatch):

    client_cert_path = os.path.join(temp_dir, "client1.pfx")
    assert os.path.exists(client_cert_path)

    # Test removing client
    class RemoveArgs:
        command = "remove"
        client_names = ["client1"]
        output_dir = temp_dir

    monkeypatch.setattr("wtph.certs.parse_args", RemoveArgs())
    remove_client(RemoveArgs())

    assert not os.path.exists(client_cert_path)


def test_remove_nonexistent_client(temp_dir, monkeypatch):
    class RemoveArgs:
        command = "remove"
        client_names = ["nonexistent"]
        output_dir = temp_dir

    monkeypatch.setattr("wtph.certs.parse_args", RemoveArgs())
    remove_client(RemoveArgs())  # Should not raise exception


@pytest.mark.parametrize(
    "command,client_name,expected_result",
    [
        ("add", "newclient", True),
        ("remove", "newclient", False),
    ],
)
def test_client_operations_integration(
    temp_dir,
    base_args,
    command,
    client_name,
    expected_result,
    default_create,
    monkeypatch,
):
    # Perform operation
    base_args.command = command
    base_args.client_names = [client_name]
    base_args.output_dir = temp_dir

    monkeypatch.setattr("wtph.certs.parse_args", lambda: base_args)
    main()

    client_cert_path = os.path.join(temp_dir, f"{client_name}.pfx")
    assert os.path.exists(client_cert_path) == expected_result
