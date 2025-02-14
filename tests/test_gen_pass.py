# test_password_handling.py
from wtph.certs import generate_passphrase


def test_generate_passphrase():
    word_list = ["apple", "banana", "cherry", "date"]
    passphrase = generate_passphrase(word_list, num_words=3)

    assert isinstance(passphrase, str)
    assert len(passphrase.split("-")) == 3
    assert all(word.istitle() for word in passphrase.split("-"))


def test_generate_passphrase_custom_separator():
    word_list = ["apple", "banana", "cherry", "date"]
    passphrase = generate_passphrase(word_list, num_words=3, separator="_")

    assert "_" in passphrase
    assert len(passphrase.split("_")) == 3


def test_generate_passphrase_no_capitalize():
    word_list = ["apple", "banana", "cherry", "date"]
    passphrase = generate_passphrase(word_list, num_words=3, capitalize=False)

    assert all(not word.istitle() for word in passphrase.split("-"))
