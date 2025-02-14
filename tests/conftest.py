# conftest.py
import pytest
import tempfile
from pathlib import Path


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as tmpdirname:
        yield tmpdirname


class FileWrapper:
    def __init__(self, filename, mode="r", *args, **kwargs):
        self.filename = filename
        self._file_object = None
        self.mode = mode
        self.args = args
        self.kwargs = kwargs

    def __enter__(self):
        self.open(self.mode, *self.args, **self.kwargs)
        return self

    def __exit__(self, *args):
        self._file_object.close()

    def open(self, mode, *args, **kwargs):
        self._file_object = open(self.filename, mode, *args, **kwargs)


@pytest.fixture
def word_list_file(temp_dir):
    word_list = [
        "apple",
        "banana",
        "cherry",
        "date",
        "elderberry",
        "fig",
        "lemon",
        "lime",
        "coconut",
        "strawberry",
        "blueberry",
        "grape",
        "carrot",
        "lettuce",
        "tomato",
    ]
    file_path = Path(temp_dir) / "words.txt"
    with open(file_path, "w") as f:
        f.write("\n".join(word_list))
    return str(file_path)


@pytest.fixture
def base_args(temp_dir, word_list_file):
    class Args:
        def __init__(self):
            self.command = "create"
            self.output_dir = temp_dir
            self.key_size = 2048
            self.valid_days = 365
            self.country = "US"
            self.state = "State"
            self.locality = "Locality"
            self.org = "TestOrg"
            self.org_unit = "TestUnit"
            self.email = "test@example.com"
            self.client_names = ["client1"]
            self.client_passwords = []
            self.server_cn = "foo"

        @property
        def word_list_file(self):
            return word_list_file

    return Args()
