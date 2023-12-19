from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from InquirerPy import prompt
from rich.console import Console
from rich.markdown import Markdown
import json

console = Console()
KEY_STORAGE_FILE = "key_storage.json"


def generate_keys(key_size):
    """
    Generate a pair of RSA private and public keys with an indefinite spinner.

    :param key_size: Size of the key in bits (e.g., 2048, 4096)
    :return: A tuple of (private_key, public_key)
    """
    with console.status(
        "[bold green]Generating keys...[/bold green]", spinner="arrow3"
    ) as status:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        public_key = private_key.public_key()

    return private_key, public_key


def save_key_to_file(key, filename, key_size, is_private=False):
    """
    Save a key to a PEM format file.

    :param key: The key (private or public) to be saved
    :param filename: The name of the file to save the key in
    :param is_private: Boolean indicating if the key is a private key
    """
    if is_private:
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    else:
        pem = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    with open(filename, "wb") as file:
        file.write(pem)

    try:
        with open(KEY_STORAGE_FILE, "r+") as storage:
            key_data = json.load(storage)
            key_type = "private" if is_private else "public"
            key_data[filename] = {"type": key_type, "size": key_size}
            storage.seek(0)
            json.dump(key_data, storage)
    except FileNotFoundError:
        with open(KEY_STORAGE_FILE, "w") as storage:
            json.dump({filename: {"type": key_type, "size": key_size}}, storage)


def list_keys():
    """
    List the stored keys from the key storage file.
    """
    try:
        with open(KEY_STORAGE_FILE, "r") as storage:
            return json.load(storage)
    except FileNotFoundError:
        return {}


def select_key_from_storage(is_private):
    """
    Allow the user to select a key from the stored keys.
    """
    keys = list_keys()
    filtered_keys = {
        k: v
        for k, v in keys.items()
        if v["type"] == ("private" if is_private else "public")
    }
    if not filtered_keys:
        console.print("[red]No keys available. Please generate a key first.[/red]")
        return None
    key_choices = list(filtered_keys.keys())
    key_name = prompt(
        {
            "type": "list",
            "name": "key",
            "message": "Select a key:",
            "choices": key_choices,
        }
    )["key"]
    return key_name


def key_generation_menu():
    """
    Display the key generation menu and handle user interactions.
    """
    key_size_question = {
        "type": "list",
        "name": "key_size",
        "message": "Select key size:",
        "choices": ["2048", "3072", "4096"],
    }
    key_size = int(prompt([key_size_question])["key_size"])

    private_key, public_key = generate_keys(key_size)

    save_key_to_file(private_key, "private_key.pem", key_size, is_private=True)
    save_key_to_file(public_key, "public_key.pem", key_size)

    print(
        f"Keys generated and saved as 'private_key.pem' and 'public_key.pem' with {key_size}-bit size."
    )
