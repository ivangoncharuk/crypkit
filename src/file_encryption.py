from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from InquirerPy import prompt
from rich.console import Console
import os

console = Console()


def load_key(file_path, is_private):
    """
    Load a private or public key from a file.
    """
    with open(file_path, "rb") as key_file:
        if is_private:
            return serialization.load_pem_private_key(
                key_file.read(),
                password=None,
            )
        else:
            return serialization.load_pem_public_key(key_file.read())


def encrypt_file(file_path, public_key):
    """
    Encrypt a file using the provided public key.
    """
    with open(file_path, "rb") as file:
        original_data = file.read()

    encrypted_data = public_key.encrypt(
        original_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    encrypted_file_path = file_path + ".encrypted"
    with open(encrypted_file_path, "wb") as file:
        file.write(encrypted_data)

    return encrypted_file_path


def decrypt_file(file_path, private_key):
    """
    Decrypt a file using the provided private key.
    """
    with open(file_path, "rb") as file:
        encrypted_data = file.read()

    original_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    decrypted_file_path = file_path.replace(".encrypted", ".decrypted")
    with open(decrypted_file_path, "wb") as file:
        file.write(original_data)

    return decrypted_file_path


def file_encryption_menu():
    """
    Display the file encryption/decryption menu and handle user interactions.
    """
    choices = {"encrypt": "Encrypt a file", "decrypt": "Decrypt a file"}
    questions = [
        {
            "type": "list",
            "name": "action",
            "message": "Select an action:",
            "choices": list(choices.values()),
        }
    ]
    action = prompt(questions)["action"]

    file_path_question = {
        "type": "input",
        "name": "file_path",
        "message": "Enter the path of the file:",
    }
    file_path = prompt([file_path_question])["file_path"]

    key_path_question = {
        "type": "input",
        "name": "key_path",
        "message": "Enter the path of the key:",
    }
    key_path = prompt([key_path_question])["key_path"]

    if action == choices["encrypt"]:
        public_key = load_key(key_path, is_private=False)
        encrypted_file_path = encrypt_file(file_path, public_key)
        console.print(
            f"File encrypted successfully. Encrypted file: {encrypted_file_path}"
        )
    elif action == choices["decrypt"]:
        private_key = load_key(key_path, is_private=True)
        decrypted_file_path = decrypt_file(file_path, private_key)
        console.print(
            f"File decrypted successfully. Decrypted file: {decrypted_file_path}"
        )
