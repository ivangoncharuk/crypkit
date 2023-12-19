from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from InquirerPy import prompt
from rich.console import Console
import os
import tkinter as tk
from tkinter import filedialog

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
    action = prompt(
        [
            {
                "type": "list",
                "name": "action",
                "message": "Select an action:",
                "choices": list(choices.values()),
            }
        ]
    )["action"]

    if action == choices["encrypt"]:
        file_path = select_file("Select a file to encrypt")
        key_path = select_key_file(is_private=False)
        if file_path and key_path:
            public_key = load_key(key_path, is_private=False)
            encrypted_file_path = encrypt_file(file_path, public_key)
            console.print(
                f"File encrypted successfully. Encrypted file: {encrypted_file_path}"
            )
    elif action == choices["decrypt"]:
        file_path = select_file("Select a file to decrypt")
        key_path = select_key_file(is_private=True)
        if file_path and key_path:
            private_key = load_key(key_path, is_private=True)
            decrypted_file_path = decrypt_file(file_path, private_key)
            console.print(
                f"File decrypted successfully. Decrypted file: {decrypted_file_path}"
            )


def select_file(title="Select a file"):
    """
    Open a file dialog for the user to select a file using tkinter.
    """
    root = tk.Tk()
    root.withdraw()  # Hide the main tkinter window
    return filedialog.askopenfilename(title=title)


def select_key_file(is_private):
    """
    Open a file dialog for the user to select a key file using tkinter.
    """
    title = "Select a Private Key" if is_private else "Select a Public Key"
    return select_file(title)
