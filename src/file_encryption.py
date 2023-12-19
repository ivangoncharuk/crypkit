from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from InquirerPy import prompt
from rich.console import Console
from rich.panel import Panel
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


def get_file_path(method, title):
    """
    Get the file path either through file explorer or manual input based on user's choice.
    """
    return (
        select_file(title)
        if method == "Explorer"
        else prompt(
            {
                "type": "input",
                "name": "path",
                "message": f"Enter the path for {title.lower()}:",
            }
        )["path"]
    )


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

    file_method = prompt(
        {
            "type": "list",
            "name": "method",
            "message": "Select method to choose the file:",
            "choices": ["Explorer", "Manual Path"],
        }
    )["method"]
    file_path = get_file_path(
        file_method,
        "a file to encrypt" if action == choices["encrypt"] else "a file to decrypt",
    )

    key_method = prompt(
        {
            "type": "list",
            "name": "method",
            "message": "Select method to choose the key:",
            "choices": ["Explorer", "Manual Path"],
        }
    )["method"]
    key_path = get_file_path(
        key_method, "a Public Key" if action == choices["encrypt"] else "a Private Key"
    )

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

        display_content = prompt(
            {
                "type": "confirm",
                "name": "display",
                "message": "Do you want to display the decrypted content?",
                "default": False,
            }
        )["display"]

        if display_content:
            try:
                with open(decrypted_file_path, "r", encoding="utf-8") as file:
                    decrypted_content = file.read()
                    panel = Panel(
                        decrypted_content,
                        title="Decrypted Content",
                        expand=False,
                        border_style="blue",
                    )
                    console.print(panel)
            except UnicodeDecodeError:
                console.print(
                    "[red]Unable to display content: the file may contain binary data.[/red]"
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
