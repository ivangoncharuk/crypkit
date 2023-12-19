from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from InquirerPy import prompt


def generate_keys(key_size):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def save_key_to_file(key, filename, is_private=False):
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


def key_generation_menu():
    key_size_question = {
        "type": "list",
        "name": "key_size",
        "message": "Select key size:",
        "choices": ["2048", "4096"],
    }
    key_size = int(prompt([key_size_question])["key_size"])

    private_key, public_key = generate_keys(key_size)

    save_key_to_file(private_key, "private_key.pem", is_private=True)
    save_key_to_file(public_key, "public_key.pem")

    print(
        f"Keys generated and saved as 'private_key.pem' and 'public_key.pem' with {key_size}-bit size."
    )
