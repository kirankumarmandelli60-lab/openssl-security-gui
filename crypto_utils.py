from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
import os
from cryptography.hazmat.primitives.asymmetric import padding

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_rsa_keys(overwrite=False):
    os.makedirs("keys", exist_ok=True)

    private_key_path = "keys/private_key.pem"
    public_key_path = "keys/public_key.pem"
    if not overwrite and (os.path.exists(private_key_path) or os.path.exists(public_key_path)):
        raise FileExistsError("RSA key files already exist. Back them up or remove them before generating a new key pair.")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    with open(private_key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    with open(public_key_path, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    return True


def generate_file_hash(file_path):
    digest = hashes.Hash(hashes.SHA256())

    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            digest.update(chunk)

    return digest.finalize().hex()

def encrypt_file(file_path):
    os.makedirs("encrypted", exist_ok=True)
    os.makedirs("keys", exist_ok=True)

    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)

    nonce = os.urandom(12)

    with open(file_path, "rb") as f:
        data = f.read()

    encrypted_data = aesgcm.encrypt(
        nonce,
        data,
        None
    )

    file_name = os.path.basename(file_path)

    output_path = f"encrypted/{file_name}.enc"

    with open(output_path, "wb") as f:
        f.write(nonce)
        f.write(encrypted_data)

    with open("keys/aes_key.bin", "wb") as f:
        f.write(key)

    return output_path
def decrypt_file(file_path):
    os.makedirs("decrypted", exist_ok=True)

    with open("keys/aes_key.bin", "rb") as f:
        key = f.read()

    aesgcm = AESGCM(key)

    with open(file_path, "rb") as f:
        nonce = f.read(12)
        encrypted_data = f.read()

    if len(nonce) != 12 or not encrypted_data:
        raise ValueError("Invalid encrypted file: missing AES-GCM nonce or ciphertext.")

    decrypted_data = aesgcm.decrypt(
        nonce,
        encrypted_data,
        None
    )

    file_name = os.path.basename(file_path)

    if file_name.endswith(".enc"):
        file_name = file_name[:-4]

    output_path = f"decrypted/{file_name}"

    with open(output_path, "wb") as f:
        f.write(decrypted_data)

    return output_path

def sign_file(file_path):
    os.makedirs("signatures", exist_ok=True)

    with open("keys/private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )

    with open(file_path, "rb") as f:
        data = f.read()

    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    file_name = os.path.basename(file_path)

    signature_path = f"signatures/{file_name}.sig"

    with open(signature_path, "wb") as f:
        f.write(signature)

    return signature_path

def verify_signature(file_path, signature_path):
    with open("keys/public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read()
        )

    with open(file_path, "rb") as f:
        data = f.read()

    with open(signature_path, "rb") as f:
        signature = f.read()

    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return True

    except Exception:
        return False
