import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import hashlib

backend = default_backend()
ITERATIONS = 100_000

# Hash login passwords (for auth)
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Generate Fernet key using PBKDF2 with proper cryptography hash
def generate_key(passkey: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # ✅ CORRECT algorithm type
        length=32,
        salt=salt,
        iterations=ITERATIONS,
        backend=backend
    )
    return base64.urlsafe_b64encode(kdf.derive(passkey.encode()))

def encrypt_data(data: str, passkey: str) -> str:
    salt = os.urandom(16)
    key = generate_key(passkey, salt)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data.encode())
    return base64.urlsafe_b64encode(salt + encrypted).decode()

def decrypt_data(encrypted_data_b64: str, passkey: str) -> str or None:
    try:
        raw = base64.urlsafe_b64decode(encrypted_data_b64.encode())
        salt, encrypted = raw[:16], raw[16:]
        key = generate_key(passkey, salt)
        fernet = Fernet(key)
        return fernet.decrypt(encrypted).decode()
    except Exception:
        return None
