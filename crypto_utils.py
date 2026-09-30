import base64
import hashlib
import hmac
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ITERATIONS = 310_000

def derive_key(master_password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", master_password.encode("utf-8"), salt, ITERATIONS, dklen=32
    )

def hash_master_password(master_password: str, salt: bytes) -> str:
    return derive_key(master_password, salt).hex()

def verify_master_password(master_password: str, salt: bytes, stored_hash: str) -> bool:
    candidate = derive_key(master_password, salt).hex()
    return hmac.compare_digest(candidate, stored_hash)

def encrypt_text(text: str, key: bytes) -> str:
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, text.encode("utf-8"), None)
    return base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")

def decrypt_text(token: str, key: bytes) -> str:
    raw = base64.urlsafe_b64decode(token.encode("ascii"))
    nonce, ciphertext = raw[:12], raw[12:]
    return AESGCM(key).decrypt(nonce, ciphertext, None).decode("utf-8")
