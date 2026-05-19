import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ENCRYPTION_KEY_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), ".encryption_key"
)

def get_or_create_encryption_key():
    """Get existing key or create new one — stored in file not in code"""
    if os.path.exists(ENCRYPTION_KEY_FILE):
        with open(ENCRYPTION_KEY_FILE, "rb") as f:
            return f.read()
    
    # Generate new key
    key = Fernet.generate_key()
    with open(ENCRYPTION_KEY_FILE, "wb") as f:
        f.write(key)
    
    # Protect the file
    os.chmod(ENCRYPTION_KEY_FILE, 0o600)
    return key

def get_cipher():
    key = get_or_create_encryption_key()
    return Fernet(key)

def encrypt_api_key(api_key: str) -> str:
    """Encrypt API key — returns encrypted string safe to store in DB"""
    if not api_key:
        return ""
    cipher = get_cipher()
    encrypted = cipher.encrypt(api_key.encode())
    return base64.urlsafe_b64encode(encrypted).decode()

def decrypt_api_key(encrypted_key: str) -> str:
    """Decrypt API key — only called when needed for API calls"""
    if not encrypted_key:
        return ""
    try:
        cipher = get_cipher()
        decoded = base64.urlsafe_b64decode(encrypted_key.encode())
        decrypted = cipher.decrypt(decoded)
        return decrypted.decode()
    except Exception:
        return ""

def mask_api_key(api_key: str) -> str:
    """Show masked version: gsk_••••••••••••••3f4a"""
    if not api_key or len(api_key) < 8:
        return "••••••••••••••••"
    return api_key[:4] + "•" * (len(api_key) - 8) + api_key[-4:]
