import secrets
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

def salt():
    salt = secrets.token_bytes(16)
    return(salt)
    
    

def encryption_key(master_password, salt):
    kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100_000,
    backend=default_backend()) 
    key_raw = kdf.derive(master_password.encode('utf-8'))
    key = base64.urlsafe_b64encode(key_raw)
    return key


def password_encryption(Key ,password):
    password = password.encode("utf-8")
    f = Fernet(Key)
    encrypted_token = f.encrypt(password)
    return encrypted_token
