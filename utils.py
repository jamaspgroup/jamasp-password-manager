import secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

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
    return key_raw