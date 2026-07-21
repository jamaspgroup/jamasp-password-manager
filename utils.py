import secrets
import base64
import words
import character
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet


def salt():
    """It produces a random salt."""
    salt = secrets.token_bytes(16)
    return(salt)
    
    

def encryption_key(master_password, salt):
    """It takes the master password and the salt,
    and generates an encryption key from them."""
    kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100_000,
    backend=default_backend()) 
    key_raw = kdf.derive(master_password.encode('utf-8'))
    key = base64.urlsafe_b64encode(key_raw)
    return key


def password_encryption(Key , password):
    """It takes the code and encrypts it
    using the encryption key."""
    password = password.encode("utf-8")
    f = Fernet(Key)
    encrypted_token = f.encrypt(password)
    return encrypted_token


def Decoding(Key,encrypted_token):
    """It takes the encrypted data along
    with the key and decrypts it."""
    f = Fernet(Key)
    original_password_bytes = f.decrypt(encrypted_token)
    original_password = original_password_bytes.decode('utf-8')
    return original_password


def simple_password():
    """It creates a simple password using
    an English word and a number."""
    a = secrets.choice(words.my_words)
    b = secrets.randbelow(9999)
    b = str(b)
    c = secrets.randbits(1)
    if c :
        d = a + b
    else:
        d = b + a
    return d


def hard_password(Count = 20, Mode = True):
    """Generates strong passwords with 
    custom characters and custom lengths."""
    a = secrets.randbits(1)
    c = secrets.randbits(1)
    if a:
        Count = Count - 1
    elif c:
        Count = Count
    else:
        Count = Count + 1
        
    if Mode:
        ch = character.character
    else:
        ch = character.character_full
        
    password = ''
    for i in range(Count):
        p = secrets.choice(ch)
        password +=  p
    return password


def init_password(Count = 20):
    """Generates numeric-only
    codes of a custom length."""
    password = ''
    for i in range(Count):
        p = secrets.randbelow(10)
        p = str(p)
        password +=  p
    return password


def TOTP():
    key = secrets.token_bytes(10)
    
