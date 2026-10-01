import secrets
import base64
import words
import character
import time
import struct
import hmac
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
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
    kdf = Argon2id(
    salt=salt,
    length=32,
    iterations=600,
    lanes=4,
    memory_cost=131072,) 
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


def Secret_production():
    Secret = secrets.token_bytes(10)    #Generating a shared secret
    Secret_Base32 = base64.b32encode(Secret).decode("ascii")  #Convert secret format to Base32
    return Secret_Base32
    
    
def TOTP(Secret_Base32):
    time_frame = int(time.time() // 30)     #Taking a time frame     
    time_bytes = struct.pack(">Q", time_frame)       #Convert time to bytes
    Secret = base64.b32decode(Secret_Base32)        #Convert secret to bytes
    pass_hash = hmac.new(key= Secret ,msg=time_bytes, digestmod=hashlib.sha1)       #Generate two-factor authentication as a hash
    pass_bytes = pass_hash.digest()      #Convert to two-factor authentication bytes    
    offset = pass_bytes[-1] & 0x0F       #Takes the last byte of the HMAC output and extracts a number between 0 and 15 from it.
    binary_code = pass_bytes[offset:offset + 4]     
    code_int = int.from_bytes(binary_code, "big")
    code_int = code_int & 0x7FFFFFFF
    otp = code_int % 1_000_000
    
    return otp


print(encryption_key("123354565676788904" ,b'\x8d\x7f\x80\xd4\xe0\xa2\xcbTsN\xae\xc37\x04//'))
print(encryption_key("123354565676788904" ,b'\x8d\x7f\x80\xd4\xe0\xa2\xcbTsN\xae\xc37\x04//'))
print(encryption_key("123354565676788904" ,b'\x8d\x7f\x80\xd4\xe0\xa2\xcbTsN\xae\xc37\x04//'))
print(encryption_key("123354565676788904" ,b'\x8d\x7f\x80\xd4\xe0\xa2\xcbTsN\xae\xc37\x04//'))
print(encryption_key("123354565676788904" ,b'\x8d\x7f\x80\xd4\xe0\xa2\xcbTsN\xae\xc37\x04//'))
print(encryption_key("123354565676788904" ,b'\x8d\x7f\x80\xd4\xe0\xa2\xcbTsN\xae\xc37\x04//'))
print(encryption_key("123354565676788904" ,b'\x8d\x7f\x80\xd4\xe0\xa2\xcbTsN\xae\xc37\x04//'))
print(encryption_key("123354565676788904" ,b'\x8d\x7f\x80\xd4\xe0\xa2\xcbTsN\xae\xc37\x04//'))
print(encryption_key("123354565676788904" ,b'\x8d\x7f\x80\xd4\xe0\xa2\xcbTsN\xae\xc37\x04//'))