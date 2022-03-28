import secrets
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import sys
from os.path import exists
import pickle

backend = default_backend()
iterations = 100_000

# Secret handling functions
def _derive_key(password: bytes, salt: bytes, iterations: int = iterations) -> bytes:
    """Derive a secret key from a given password and salt"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=iterations, backend=backend)
    return b64e(kdf.derive(password))

def password_encrypt(message: bytes, password: str, iterations: int = iterations) -> bytes:
    salt = secrets.token_bytes(16)
    key = _derive_key(password.encode(), salt, iterations)
    return b64e(
        b'%b%b%b' % (
            salt,
            iterations.to_bytes(4, 'big'),
            b64d(Fernet(key).encrypt(message)),
        )
    )

def password_decrypt(token: bytes, password: str) -> bytes:
    decoded = b64d(token)
    salt, iter, token = decoded[:16], decoded[16:20], b64e(decoded[20:])
    iterations = int.from_bytes(iter, 'big')
    key = _derive_key(password.encode(), salt, iterations)
    return Fernet(key).decrypt(token)

# Args len check
if len(sys.argv) < 2 :
    print("No mode selected. Format: passmanager.py [list/add/delete] optional:name optional:value")
    exit()

# Initialize secret data
secretsData = {}
if exists("passwords.dat") :
    masterPass = input("Master Password:")
    with open("passwords.dat", "rb") as file_secret:
        secretsData = pickle.load(file_secret)
    if masterPass != password_decrypt(secretsData["#MASTERPASS#"], masterPass).decode() :
        print("MasterPass Not Match")
        exit()
else :
    print("### Initializing Password File ###")
    masterPass = input("SET Master Password: ")
    masterPass_check = input("CONFIRM Master Password: ")
    while masterPass != masterPass_check:
        masterPass = input("SET Master Password: ")
        masterPass_check = input("CONFIRM Master Password: ")
    secretsData["#MASTERPASS#"] = password_encrypt(masterPass.encode(),masterPass)
    with open("passwords.dat", "wb") as file_secret:
        pickle.dump(secretsData, file_secret)

# List all secrets
if sys.argv[1] == "list" :
    for secret, secret_pass in secretsData.items():
        decrypted = password_decrypt(secret_pass, masterPass).decode()
        if secret != "#MASTERPASS#":
            print(f"{secret} = {decrypted}")

# Add secret
if sys.argv[1] == "add" :
    name = sys.argv[2] if len(sys.argv) == 4 else input("Name: ")
    passVal = sys.argv[3] if len(sys.argv) == 4 else input("Password: ")
    secretsData[name] = password_encrypt(passVal.encode(), masterPass)
    with open("passwords.dat", "wb") as file_secret:
        pickle.dump(secretsData, file_secret)

# Delete secret
if sys.argv[1] == "delete" :
    name = sys.argv[2] if len(sys.argv) == 3 else input("Name of secret to delete: ")
    if not secretsData.pop(name, False) :
        print("Key Not Found")
    else:
        print("Key Removed")
    with open("passwords.dat", "wb") as file_secret:
        pickle.dump(secretsData, file_secret)

    




