import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding # For AES CBC padding
from cryptography.hazmat.backends import default_backend

# --- User A: Key Generation ---
print("User A: Generating RSA key pair...")
private_key_A = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key_A = private_key_A.public_key()
print("User A: RSA key pair generated.")
# In a real app, public_key_A would be shared (e.g., saved to a file, sent over network)

# --- User B: Encryption ---
print("\nUser B: Preparing to encrypt message...")
# Message to be encrypted
message = b"This is a secret message from User B to User A."
with open("message.txt", "wb") as f:
    f.write(message)
print("User B: Original message saved to message.txt")

# 1. Generate random AES-256 key
aes_key = os.urandom(32)  # 256 bits = 32 bytes
# Use AES-GCM for Authenticated Encryption (preferred)
# Alternatively use CBC + HMAC, or just CBC if simplicity is prioritized over auth.
# Let's use GCM as it's modern and handles integrity.
iv = os.urandom(12) # GCM recommended nonce size is 12 bytes

# 2. Encrypt message using AES-GCM
print("User B: Encrypting message with AES-256-GCM...")
encryptor = Cipher(
    algorithms.AES(aes_key),
    modes.GCM(iv),
    backend=default_backend()
).encryptor()
# GCM does not require padding
ciphertext = encryptor.update(message) + encryptor.finalize()
tag = encryptor.tag # GCM tag for integrity

# Save encrypted message (IV + Ciphertext + Tag)
encrypted_message = iv + tag + ciphertext
with open("encrypted_message.bin", "wb") as f:
    f.write(encrypted_message)
print("User B: Encrypted message saved to encrypted_message.bin")

# 3. Encrypt AES key using RSA (User A's public key)
print("User B: Encrypting AES key with User A's RSA public key...")
aes_key_encrypted = public_key_A.encrypt(
    aes_key,
    rsa_padding.OAEP(
        mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
with open("aes_key_encrypted.bin", "wb") as f:
    f.write(aes_key_encrypted)
print("User B: Encrypted AES key saved to aes_key_encrypted.bin")

# --- User A: Decryption ---
print("\nUser A: Preparing to decrypt message...")
# Assume User A received encrypted_message.bin and aes_key_encrypted.bin

# 1. Decrypt AES key using their private RSA key
print("User A: Decrypting AES key with private RSA key...")
with open("aes_key_encrypted.bin", "rb") as f:
    aes_key_encrypted_received = f.read()

decrypted_aes_key = private_key_A.decrypt(
    aes_key_encrypted_received,
    rsa_padding.OAEP(
        mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print("User A: AES key decrypted.")

# 2. Decrypt message using the decrypted AES key
print("User A: Decrypting message with AES-256-GCM...")
with open("encrypted_message.bin", "rb") as f:
    encrypted_message_received = f.read()

# Extract IV, Tag, and Ciphertext (assuming GCM format: IV + Tag + Ciphertext)
received_iv = encrypted_message_received[:12] # First 12 bytes for IV
received_tag = encrypted_message_received[12:28] # Next 16 bytes for GCM Tag
received_ciphertext = encrypted_message_received[28:] # The rest is ciphertext

decryptor = Cipher(
    algorithms.AES(decrypted_aes_key),
    modes.GCM(received_iv, received_tag), # Pass tag for verification
    backend=default_backend()
).decryptor()

try:
    decrypted_message = decryptor.update(received_ciphertext) + decryptor.finalize()
    # GCM checks integrity during finalize(). If tag is invalid, it raises InvalidTag exception.
    with open("decrypted_message.txt", "wb") as f:
        f.write(decrypted_message)
    print("User A: Message decrypted successfully and saved to decrypted_message.txt")
    print(f"User A: Decrypted Message: {decrypted_message.decode()}")
except Exception as e: # Catches InvalidTag or other potential errors
    print(f"User A: Decryption failed! Error: {e}")