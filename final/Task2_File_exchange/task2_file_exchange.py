import os
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding # For AES CBC padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# --- Key Generation for Bob ---
print("Generating RSA key pair for Bob...")
private_key_bob = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key_bob = private_key_bob.public_key()

# Save Bob's keys to PEM files
pem_private = private_key_bob.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption() # No password on private key for simplicity
)
pem_public = public_key_bob.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

with open("bob_private.pem", "wb") as f:
    f.write(pem_private)
with open("bob_public.pem", "wb") as f:
    f.write(pem_public)
print("Bob's RSA key pair saved to bob_private.pem and bob_public.pem")

# --- Alice: Prepare and Encrypt File ---
print("\nAlice: Preparing file and encrypting...")
# 1. Create plaintext file
file_content = b"This is the content of the secret file that Alice wants to send to Bob securely."
with open("alice_message.txt", "wb") as f:
    f.write(file_content)
print("Alice: Original file alice_message.txt created.")

# Compute original hash for integrity check later
original_hash = hashlib.sha256(file_content).hexdigest()
print(f"Alice: Original file SHA-256 hash: {original_hash}")

# 2. Generate random AES-256 key and IV
aes_key = os.urandom(32)  # 256 bits
iv = os.urandom(16)       # AES block size is 16 bytes, common IV size for CBC

# 3. Encrypt the file using AES-256 (Using CBC mode as IV is explicitly mentioned)
print("Alice: Encrypting file with AES-256-CBC...")
cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()

# Apply PKCS7 padding before encryption
padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
padded_data = padder.update(file_content) + padder.finalize()

ciphertext = encryptor.update(padded_data) + encryptor.finalize()

# Prepend IV to the ciphertext (common practice)
encrypted_file_content = iv + ciphertext
with open("encrypted_file.bin", "wb") as f:
    f.write(encrypted_file_content)
print("Alice: Encrypted file saved to encrypted_file.bin (IV prepended)")

# 4. Encrypt the AES key using Bob's RSA public key
print("Alice: Encrypting AES key with Bob's public RSA key...")
# Load Bob's public key (as Alice would typically do)
with open("bob_public.pem", "rb") as key_file:
    public_key_bob_loaded = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

aes_key_encrypted = public_key_bob_loaded.encrypt(
    aes_key,
    rsa_padding.OAEP(
        mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
with open("aes_key_encrypted.bin", "wb") as f:
    f.write(aes_key_encrypted)
print("Alice: Encrypted AES key saved to aes_key_encrypted.bin")

# --- Bob: Decrypt File and Verify Integrity ---
print("\nBob: Receiving files and decrypting...")
# Assume Bob received encrypted_file.bin and aes_key_encrypted.bin

# 1. Decrypt the AES key using Bob's RSA private key
print("Bob: Decrypting AES key with private RSA key...")
# Load Bob's private key
with open("bob_private.pem", "rb") as key_file:
    private_key_bob_loaded = serialization.load_pem_private_key(
        key_file.read(),
        password=None, # No password was set
        backend=default_backend()
    )

with open("aes_key_encrypted.bin", "rb") as f:
    aes_key_encrypted_received = f.read()

decrypted_aes_key = private_key_bob_loaded.decrypt(
    aes_key_encrypted_received,
    rsa_padding.OAEP(
        mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print("Bob: AES key decrypted.")

# 2. Decrypt the file using the decrypted AES key and IV
print("Bob: Decrypting file with AES-256-CBC...")
with open("encrypted_file.bin", "rb") as f:
    encrypted_file_received = f.read()

# Extract IV (first 16 bytes) and ciphertext
received_iv = encrypted_file_received[:16]
received_ciphertext = encrypted_file_received[16:]

cipher = Cipher(algorithms.AES(decrypted_aes_key), modes.CBC(received_iv), backend=default_backend())
decryptor = cipher.decryptor()
padded_decrypted_data = decryptor.update(received_ciphertext) + decryptor.finalize()

# Remove PKCS7 padding
unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
decrypted_data = unpadder.update(padded_decrypted_data) + unpadder.finalize()

with open("decrypted_message.txt", "wb") as f:
    f.write(decrypted_data)
print("Bob: File decrypted and saved to decrypted_message.txt")
print(f"Bob: Decrypted Content: {decrypted_data.decode()}")

# 3. After decryption, compute SHA-256 hash for integrity verification
decrypted_hash = hashlib.sha256(decrypted_data).hexdigest()
print(f"Bob: Decrypted file SHA-256 hash: {decrypted_hash}")

# Compare hashes
print("\nIntegrity Check:")
print(f"  Original hash (Alice): {original_hash}")
print(f"  Decrypted hash (Bob):  {decrypted_hash}")
if original_hash == decrypted_hash:
    print("  SUCCESS: Hashes match! File integrity verified.")
else:
    print("  FAILURE: Hashes DO NOT match! File may have been tampered with or decryption failed.")