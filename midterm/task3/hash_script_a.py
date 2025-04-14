# save as hash_script.py
import hashlib

filename = "data.txt"
hasher = hashlib.sha256()

with open(filename, 'rb') as file:
    buf = file.read()
    hasher.update(buf)

print(f"SHA-256 Hash: {hasher.hexdigest()}")