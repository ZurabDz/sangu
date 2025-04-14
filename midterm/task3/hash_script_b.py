# save as hmac_script.py
import hmac
import hashlib

key = b"aliens_are_real"  # Key must be bytes
filename = "data.txt"

hasher = hmac.new(key, digestmod=hashlib.sha256)

with open(filename, 'rb') as file:
    buf = file.read()
    hasher.update(buf)

print(f"HMAC-SHA256: {hasher.hexdigest()}")