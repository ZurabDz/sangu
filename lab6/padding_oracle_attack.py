#!/usr/bin/env python3

import sys
from binascii import unhexlify, hexlify
from cryptography.hazmat.primitives import padding as padding_module # Alias
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# --- Provided Setup ---
BLOCK_SIZE = 16 # AES block size is 16 bytes
KEY = b"this_is_16_bytes" # Key used by the ORACLE, not by the attacker directly

# Ciphertext = IV + encrypted blocks (from check_decrypt.py success example or similar)
# Example ciphertext (make sure this matches your lab's target)
CIPHERTEXT_HEX = (
    "746869735f69735f31365f6279746573" # IV: "this_is_16_bytes"
    "9404628dcdf3f003482b3b0648bd920b" # Block 1
    "3f60e13e89fa6950d3340adbbbb41c12" # Block 2
    "b3d1d97ef97860e9df7ec0d31d13839a" # Block 3
    "e17b3be8f69921a07627021af16430e1" # Block 4 (contains padding)
)

# The Oracle Function (provided)
def padding_oracle(ciphertext: bytes) -> bool:
    """Returns True if the ciphertext decrypts with valid padding, False otherwise."""
    # Basic length check
    if len(ciphertext) % BLOCK_SIZE != 0 or len(ciphertext) < 2 * BLOCK_SIZE:
        # print(f"Oracle: Invalid length {len(ciphertext)}")
        return False

    iv = ciphertext[:BLOCK_SIZE]
    ct = ciphertext[BLOCK_SIZE:]

    try:
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ct) + decryptor.finalize()

        # Attempt to unpad
        unpadder = padding_module.PKCS7(BLOCK_SIZE * 8).unpadder()
        unpadder.update(decrypted)
        unpadder.finalize()  # This raises ValueError if padding is incorrect
        # print(f"Oracle: Valid padding for {hexlify(ciphertext[-BLOCK_SIZE:])}")
        return True
    except (ValueError, TypeError) as e:
        # print(f"Oracle: Invalid padding for {hexlify(ciphertext[-BLOCK_SIZE:])} - {e}")
        return False
    except Exception as e:
        # Catch other potential crypto errors, though padding is primary
        print(f"Oracle: Unexpected error: {e}")
        return False

# --- Task 1 Answers ---
# 1. How padding_oracle determines validity: It decrypts the ciphertext and then
#    attempts to remove PKCS#7 padding using cryptography library's unpadder.
#    If the padding is malformed (last byte value doesn't match the number of
#    padding bytes, or values are inconsistent), the unpadder raises a ValueError,
#    which is caught, and the function returns False. Otherwise, it returns True.
# 2. Purpose of IV in CBC: To randomize the first block's encryption, ensuring
#    identical plaintexts produce different ciphertexts (with different IVs).
#    It prevents basic pattern analysis on the first block.
# 3. Why ciphertext needs to be multiple of block size: CBC operates on fixed-size
#    blocks. The input (IV + encrypted data) must align with these block boundaries
#    for the decryption process (chaining XORs and block cipher decryptions) to work.
#    Padding ensures the original *plaintext* becomes a multiple of the block size
#    before encryption.

# --- Helper Functions ---
def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XORs two byte strings of equal length."""
    # Using bytearray for potential slight performance gain and clarity
    res = bytearray(len(a))
    for i in range(len(a)):
        res[i] = a[i] ^ b[i]
    return bytes(res)

# --- Task 2: Implement Block Splitting ---
def split_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> list[bytes]:
    """Split data into blocks of the specified size."""
    if len(data) % block_size != 0:
        print(f"Warning: Data length {len(data)} is not a multiple of block size {block_size}")
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]

# --- Task 3: Implement Single Block Decryption ---
def decrypt_block(prev_block: bytes, target_block: bytes) -> bytes:
    """
    Decrypt a single block using the padding oracle attack.
    Returns the decrypted plaintext block.
    """
    assert len(prev_block) == BLOCK_SIZE
    assert len(target_block) == BLOCK_SIZE

    intermediate_state = bytearray(BLOCK_SIZE)
    crafted_prev_block = bytearray(BLOCK_SIZE) # Can start with zeros

    print(f"    Decrypting Block: {hexlify(target_block).decode()}")
    sys.stdout.flush() # Ensure output is shown progressively

    for byte_index in range(BLOCK_SIZE - 1, -1, -1):
        padding_value = BLOCK_SIZE - byte_index

        # Set suffix of crafted block: C'_prev[j] = I[j] XOR padding_value
        for i in range(byte_index + 1, BLOCK_SIZE):
            crafted_prev_block[i] = intermediate_state[i] ^ padding_value

        found = False
        for guess in range(256):
            crafted_prev_block[byte_index] = guess
            test_ciphertext = bytes(crafted_prev_block) + target_block

            if padding_oracle(test_ciphertext):
                # Check for false positive on the first byte if original padding was 0x01
                # This is a refinement: if guess == prev_block[byte_index] and padding_value == 1:
                #    # Test a different byte to confirm it wasn't just luck
                #    crafted_prev_block[byte_index-1] = (crafted_prev_block[byte_index-1] + 1) % 256 # Modify previous byte slightly
                #    test_ciphertext_confirm = bytes(crafted_prev_block) + target_block
                #    crafted_prev_block[byte_index-1] = (crafted_prev_block[byte_index-1] - 1) % 256 # Revert change
                #    if not padding_oracle(test_ciphertext_confirm):
                #         continue # Skip this guess, it was likely the original padding causing a match

                intermediate_state[byte_index] = guess ^ padding_value
                # Simple progress indicator
                print(f"\r    Found byte {byte_index} -> 0x{intermediate_state[byte_index]:02x} (padding={padding_value}, guess=0x{guess:02x})" + " "*10, end="")
                sys.stdout.flush()
                found = True
                break

        if not found:
             # Clear progress line on error
             print("\r" + " "*60 + "\r", end="")
             raise Exception(f"Could not find valid byte for index {byte_index}")

     # Clear progress line
    print("\r" + " "*60 + "\r", end="")
    plaintext_block = xor_bytes(bytes(intermediate_state), prev_block)
    print(f"    Decrypted Block (Hex): {hexlify(plaintext_block).decode()}")
    return plaintext_block

# --- Task 4: Implement Full Attack ---
def padding_oracle_attack(ciphertext: bytes) -> bytes:
    """Perform the padding oracle attack on the entire ciphertext."""
    if len(ciphertext) % BLOCK_SIZE != 0 or len(ciphertext) < 2 * BLOCK_SIZE:
         raise ValueError("Ciphertext length is invalid for CBC with IV")

    blocks = split_blocks(ciphertext, BLOCK_SIZE)
    # IV is blocks[0]

    decrypted_plaintext = b''

    # Iterate C1, C2, ..., Cn
    for i in range(1, len(blocks)):
        prev_block = blocks[i-1]  # IV for i=1, C_{i-1} otherwise
        target_block = blocks[i]
        print(f"\n[*] Attacking Block {i}/{len(blocks)-1}...")
        plaintext_block = decrypt_block(prev_block, target_block)
        decrypted_plaintext += plaintext_block
        # print(f"[*] Intermediate Plaintext (hex): {hexlify(decrypted_plaintext).decode()}")

    return decrypted_plaintext

# --- Task 5: Implement Plaintext Decoding ---
def unpad_and_decode(plaintext: bytes) -> str:
    """Attempt to unpad and decode the plaintext."""
    print(f"\n[*] Attempting to unpad {len(plaintext)} bytes...")
    try:
        unpadder = padding_module.PKCS7(BLOCK_SIZE * 8).unpadder()
        unpadded_data = unpadder.update(plaintext) + unpadder.finalize()
        print(f"[*] Unpadding successful. Unpadded length: {len(unpadded_data)}")
        print(f"[*] Unpadded Hex: {hexlify(unpadded_data).decode()}")
    except ValueError as e:
        print(f"[!] Error during PKCS#7 unpadding: {e}")
        print(f"[!] Will attempt to decode raw data. Padding might be incorrect.")
        # Fallback to using the potentially padded data directly
        unpadded_data = plaintext # Keep original data if unpadding fails

    try:
        # Attempt to decode using UTF-8
        decoded_string = unpadded_data.decode('utf-8')
        print("[*] Decoding successful (UTF-8).")
        return decoded_string
    except UnicodeDecodeError as e:
        print(f"[!] Error decoding unpadded data as UTF-8: {e}")
        # Provide useful info if decoding fails
        return f"<Decoding Error - Unpadded Hex: {hexlify(unpadded_data).decode()}>"


# --- Main Execution ---
if __name__ == "__main__":
    print("--- Padding Oracle Attack Lab ---")
    try:
        ciphertext = unhexlify(CIPHERTEXT_HEX)
        print(f"[*] Target Ciphertext Length: {len(ciphertext)} bytes")
        print(f"[*] IV: {hexlify(ciphertext[:BLOCK_SIZE]).decode()}")
        print(f"[*] Encrypted Blocks: {len(ciphertext)//BLOCK_SIZE - 1}")

        recovered = padding_oracle_attack(ciphertext)

        print("\n[+] Decryption complete!")
        print(f"[*] Recovered plaintext (raw bytes): {recovered}")
        print(f"[*] Recovered Hex: {hexlify(recovered).decode()}")

        decoded = unpad_and_decode(recovered)
        print("\n[+] Final plaintext:")
        print(decoded)

    except Exception as e:
        print(f"\n[!!!] Error occurred during attack: {e}")
        import traceback
        traceback.print_exc()