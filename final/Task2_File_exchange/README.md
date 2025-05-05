# Task 2: Secure File Exchange Using RSA + AES - Flow and Comparison

This task demonstrates a secure file exchange protocol from Alice to Bob using hybrid encryption (RSA + AES) and includes an integrity check.

## Encryption/Decryption Flow:

1.  **Key Generation (Bob):**
    *   An RSA key pair (2048-bit) is generated for Bob.
    *   The public key (`bob_public.pem`) is shared with Alice.
    *   The private key (`bob_private.pem`) is kept secret by Bob.

2.  **File Preparation (Alice):**
    *   Alice creates the plaintext file (`alice_message.txt`).
    *   Alice computes the SHA-256 hash of the original file content for later integrity verification.

3.  **Encryption (Alice):**
    *   **AES Key/IV Generation:** Alice generates a random 256-bit AES key and a random 16-byte Initialization Vector (IV).
    *   **File Encryption (AES-CBC):**
        *   The content of `alice_message.txt` is padded using PKCS7 to be a multiple of the AES block size (16 bytes).
        *   The padded data is encrypted using AES-256 in CBC (Cipher Block Chaining) mode with the generated AES key and IV.
        *   The IV is prepended to the resulting ciphertext. This combined data is saved as `encrypted_file.bin`.
    *   **AES Key Encryption (RSA):**
        *   Alice encrypts the *AES key* (not the IV) using Bob's *public RSA key* (loaded from `bob_public.pem`). OAEP padding is used.
        *   The encrypted AES key is saved as `aes_key_encrypted.bin`.
    *   Alice sends `encrypted_file.bin` and `aes_key_encrypted.bin` to Bob.

4.  **Decryption (Bob):**
    *   **AES Key Decryption (RSA):**
        *   Bob uses his *private RSA key* (loaded from `bob_private.pem`) to decrypt `aes_key_encrypted.bin`, recovering the AES key.
    *   **File Decryption (AES-CBC):**
        *   Bob reads `encrypted_file.bin`. He separates the prepended IV (first 16 bytes) from the rest of the ciphertext.
        *   Using the *decrypted AES key* and the extracted IV, Bob decrypts the ciphertext using AES-256-CBC.
        *   The PKCS7 padding is removed from the decrypted data to recover the original file content.
        *   The result is saved as `decrypted_message.txt`.

5.  **Integrity Verification (Bob):**
    *   Bob computes the SHA-256 hash of the content in `decrypted_message.txt`.
    *   Bob compares this computed hash with the original hash (which Alice would need to send separately or Bob might know beforehand - in this script, it's known from the start).
    *   If the hashes match, the integrity of the file is confirmed.

## Comparison: AES vs. RSA

| Feature       | AES (Advanced Encryption Standard)                     | RSA (Rivest–Shamir–Adleman)                         |
| :------------ | :----------------------------------------------------- | :-------------------------------------------------- |
| **Type**      | Symmetric-key algorithm                                | Asymmetric-key algorithm                            |
| **Keys**      | Uses the *same* secret key for encryption & decryption | Uses a *pair* of keys: public (encryption) & private (decryption) |
| **Speed**     | Very Fast (hardware acceleration common)               | Significantly Slower (computationally intensive)    |
| **Use Case**  | Encrypting bulk data (files, streams, messages)        | Encrypting small data (like symmetric keys), digital signatures, key exchange |
| **Key Length**| 128, 192, or 256 bits                                  | Typically 2048 bits or higher for good security     |
| **Security**  | Considered secure against known attacks (when used properly with good modes like GCM or CBC+HMAC) | Secure based on the difficulty of factoring large numbers (requires adequate key length, proper padding like OAEP) |
| **Key Mgmt**  | Key distribution is challenging (need a secure channel) | Key distribution is easier (public key can be shared openly) |

**Hybrid Approach:** The protocol used here combines the best of both:
*   RSA's asymmetric nature simplifies the secure exchange of the session key (the AES key).
*   AES's symmetric nature provides high-speed encryption for the actual file content.

This hybrid model is the standard approach for protocols like TLS/SSL and PGP.