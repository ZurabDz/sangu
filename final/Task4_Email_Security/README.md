How the PGP Signature Validates the Sender (Alice)

When Bob receives the signed and encrypted message (`signed_message.asc`) and runs `gpg --decrypt`, the following happens regarding the signature:

1.  **Decryption:** GPG first uses Bob's private key to decrypt the outer layer of the message, revealing the inner content which includes the original message *and* Alice's digital signature.

2.  **Signature Identification:** GPG identifies the signature block and notes the Key ID of the key that was used to create the signature (Alice's Key ID).

3.  **Hash Computation:** GPG takes the decrypted original message content (before the signature was applied) and computes its cryptographic hash using the same algorithm Alice used when signing (e.g., SHA-256).

4.  **Signature Decryption:** GPG uses the *sender's* (Alice's) *public key* (which Bob must have in his keyring) to "decrypt" the signature block. A digital signature is essentially a hash of the message that has been encrypted with the sender's *private key*. Decrypting it with the sender's public key recovers the original hash that Alice computed.

5.  **Hash Comparison:** GPG compares the hash it computed in Step 3 with the hash it recovered from the signature in Step 4.

6.  **Validation Result:**
    *   **If the hashes match:** It proves two things:
        *   **Authenticity:** Only someone with Alice's private key could have encrypted the hash that decrypts correctly with Alice's public key. Therefore, the message must have originated from Alice.
        *   **Integrity:** The message content has not been altered since Alice signed it, because any change would result in a different hash in Step 3.
    *   **If the hashes do not match:** The signature is invalid. This means either the message was tampered with, or it wasn't actually signed by the key corresponding to the public key Bob used for verification.

GPG displays a message like "Good signature from 'Alice <alice@example.com>'" if verification is successful, confirming both the sender's identity (based on the trust Bob places in Alice's public key) and the message integrity.