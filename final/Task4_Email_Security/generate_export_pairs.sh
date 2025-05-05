# Generate Alice's key (no passphrase for simplicity in this example)
gpg --batch --passphrase '' --quick-gen-key alice@example.com default default never
# Generate Bob's key
gpg --batch --passphrase '' --quick-gen-key bob@example.com default default never

# List keys to confirm
gpg --list-keys

# Export Alice's public key
gpg --export --armor alice@example.com > alice_pub.asc
# Export Alice's private key (USE WITH CAUTION - normally not shared!)
gpg --export-secret-keys --armor alice@example.com > alice_priv.key

# Export Bob's public key
gpg --export --armor bob@example.com > bob_pub.asc
# Export Bob's private key (USE WITH CAUTION)
gpg --export-secret-keys --armor bob@example.com > bob_priv.key