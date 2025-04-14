openssl genpkey -genparam -algorithm DH -out dh_params.pem

openssl genpkey -paramfile dh_params.pem -out alice_private_key.pem
openssl pkey -in alice_private_key.pem -pubout -out alice_public_key.pem 

openssl genpkey -paramfile dh_params.pem -out bob_private_key.pem
openssl pkey -in bob_private_key.pem -pubout -out bob_public_key.pem

echo "--- Alice's Public Key ---"
cat alice_public_key.pem
echo "--- Bob's Public Key ---"
cat bob_public_key.pem

openssl pkeyutl -derive -inkey alice_private_key.pem -peerkey bob_public_key.pem -out alice_shared_secret.bin
openssl pkeyutl -derive -inkey bob_private_key.pem -peerkey alice_public_key.pem -out bob_shared_secret.bin

# Compare using cmp (no output means identical)
cmp alice_shared_secret.bin bob_shared_secret.bin

# Or compare hashes
openssl dgst -sha256 alice_shared_secret.bin
openssl dgst -sha256 bob_shared_secret.bin 