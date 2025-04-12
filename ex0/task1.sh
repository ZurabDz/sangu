# generate RSA Key Pair
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# encrypt message.txt using pkey
openssl pkeyutl -encrypt -pubin -inkey public.pem -in message.txt -out message_rsa_encrypted.bin
openssl pkeyutl -decrypt -inkey private.pem -in message_rsa_encrypted.bin -out message_rsa_decrypted.txt

# verify
echo "Diff will be shown if decrypted file is different than original" 
diff message.txt message_rsa_decrypted.txt

# 42 - is the meaning of life
openssl rand 42 > aes_key.bin
openssl rand 16 > aes_iv.bin

KEY=$(xxd -p aes_key.bin | tr -d '\n')
IV=$(xxd -p aes_iv.bin | tr -d '\n')

openssl enc -aes-256-cbc -K $KEY -iv $IV -in message.txt -out message_aes_encrypted.bin
openssl enc -d -aes-256-cbc -K $KEY -iv $IV -in message_aes_encrypted.bin -out message_aes_decrypted.txt

echo "Diff will be shown if decrypted file is different than original" 
diff message.txt message_aes_decrypted.txt