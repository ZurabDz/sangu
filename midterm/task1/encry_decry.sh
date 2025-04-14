echo "This file contains top secret information." > secret.txt

openssl enc -aes-128-cbc -salt -in secret.txt -out secret.enc -pass pass:42_is_an_answer 
openssl enc -d -aes-128-cbc -in secret.enc -out decrypted_secret.txt -pass pass:42_is_an_answer 

echo "Decrypted"
cat decrypted_secret.txt


echo "Diff if exists: "
diff secret.txt decrypted_secret.txt