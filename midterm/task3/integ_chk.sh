sed -i.bak 's/Never/Xever/' data.txt 

cat data.txt


openssl dgst -sha256 -hmac "secretkey123" data.txt

python hash_script_b.py
