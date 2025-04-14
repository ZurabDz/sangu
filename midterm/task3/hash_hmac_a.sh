echo "Trust, but always verify. People don't always lie cause they want to(oops I modfied text hehe)" > data.txt
openssl dgst -sha256 data.txt
sha256sum data.txt

echo "running script"
python hash_script_a.py
