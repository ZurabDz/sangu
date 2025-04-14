openssl ecparam -name prime256v1 -genkey -noout -out ecc_private.pem
openssl ec -in ecc_private.pem -pubout -out ecc_public.pem


echo "Elliptic Curves are efficient.​" > ecc.txt
openssl dgst -sha256 -sign ecc_private.pem -out ecc.sig ecc.txt

openssl dgst -sha256 -verify ecc_public.pem -signature ecc.sig ecc.txt