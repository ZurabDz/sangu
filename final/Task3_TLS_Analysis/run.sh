TARGET_HOST="google.com"
TARGET_PORT="443"

# Run openssl s_client and save output
# Use </dev/null to prevent waiting for stdin
# Use -servername for SNI, which is often required
openssl s_client -connect ${TARGET_HOST}:${TARGET_PORT} -servername ${TARGET_HOST} -showcerts </dev/null > Task3_TLS_Analysis/openssl_output.txt 2>&1
# 2>&1 redirects stderr too, which might contain useful info/errors

echo "OpenSSL output saved to Task3_TLS_Analysis/openssl_output.txt"