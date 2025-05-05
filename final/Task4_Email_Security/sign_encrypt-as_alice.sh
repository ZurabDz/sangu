gpg --encrypt --sign --armor \
    --recipient bob@example.com \
    --local-user alice@example.com \
    -o signed_message.asc \
    original_message.txt