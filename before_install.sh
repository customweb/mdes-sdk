#!/usr/bin/env bash

echo "[INFO] Running before_script script. Decrypting 'wallee_M4M-sandbox.p12.enc', 'public-key-encrypt.crt.enc', 'private-key-decrypt.pem.enc'";	
# the private key should be load before-install, because it is required for running the junit
openssl aes-256-cbc -K $encrypted_a09fc3b71c0b_key -iv $encrypted_a09fc3b71c0b_iv -in ./src/test/resources/private-key-decrypt.pem.enc -out ./src/test/resources/private-key-decrypt.pem -d
