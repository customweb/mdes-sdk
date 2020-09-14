#!/usr/bin/env bash

echo "[INFO] Running before_install script. Decrypting private key."
# the private key should be load before-install, because it is required for running the junit
openssl aes-256-cbc -K $encrypted_a09fc3b71c0b_key -iv $encrypted_a09fc3b71c0b_iv -in ./src/test/resources/e5fec5dc4e2fab3c968dbe78a905Private-Key-Decrypt.pem.enc -out ./src/test/resources/e5fec5dc4e2fab3c968dbe78a905Private-Key-Decrypt.pem -d;