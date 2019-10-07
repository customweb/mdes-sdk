#!/usr/bin/env bash

if [ -z "${TRAVIS_TAG}" ]; 
then
	echo "[INFO] This is not tagged build. The TRAVIS_TAG is not set. Skipping before_script step.";

else
	echo "[INFO] Running before_script script. Decrypting 'wallee_M4M-sandbox.p12.enc', 'public-key-encrypt.crt.enc', 'private-key-decrypt.pem.enc'"
	
	openssl aes-256-cbc -K $encrypted_a09fc3b71c0b_key -iv $encrypted_a09fc3b71c0b_iv -in ./src/test/resources/wallee_M4M-sandbox.p12.enc -out ./src/test/resources/wallee_M4M-sandbox.p12 -d
	
	openssl aes-256-cbc -K $encrypted_a09fc3b71c0b_key -iv $encrypted_a09fc3b71c0b_iv -in ./src/test/resources/public-key-encrypt.crt.enc -out ./src/test/resources/public-key-encrypt.crt -d
	
    openssl aes-256-cbc -K $encrypted_a09fc3b71c0b_key -iv $encrypted_a09fc3b71c0b_iv -in ./src/test/resources/private-key-decrypt.pem.enc -out ./src/test/resources/private-key-decrypt.pem -d
	
fi