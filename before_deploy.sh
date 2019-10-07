#!/usr/bin/env bash

if [ -z "${TRAVIS_TAG}" ]; 
then
	echo "[INFO] This is not tagged build. The TRAVIS_TAG is not set. Skipping before_deploy step.";

else
	echo "[INFO] Running before_deploy script. Decrypting 'codesigning.asc.enc'..."
	openssl aes-256-cbc -K $encrypted_5d3bf8e2f4dc_key -iv $encrypted_5d3bf8e2f4dc_iv -in codesigning.asc.enc -out codesigning.asc -d && \
	gpg --fast-import codesigning.asc;
	
	openssl aes-256-cbc -K $encrypted_a09fc3b71c0b_key -iv $encrypted_a09fc3b71c0b_iv -in wallee_M4M-sandbox.p12.enc -out wallee_M4M-sandbox.p12 -d
	
	openssl aes-256-cbc -K $encrypted_a09fc3b71c0b_key -iv $encrypted_a09fc3b71c0b_iv -in public-key-encrypt.crt.enc -out public-key-encrypt.crt -d
	
    openssl aes-256-cbc -K $encrypted_a09fc3b71c0b_key -iv $encrypted_a09fc3b71c0b_iv -in private-key-decrypt.pem.enc -out private-key-decrypt.pem -d
	
fi