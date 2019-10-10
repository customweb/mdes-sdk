#!/usr/bin/env bash

if [ -z "${TRAVIS_TAG}" ]; 
then
	echo "[INFO] This is not tagged build. The TRAVIS_TAG is not set. Skipping deployment.";
else
	echo "[INFO] Running deployment based on the mvn_settings.xml"
	mvn deploy -e -P sign,build-extras --settings mvn_settings.xml;
	
	if [ $? -eq 0 ]
	then
		exit 0;
	else
	  echo "[ERROR] Deployment failed with exit code $?."
	  exit 1;
	fi	
fi