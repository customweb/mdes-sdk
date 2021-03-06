#!/usr/bin/env bash

if [ -z "${TRAVIS_TAG}" ]; 
then
	echo "[INFO] This is not tagged build. The TRAVIS_TAG is not set. Skipping deployment.";
else
	echo "[INFO] Running deployment based on the mvn_settings.xml"
	mvn deploy -e -P sign,build-extras --settings mvn_settings.xml;
	exit 1;
	# TODO even returning "exit 1;" Travis does not abort the build, and eventually it is mark as "passing".
fi