#!/bin/bash

./makeUploadPackage.sh

. ./versionInfo

pushd depends/x86_64-unknown-linux-gnu
#pwd
#echo ${uploadFile}

curl -F "file=@${uploadFile}" http://gitlab.hdactech.com:8080/express/upload

popd
