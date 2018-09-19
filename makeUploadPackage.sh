#!/bin/bash

. ./versionInfo

#echo "major=$major, minor=$minor, patch=$patch"
make install
pushd depends/x86_64-unknown-linux-gnu
mkdir -p ${dirRoot}
cp -Rf bin ${dirRoot}
#pwd
tar cvfz ${uploadFile} ${dirRoot}
rm -f ${dirRoot}
popd