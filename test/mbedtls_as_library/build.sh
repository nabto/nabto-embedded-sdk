#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

DIR=`pwd`

MBEDTLS_DIR=${DIR}/mbedtls
MBEDTLS_BUILD_DIR=${DIR}/mbedtls_build
MBEDTLS_INSTALL_DIR=${DIR}/mbedtls_install

NABTO_BUILD_DIR=${DIR}/nabto


mkdir -p ${MBEDTLS_DIR}
cd ${MBEDTLS_DIR}
curl -sSL https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v3.4.0.tar.gz | tar -xzf - --strip-components=1

MBEDTLS_BUILD_DIR=${DIR}/mbedtls_build

mkdir ${MBEDTLS_BUILD_DIR}
cd ${MBEDTLS_BUILD_DIR}
cmake -DCMAKE_INSTALL_PREFIX=${MBEDTLS_INSTALL_DIR} -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DUSE_SHARED_MBEDTLS_LIBRARY=On ../mbedtls
make -j 8
make install

mkdir ${NABTO_BUILD_DIR}
cd ${NABTO_BUILD_DIR}
cmake -DNABTO_DEVICE_MBEDTLS_PROVIDER=package -DMbedTLS_DIR=${MBEDTLS_INSTALL_DIR}/lib/cmake/MbedTLS ${SCRIPT_DIR}/../..

make -j 8
