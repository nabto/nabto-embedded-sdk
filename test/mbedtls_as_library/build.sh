#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

SOURCE_DIR=${SCRIPT_DIR}/../..
BUILD_DIR=${SOURCE_DIR}/build/mbedtls_as_library


MBEDTLS_DIR=${BUILD_DIR}/mbedtls
MBEDTLS_BUILD_DIR=${BUILD_DIR}/mbedtls_build
MBEDTLS_INSTALL_DIR=${BUILD_DIR}/mbedtls_install

NABTO_BUILD_DIR=${BUILD_DIR}/nabto


mkdir -p ${MBEDTLS_DIR}
cd ${MBEDTLS_DIR}
curl -sSL https://github.com/Mbed-TLS/mbedtls/releases/download/v3.6.0/mbedtls-3.6.0.tar.bz2 | tar -xjf - --strip-components=1

mkdir -p ${MBEDTLS_BUILD_DIR}
cd ${MBEDTLS_BUILD_DIR}
cmake -DCMAKE_INSTALL_PREFIX=${MBEDTLS_INSTALL_DIR} -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DUSE_SHARED_MBEDTLS_LIBRARY=On ../mbedtls
make -j 8
make install

mkdir ${NABTO_BUILD_DIR}
cd ${NABTO_BUILD_DIR}
cmake -DNABTO_DEVICE_USE_SYSTEM_MBEDTLS=ON -DMbedTLS_DIR=${MBEDTLS_INSTALL_DIR}/lib/cmake/MbedTLS ${SCRIPT_DIR}/../..

make -j 8
