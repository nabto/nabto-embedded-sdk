#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

set -e
set -v

export CC=gcc
export CXX=g++

CURRENT_DIR=$(pwd)

NABTO_EMBEDDED_SDK_SOURCE_DIR=${DIR}/../../..
NABTO_EMBEDDED_SDK_BUILD_DIR=${CURRENT_DIR}/nabto_embedded_sdk_build
INSTALL_DIR=${CURRENT_DIR}/install

mkdir -p ${NABTO_EMBEDDED_SDK_BUILD_DIR}
mkdir -p ${INSTALL_DIR}

cd ${NABTO_EMBEDDED_SDK_BUILD_DIR}
cmake -DCMAKE_INSTALL_PREFIX=${INSTALL_DIR} ${NABTO_EMBEDDED_SDK_SOURCE_DIR}
make -j 16 install

cd ${CURRENT_DIR}
gcc -I${INSTALL_DIR}/include -L${INSTALL_DIR}/lib ${DIR}/test.c -lnabto_device -levent_extra -levent_pthreads -levent_core -lnn -lnabto_mdns -lnabto_stream -lnabto_stun -lnabto_coap -ltinycbor -lmbedtls -lmbedcrypto -lmbedx509
