#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

SRC_DIR=${DIR}/..

BUILD_DIR=${DIR}/../../build/nabto-embedded-sdk
mkdir -p ${BUILD_DIR}

INSTALL_DIR=${DIR}/../../artifacts/nabto-embedded-sdk

cd ${BUILD_DIR}

cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=${INSTALL_DIR} ${SRC_DIR} || exit 1
make -j install || exit 1
