#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

set -e

SOURCE_DIR=${DIR}/../../..
BUILD_DIR=${SOURCE_DIR}/build/cmake_fetchcontent
INSTALL_DIR=${BUILD_DIR}/install
mkdir -p ${BUILD_DIR}
cd ${BUILD_DIR}
cmake -DCMAKE_INSTALL_PREFIX=${INSTALL_DIR} ${DIR}
make -j16
./test
