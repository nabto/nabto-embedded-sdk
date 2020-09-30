#!/bin/bash

SCRIPT_DIR="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

SANDBOX_DIR=$SCRIPT_DIR/../..
BUILD_ROOT=$SANDBOX_DIR/build/nabto-embedded-sdk
ARTIFACTS_ROOT=$SANDBOX_DIR/artifacts/nabto-embedded-sdk

cd $SCRIPT_DIR/linux

# cleanup
rm -rf ${ARTIFACTS_ROOT}/armhf
rm -rf ${ARTIFACTS_ROOT}/linux64

export USER_ID=`id -u`
export GROUP_ID=`id -g`

docker-compose run build-armhf

docker-compose run build-linux64
