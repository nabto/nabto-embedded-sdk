#!/bin/bash

SCRIPT_DIR="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

SANDBOX_DIR=$SCRIPT_DIR/../..
BUILD_ROOT=$SANDBOX_DIR/build/nabto-embedded-sdk
ARTIFACTS_ROOT=$SANDBOX_DIR/artifacts/nabto-embedded-sdk

cd $SCRIPT_DIR/linux

UID=`id -u` GID=`id -g` docker-compose run build-armhf

UID=`id -u` GID=`id -g` docker-compose run build-linux64
