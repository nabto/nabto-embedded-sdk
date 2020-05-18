FROM ubuntu:18.04

RUN apt update && apt install -y gcc-8-arm-linux-gnueabihf cmake g++-8-arm-linux-gnueabihf git ninja-build libboost-dev libboost-test-dev libboost-system-dev