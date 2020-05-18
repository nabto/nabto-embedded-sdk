FROM ubuntu:18.04

run apt update

run apt-get install apt-transport-https ca-certificates gnupg software-properties-common wget

run wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | gpg --dearmor - > /etc/apt/trusted.gpg.d/kitware.gpg

run apt-add-repository 'deb https://apt.kitware.com/ubuntu/ bionic main'

RUN apt update && apt install -y gcc-8-arm-linux-gnueabihf cmake g++-8-arm-linux-gnueabihf git ninja-build libboost-dev libboost-test-dev libboost-system-dev
