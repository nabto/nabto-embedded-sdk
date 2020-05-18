FROM ubuntu:16.04

run apt-get update && apt-get install software-properties-common apt-transport-https ca-certificates gnupg wget -y

run add-apt-repository ppa:git-core/ppa -y

run wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | gpg --dearmor - > /etc/apt/trusted.gpg.d/kitware.gpg

run apt-add-repository 'deb https://apt.kitware.com/ubuntu/ xenial main'

run apt-get update && apt-get install build-essential cmake git ninja-build libboost-dev libboost-test-dev libboost-system-dev -y
