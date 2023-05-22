FROM ubuntu:18.04

RUN apt update && apt install -y gcc-8-aarch64-linux-gnu g++-8-aarch64-linux-gnu wget apt-transport-https gnupg software-properties-common git

# add a current cmake
run wget -q -O - https://apt.kitware.com/keys/kitware-archive-latest.asc | apt-key add -
run apt-add-repository 'deb https://apt.kitware.com/ubuntu/ bionic main'

run apt-get update && apt-get install build-essential cmake git -y
