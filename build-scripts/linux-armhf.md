
Start a docker container

docker run --rm -it -v `pwd`/sandbox:/sandbox ubuntu:18.04

# apt update
# apt install gcc-8-arm-linux-gnueabihf cmake g++-8-arm-linux-gnueabihf
# export CC=arm-linux-gnueabihf-gcc-8
# export CXX=arm-linux-gnueabihf-g++-8

build software as normal inside container.
