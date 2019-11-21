FROM ubuntu:16.04

run apt-get update && apt-get install software-properties-common -y

run add-apt-repository ppa:git-core/ppa -y

run apt-get update && apt-get install build-essential cmake git ninja-build -y
