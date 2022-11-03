#!/bin/bash

DIR="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cd $DIR

if [ $# != 1 ]; then
	echo "Usage: $0 <binary>"
	exit 1
fi

BIN=$1


# Test input [pem raw string]
# Test output [pem raw fingerprint]
# Test generate

# cert as output is not as easy to test as it changes between executions
# maybe test it later


# Test 1: convert pem to pem
$BIN -i testkey.pem --input-format pem --output-format pem --output out.txt

diff testkey.pem out.txt

if [ $? != 0 ]; then
    echo "Test 1 Failure!"
else
    echo "Test 1 Success"
fi

# Test 2: convert pem to raw
$BIN -i testkey.pem --input-format pem --output-format raw --output out.txt

diff testkey.raw out.txt

if [ $? != 0 ]; then
    echo "Test 2 Failure!"
else
    echo "Test 2 Success"
fi

# Test 3: convert pem to fingerprint
$BIN -i testkey.pem --input-format pem --output-format fingerprint --output out.txt

diff testkey.txt out.txt

if [ $? != 0 ]; then
    echo "Test 3 Failure!"
else
    echo "Test 3 Success"
fi

# Test 4: convert raw to pem
$BIN -i testkey.raw --input-format raw --output-format pem --output out.txt

diff testkey.pem out.txt

if [ $? != 0 ]; then
    echo "Test 4 Failure!"
else
    echo "Test 4 Success"
fi

# Test 5: convert raw to raw
$BIN -i testkey.raw --input-format raw --output-format raw --output out.txt

diff testkey.raw out.txt

if [ $? != 0 ]; then
    echo "Test 5 Failure!"
else
    echo "Test 5 Success"
fi

# Test 6: convert raw to fingerprint
$BIN -i testkey.raw --input-format raw --output-format fingerprint --output out.txt

diff testkey.txt out.txt

if [ $? != 0 ]; then
    echo "Test 6 Failure!"
else
    echo "Test 6 Success"
fi

RAW=`cat testkey.raw`

# Test 7: convert string to pem
$BIN -s ${RAW} --input-format raw --output-format pem --output out.txt

diff testkey.pem out.txt

if [ $? != 0 ]; then
    echo "Test 7 Failure!"
else
    echo "Test 7 Success"
fi

# Test 8: convert raw to raw
$BIN -s ${RAW} --input-format raw --output-format raw --output out.txt

diff testkey.raw out.txt

if [ $? != 0 ]; then
    echo "Test 8 Failure!"
else
    echo "Test 8 Success"
fi

# Test 9: convert raw to fingerprint
$BIN -s ${RAW} --input-format raw --output-format fingerprint --output out.txt

diff testkey.txt out.txt

if [ $? != 0 ]; then
    echo "Test 9 Failure!"
else
    echo "Test 9 Success"
fi
