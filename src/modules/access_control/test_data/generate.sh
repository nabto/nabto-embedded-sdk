#!/bin/bash

# Read all the .json files and convert them to c strings which can be
# included directly into the test code

for A in `ls *.json`; do
    echo -n "const char* `basename $A .json` = \"" > $A.c
    cat $A | awk '{$1=$1};1' | sed -e 's/\"/\\\"/g' | tr -d '\n' >> $A.c
    echo -n \" >> $A.c
done;
