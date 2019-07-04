#!/bin/bash

# Read all the .json files and convert them to c strings which can be
# included directly into the test code

for A in `ls *.json`; do
    echo "// Generated source file do not edit." > $A.c
    echo -n "const char* `basename $A .json` = \"" >> $A.c
    cat $A | awk '{$1=$1};1' | sed -e 's/\"/\\\"/g' | tr -d '\n' >> $A.c
    echo -n \" >> $A.c
done;
