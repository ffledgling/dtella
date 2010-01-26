#!/bin/sh

# Make sure we're running in the tests directory.
cd $(dirname $0)

pass=1
for testfile in test_*.py
do
    ./$testfile
    if [ $? -ne 0 ]; then
        pass=0
    fi
done
if [ $pass -eq 1 ]; then
    echo "ALL TESTS PASSED"
    exit 0
else
    echo "SOME TESTS FAILED"
    exit 1
fi
