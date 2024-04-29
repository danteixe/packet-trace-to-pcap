#!/bin/bash
# File: testing_build.sh
# Version: Bash
# Author: Daniel Teixeira (danteixe@cisco.com)
# Description: Run the script on the testing
# examples and generate the resulting PCAP files
# without splitting and while splitting the outputs
# into ingress-egress files.

echo "---- Generating the testing PCAPs without splitting. ----"

echo "1. Generate PCAPs"
find tests/test-data -type f -name 'test*.txt' -exec python3 pt_process.py {} \;
rc=$?

if (test $rc -ne 0)
then
    exit $rc
fi

echo "2. Remove previous files (better safe than sorry)"
rm -r tests/test-results

echo "3. Create the directory and move the files."
mkdir tests/test-results
mv tests/test-data/*.pcap tests/test-results

echo "---- Generate the testing PCAPs with splitting. ----"

echo "1. Generate PCAPs"
find tests/test-data -type f -name 'test*.txt' -exec python3 pt_process.py {} -s \;
rc=$?

if (test $rc -ne 0)
then
    exit $rc
fi

echo "2. Remove previous files (better safe than sorry)"
rm -r tests/test-results-split

echo "3. Create the directory and move the files."
mkdir tests/test-results-split
mv tests/test-data/*.pcap tests/test-results-split

exit 0 