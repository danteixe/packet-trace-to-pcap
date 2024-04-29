#!/bin/bash
# File: testing_test.sh
# Version: Bash
# Author: Daniel Teixeira (danteixe@cisco.com)
# Description: With the results compiled into PCAP
# files, we can compare the results with the expected
# results to confirm that the program is running as
# expected.

echo "Running tests without splitting. For each PCAP file, run a 'diff' between the actual and expected results."

rc=0

diff -r -q tests/expected-results tests/test-results >> /dev/null
rc=$((rc + $?))

cd tests/expected-results
find . -type f -name '*.pcap' -exec diff {} ../test-results/{} \;  >> /dev/null
rc=$((rc + $?))
cd ../..

echo "Running tests with splitting."

diff -r -q tests/expected-results-split tests/test-results-split >> /dev/null
rc=$((rc + $?))

cd tests/expected-results-split
find . -type f -name '*.pcap' -exec diff {} ../test-results-split/{} \; >> /dev/null
rc=$((rc + $?))

echo $rc
exit $rc