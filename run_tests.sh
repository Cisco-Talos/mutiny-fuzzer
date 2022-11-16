#!/bin/sh

# check that unittest and scapy are installed
#TODO: ^^^
# execute unit tests
python3 -m unittest tests/units/*.py
# TODO: pipe above output and cut out test results

# execute integration tests
python3 tests/integration/test_mutiny_integration.py
# TODO: pipe above output and cut out test results

# if -v: print total output
# else: just print results in one nicely formatted line
