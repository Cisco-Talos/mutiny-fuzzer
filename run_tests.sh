#!/bin/sh

# check that unittest and scapy are installed
#TODO: ^^^
# execute unit tests
python3 -m unittest tests/units/*.py

# execute integration tests
python3 tests/integration/test_mutiny_integration.py
