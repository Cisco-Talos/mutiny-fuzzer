#!/bin/sh

#TODO: check that dependencies are installed (unittest, scapy)

# units
echo
echo 'UNIT TESTING RESULTS'
python3 -m unittest tests/units/*.py -b

# integration
python3 tests/integration/test_mutiny_integration.py

