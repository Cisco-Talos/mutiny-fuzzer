from argparse import Namespace
import time
import traceback
import os
import threading
import sys
sys.path.append('../mutiny-fuzzer')
from tests.assets.mock_target import MockTarget
from tests.assets.integration_test_1.target import Target1
from backend.mutiny import Mutiny
# integration test to simulate a complete interaction between a target 
# and mutiny in order to evaluate the stability of the fuzzer as a whole

def main():
    # create mock target, accept connections in a child thread
    # connect to target using fuzzer
    
    passed_tests = 0
    total_tests = 3
    print('\nINTEGRATION TESTING RESULTS')
    print('-' * 53)
    start_time = time.perf_counter()
    try:
        test_1()
        passed_tests += 1
    except Exception as e :
        print(repr(e))
        traceback.print_exc()
        print('[ERROR]: failed test 1')
    try:
        test_2()
        passed_tests += 1
    except Exception as e:
        print(repr(e))
        traceback.print_exc()
        print('[ERROR]: failed test 2')
    try:
        test_3()
        passed_tests += 1
    except Exception as e:
        print(repr(e))
        traceback.print_exc()
        print('[ERROR]: failed test 3')
    elapsed_time = time.perf_counter() - start_time
    print(f'Ran {total_tests} tests in {elapsed_time:0.3f}s\n')

    if passed_tests == total_tests:
        print('OK')
    else:
        print(f'{total_tests-passed_tests} failed')

def test_1():
    '''
    test details:
        - prepped_fuzz: ./tests/assets/integration_test_1/prepped.fuzzer
        - target_host: 127.0.0.1
        - sleep_time: 0
        - range: 0-19
        - loop: None
        - dump_raw: 0
        - quiet: False
        - log_all: False
        - processor_dir: ./tests/assets/integration_test_1/
        - failure_threshold: 3
        - failure_timeout: 5.0
        - receive_timeout: 3.0
        - should_perform_test_run 1
        - proto: tcp
        - port: 7777
        - source_port: -1
        - source_ip: 0.0.0.0

        fuzzes until it finds a 'crash' at seed=19, then sends a pause, 
        sleeps, then sends a resume. Fuzzing stops on seed 19, since a
        range of 0-19 was specified
    '''
    block_print() 
    target_if = '127.0.0.1'
    target_port = 7777
    proto = 'tcp'
    prepped_fuzz = './tests/assets/integration_test_1/prepped.fuzzer'
    # populate args
    args = Namespace(prepped_fuzz=prepped_fuzz, target_host = target_if, sleep_time = 0, range = '0-19', loop = None, dump_raw = None, quiet = False, log_all = False)

    # stand up target server
    target = Target1(proto, target_if, target_port)
    # run mutiny
    fuzzer = Mutiny(args)
    fuzzer.radamsa = os.path.abspath( os.path.join(__file__, '../../../radamsa-0.6/bin/radamsa'))
    fuzzer.import_custom_processors()
    fuzzer.debug = False
    # start listening for the fuzz sessions
    target_thread = threading.Thread(target=target.accept_fuzz, args=())
    target_thread.start()
    # connect to target and begin fuzzing
    fuzz_thread = threading.Thread(target=fuzzer.fuzz(True), args=())
    fuzz_thread.start()
    fuzz_thread.join()
    target_thread.join()
    target.communication_conn.close()
    target.listen_conn.close()
    enable_print()
    

def test_2():
    '''
    test details:
        - prepped_fuzz: ./tests/assets/integration_test_2/prepped.fuzzer
        - target_host: 127.0.0.1
        - sleep_time: 0
        - range: None
        - loop: None
        - dump_raw: 0
        - quiet: False
        - log_all: False
        - processor_dir: ./tests/assets/integration_test_2/
        - failure_threshold: 3
        - failure_timeout: 5.0
        - receive_timeout: 3.0
        - should_perform_test_run 1
        - proto: raw
        - port: 7776
        - source_port: -1
        - source_ip: 0.0.0.0

    '''
    block_print()
    enable_print()
    pass

def test_3():
    block_print()
    enable_print()
    pass


import sys, os

# Disable
def block_print():
    sys.stdout = open(os.devnull, 'w')

# Restore
def enable_print():
    sys.stdout = sys.__stdout__


if __name__ == '__main__':
    main()
