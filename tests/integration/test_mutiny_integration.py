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
# Integration test to simulate a complete interaction between a target 
# and mutiny in order to evaluate the stability of the fuzzer as a whole.

# To debug, comment out the block_print() calls at the start of each test.


def test_1(target_if, target_port, proto, prepped_fuzzer_file):
    '''
    test details:
        - prepped_fuzz: ./tests/assets/integration_test_1/<proto>_prepped.fuzzer
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
        - proto: raw
        - port: 7772-7776, unique for each test to avoid 'Address already in use OSError'
        - source_port: -1
        - source_ip: 0.0.0.0

        Fuzzes a target until it finds a 'crash' at seed=19, then sends a pause, 
        sleeps, then sends a resume. Fuzzing stops on seed 19, since a
        range of 0-19 was specified
    '''
    block_print() 
    # populate args
    args = Namespace(prepped_fuzz = prepped_fuzzer_file, target_host = target_if, sleep_time = 0, range = '0-19', loop = None, dump_raw = None, quiet = False, log_all = False)

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
    block_print()
    '''
    test details:
        - prepped_fuzz: ./tests/assets/integration_test_1/<proto>_prepped.fuzzer
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
        - proto: raw
        - port: 7772-7776, unique for each test to avoid 'Address already in use OSError'
        - source_port: -1
        - source_ip: 0.0.0.0

        Fuzzes a target until it finds a 'crash' at seed=19, then sends a pause, 
        sleeps, then sends a resume. Fuzzing stops on seed 19, since a
        range of 0-19 was specified
    '''

    enable_print()
    pass

def test_3():
    block_print()
    enable_print()
    pass
    

def block_print():
    '''
    Redirect mutiny stdout to /dev/null 
    '''
    sys.stdout = open(os.devnull, 'w')

def enable_print():
    '''
    Restores stdout
    '''
    sys.stdout = sys.__stdout__

def main():
    # create mock target, accept connections in a child thread
    # connect to target using fuzzer
    
    passed_tests = 0
    total_tests = 3
    print('\nINTEGRATION TESTING RESULTS')
    print('-' * 53)
    start_time = time.perf_counter()
    target_if = '127.0.0.1'
    try:
        #tcp
        test_1(target_if, target_port= 7772, proto = 'tcp', prepped_fuzzer_file = 'tests/assets/integration_test_1/tcp.fuzzer')
        passed_tests += 1
        # udp 
        test_1(target_if, target_port= 7773, proto = 'udp', prepped_fuzzer_file = 'tests/assets/integration_test_1/udp.fuzzer')
        passed_tests += 1
        # ssl
        test_1(target_if, target_port= 7774, proto = 'ssl', prepped_fuzzer_file = 'tests/assets/integration_test_1/ssl.fuzzer')
        passed_tests += 1
        # raw
        test_1(target_if, target_port= 7775, proto = 'L2raw', prepped_fuzzer_file = 'tests/assets/integration_test_1/raw.fuzzer')
        passed_tests += 1
    except Exception as e:
        print(repr(e))
        traceback.print_exc()
    try:
        #tcp
        test_2(target_if, target_port= 7771, proto = 'tcp', prepped_fuzzer_file = 'tests/assets/integration_test_2/tcp.fuzzer')
        passed_tests += 1
        # udp 
        test_2(target_if, target_port= 7770, proto = 'udp', prepped_fuzzer_file = 'tests/assets/integration_test_2/udp.fuzzer')
        passed_tests += 1
        # ssl
        test_2(target_if, target_port= 7769, proto = 'ssl', prepped_fuzzer_file = 'tests/assets/integration_test_2/ssl.fuzzer')
        passed_tests += 1
        # raw
        test_2(target_if, target_port = 7768, proto = 'L2raw', prepped_fuzzer_file = 'tests/assets/integration_test_2/raw.fuzzer')
        passed_tests += 1
    except Exception as e:
        print(repr(e))
        traceback.print_exc()
    try:
        #tcp
        test_3(target_if, target_port= 7767, proto = 'tcp', prepped_fuzzer_file = 'tests/assets/integration_test_3/tcp.fuzzer')
        passed_tests += 1
        # udp 
        test_3(target_if, target_port= 7766, proto = 'udp', prepped_fuzzer_file = 'tests/assets/integration_test_3/udp.fuzzer')
        passed_tests += 1
        # ssl
        test_3(target_if, target_port= 7765, proto = 'ssl', prepped_fuzzer_file = 'tests/assets/integration_test_3/ssl.fuzzer')
        passed_tests += 1
        # raw
        test_3(target_if, target_port= 7764, proto = 'L2raw', prepped_fuzzer_file = 'tests/assets/integration_test_3/raw.fuzzer')
        passed_tests += 1
    except Exception as e:
        print(repr(e))
        traceback.print_exc()

    elapsed_time = time.perf_counter() - start_time
    print(f'Ran {total_tests} tests in {elapsed_time:0.3f}s\n')

    if passed_tests == total_tests:
        print('OK')
    else:
        print(f'{total_tests-passed_tests} Failed tests')


if __name__ == '__main__':
    main()
