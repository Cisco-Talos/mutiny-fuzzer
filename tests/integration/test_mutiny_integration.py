from argparse import Namespace
import time
import shutil
import traceback
import os
import threading
import sys
sys.path.append('../mutiny-fuzzer')
from tests.assets.mock_target import MockTarget
from tests.assets.integration_test_1.target import Target1
from tests.assets.integration_test_2.target import Target2
from backend.mutiny import Mutiny
# Integration test to simulate a complete interaction between a target 
# and mutiny in order to evaluate the stability of the fuzzer as a whole.

# To debug, comment out the block_print() calls at the start of each test.
class IntegrationSuite(object):

    def __init__(self):
        self.target_if = '127.0.0.1'
        self.passed_tests = 0
        self.total_tests = 0


    def test_1(self, target_port, proto, prepped_fuzzer_file):
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
            - port: 7772-7776, unique for each test to avoid 'Address already in use OSError'
            - source_port: -1
            - source_ip: 0.0.0.0

            Fuzzes a target until it finds a 'crash' at seed=7, then sends a pause, 
            sleeps, then sends a resume. Fuzzing stops on seed 10, since a
            range of 0-10 was specified
        '''
        print('test 1: {}'.format(proto))
        self.total_tests += 1
        self.block_print() 
        # populate args
        args = Namespace(prepped_fuzz = prepped_fuzzer_file, target_host = self.target_if, sleep_time = 0, range = '0-10', loop = None, dump_raw = None, quiet = False, log_all = False, testing = True)

        log_dir = prepped_fuzzer_file.split('.')[0] + '_logs'
        # stand up target server
        target = Target1(proto, self.target_if, target_port)
        # run mutiny
        fuzzer = Mutiny(args)
        fuzzer.radamsa = os.path.abspath( os.path.join(__file__, '../../../radamsa-0.6/bin/radamsa'))
        fuzzer.import_custom_processors()
        fuzzer.debug = False
        # start listening for the fuzz sessions
        target_thread = threading.Thread(target=target.accept_fuzz, args=())
        target_thread.start()
        time.sleep(.03) # avoid race with connection to socket
        fuzz_thread = threading.Thread(target=fuzzer.fuzz, args=())
        fuzz_thread.start() # connect to target and begin fuzzing
        target_thread.join()
        print('target joined')
        fuzz_thread.join()
        print('fuzzer joined')
        if target.communication_conn:
            target.communication_conn.close()
        else:
            target.listen_conn.close()
        shutil.rmtree(log_dir)
        self.enable_print()
        self.passed_tests += 1
        print('ok')

    def test_2(self, target_port, proto, prepped_fuzzer_file):
        '''
        test details:
            - prepped_fuzz: ./tests/assets/integration_test_2/<proto>_prepped.fuzzer
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
            - port: 7768-7771, unique for each test to avoid 'Address already in use OSError'
            - source_port: -1
            - source_ip: 0.0.0.0

            Fuzzes a target until it finds a 'crash' at seed=10, using a single
            outbound line to test against regression on the bug described in issue #11,
            upon reception of the crash, the monitor sends a HaltException to mutiny to halt execution
        '''
        self.total_tests += 1
        print('test 2: {}'.format(proto))
        #self.block_print() 
        # populate args
        args = Namespace(prepped_fuzz = prepped_fuzzer_file, target_host = self.target_if, sleep_time = 0, range = '0-', loop = None, dump_raw = None, quiet = False, log_all = False, testing = True)

        log_dir = prepped_fuzzer_file.split('.')[0] + '_logs'
        # stand up target server
        target = Target2(proto, self.target_if, target_port)
        # run mutiny
        fuzzer = Mutiny(args)
        fuzzer.radamsa = os.path.abspath( os.path.join(__file__, '../../../radamsa-0.6/bin/radamsa'))
        fuzzer.import_custom_processors()
        fuzzer.debug = False
        # start listening for the fuzz sessions
        target_thread = threading.Thread(target=target.accept_fuzz, args=())
        target_thread.start()
        time.sleep(.03) # avoid race with connection to socket
        fuzz_thread = threading.Thread(target=fuzzer.fuzz, args=())
        fuzz_thread.start() # connect to target and begin fuzzing
        target_thread.join()
        if target.communication_conn:
            target.communication_conn.close()
        else:
            target.listen_conn.close()
        target.listen_conn.close()
        shutil.rmtree(log_dir)
        self.enable_print()
        self.passed_tests += 1
        print('ok')



    def block_print(self):
        '''
        Redirect mutiny stdout to /dev/null 
        '''
        sys.stdout = open(os.devnull, 'w')

    def enable_print(self):
        '''
        Restores stdout
        '''
        sys.stdout = sys.__stdout__

def main():
    # create mock target, accept connections in a child thread
    # connect to target using fuzzer
    
    print('\nINTEGRATION TESTING RESULTS')
    print('-' * 53)
    start_time = time.perf_counter()
    suite = IntegrationSuite()
    try: # SINGLE CRASH -> PAUSE -> RESUME -> FINISH SPECIFIED RANGE
        #tcp
        suite.test_1(target_port= 7772, proto = 'tcp', prepped_fuzzer_file = 'tests/assets/integration_test_1/tcp.fuzzer')
        # udp 
        suite.test_1(target_port= 7773, proto = 'udp', prepped_fuzzer_file = 'tests/assets/integration_test_1/udp.fuzzer')
        # tls
        suite.test_1(target_port= 7774, proto = 'tls', prepped_fuzzer_file = 'tests/assets/integration_test_1/tls.fuzzer')
        # raw
        suite.test_1(target_port= 7775, proto = 'L2raw', prepped_fuzzer_file = 'tests/assets/integration_test_1/raw.fuzzer')
    except Exception as e:
        print(repr(e))
        traceback.print_exc()

    try: # SINGLE OUTBOUND LINE -> CRASH -> HALT
        #tcp
        suite.test_2(target_port= 7776, proto = 'tcp', prepped_fuzzer_file = 'tests/assets/integration_test_2/tcp.fuzzer')
        # udp 
        suite.test_2(target_port= 7777, proto = 'udp', prepped_fuzzer_file = 'tests/assets/integration_test_2/udp.fuzzer')
        # tls 
        suite.test_2(target_port= 7778, proto = 'tls', prepped_fuzzer_file = 'tests/assets/integration_test_2/tls.fuzzer')
        # raw
        suite.test_2(target_port = 7779, proto = 'L2raw', prepped_fuzzer_file = 'tests/assets/integration_test_2/raw.fuzzer')
    except Exception as e:
        print(repr(e))
        traceback.print_exc()
    elapsed_time = time.perf_counter() - start_time
    print(f'Ran {suite.total_tests} tests in {elapsed_time:0.3f}s\n')

    if suite.passed_tests == suite.total_tests:
        print('OK')
    else:
        print(f'{suite.total_tests-suite.passed_tests} Failed tests')


if __name__ == '__main__':
    main()
