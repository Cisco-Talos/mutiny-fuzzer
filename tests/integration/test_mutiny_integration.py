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
from tests.assets.integration_test_3.target import Target3
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

            Fuzzes a target until it finds a 'crash' at seed=19, then sends a pause, 
            sleeps, then sends a resume. Fuzzing stops on seed 30, since a
            range of 0-30 was specified
        '''
        self.total_tests += 1
        self.block_print() 
        # populate args
        args = Namespace(prepped_fuzz = prepped_fuzzer_file, target_host = self.target_if, sleep_time = 0, range = '0-30', loop = None, dump_raw = None, quiet = False, log_all = False, testing = True)

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
        fuzz_thread = threading.Thread(target=fuzzer.fuzz(), args=())
        #fuzz_thread.start() # connect to target and begin fuzzing
        target_thread.join()
        if target.communication_conn:
            target.communication_conn.close()
        else:
            target.listen_conn.close()
        target.listen_conn.close()
        shutil.rmtree(log_dir)
        self.enable_print()
        self.passed_tests += 1

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
        fuzz_thread = threading.Thread(target=fuzzer.fuzz(), args=())
        #fuzz_thread.start() # connect to target and begin fuzzing
        target_thread.join()
        if target.communication_conn:
            target.communication_conn.close()
        else:
            target.listen_conn.close()
        target.listen_conn.close()
        shutil.rmtree(log_dir)
        self.enable_print()
        self.passed_tests += 1


    def test_3(self, target_port, proto, prepped_fuzzer_file):
        '''
        test details:
            - prepped_fuzz: ./tests/assets/integration_test_3/<proto>_prepped.fuzzer
            - target_host: 127.0.0.1
            - sleep_time: 0
            - range: None
            - loop: None
            - dump_raw: 0
            - quiet: False
            - log_all: False
            - processor_dir: ./tests/assets/integration_test_3/
            - failure_threshold: 3
            - failure_timeout: 5.0
            - receive_timeout: 3.0
            - should_perform_test_run 1
            - port: 7763-7767, unique for each test to avoid 'Address already in use OSError'
            - source_port: -1
            - source_ip: 0.0.0.0

            Fuzzes for .5 seconds, receives a HaltException from the monitor, then is restarted
            in order to verify correct resumption as per issue #31
        '''
        pass
        '''
        FIXME: since the feature tested in the following test was scrapped and
        is in the process of being rewritten, this function will need
        to be changed to reflect the new var names/architecture

        self.total_tests += 1
        #self.block_print() 
        # populate args
        args = Namespace(prepped_fuzz = prepped_fuzzer_file, target_host = self.target_if, sleep_time = 0, range = '0-20', loop = None, dump_raw = None, quiet = False, log_all = False, testing = True)

        # stand up target server
        target = Target3(proto, self.target_if, target_port)
        log_dir = prepped_fuzzer_file.split('.')[0] + '_logs'
        # run mutiny
        fuzzer = Mutiny(args)
        fuzzer.radamsa = os.path.abspath( os.path.join(__file__, '../../../radamsa-0.6/bin/radamsa'))
        fuzzer.import_custom_processors()
        fuzzer.max_run_number = 20
        fuzzer.debug = False
        # start listening for the fuzz sessions
        target_thread = threading.Thread(target=target.accept_fuzz, args=())
        target_thread.start()
        # connect to target and begin fuzzing
        fuzz_thread = threading.Thread(target=fuzzer.fuzz(), args=())
        fuzz_thread.start()
        fuzz_thread.join()
        shutil.rmtree(log_dir)

        assert fuzzer.fuzzer_data.last_seed_tried == 20 # verify seed was saved

        # restart to test resumption from last_seed_tried
        args.range = None
        fuzzer = Mutiny(args) 
        fuzzer.radamsa = os.path.abspath( os.path.join(__file__, '../../../radamsa-0.6/bin/radamsa'))
        fuzzer.import_custom_processors()
        fuzzer.debug = False
        assert fuzzer.min_run_number == 20 # verify seed is used to start
        # change max_run_number to 21 so we dont have to interrupt execution with monitor
        fuzzer.max_run_number = 21
        fuzz_thread = threading.Thread(target=fuzzer.fuzz(), args=())
        fuzz_thread.start()
        fuzz_thread.join()
        assert fuzzer.fuzzer_data.last_seed_tried == 21 # verify seed was saved
        target.communication_conn.close()
        target.communication_conn = None
        target.listen_conn.close()
        self.passed_tests += 1
        self.enable_print()
        shutil.rmtree(log_dir)
        '''
        

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
        pass
        #tcp
        suite.test_1(target_port= 7772, proto = 'tcp', prepped_fuzzer_file = 'tests/assets/integration_test_1/tcp.fuzzer')
        # udp 
        #suite.test_1(target_port= 7773, proto = 'udp', prepped_fuzzer_file = 'tests/assets/integration_test_1/udp.fuzzer')
        # ssl
        #suite.test_1(target_port= 7774, proto = 'ssl', prepped_fuzzer_file = 'tests/assets/integration_test_1/ssl.fuzzer')
        # raw
        #suite.test_1(target_port= 7775, proto = 'L2raw', prepped_fuzzer_file = 'tests/assets/integration_test_1/raw.fuzzer')
    except Exception as e:
        print(repr(e))
        traceback.print_exc()

    try: # SINGLE OUTBOUND LINE -> CRASH -> HALT
        #tcp
        pass
        suite.test_2(target_port= 7776, proto = 'tcp', prepped_fuzzer_file = 'tests/assets/integration_test_2/tcp.fuzzer')
        # udp 
        #suite.test_2(target_port= 7777, proto = 'udp', prepped_fuzzer_file = 'tests/assets/integration_test_2/udp.fuzzer')
        # ssl
        #suite.test_2(target_port= 7778, proto = 'ssl', prepped_fuzzer_file = 'tests/assets/integration_test_2/ssl.fuzzer')
        # raw
        #suite.test_2(target_port = 7779, proto = 'L2raw', prepped_fuzzer_file = 'tests/assets/integration_test_2/raw.fuzzer')
    except Exception as e:
        print(repr(e))
        traceback.print_exc()
    try: # FUZZ -> HALT -> RESUME FROM LAST_SEED_TRIED -> HALT
        #tcp
        #suite.test_3(target_port= 7780, proto = 'tcp', prepped_fuzzer_file = 'tests/assets/integration_test_3/tcp.fuzzer')
        # udp 
        #suite.test_3(target_port= 7782, proto = 'udp', prepped_fuzzer_file = 'tests/assets/integration_test_3/udp.fuzzer')
        # ssl
        #suite.test_3(target_port= 7784, proto = 'ssl', prepped_fuzzer_file = 'tests/assets/integration_test_3/ssl.fuzzer')
        # raw
        #suite.test_3(target_port= 7786, proto = 'L2raw', prepped_fuzzer_file = 'tests/assets/integration_test_3/raw.fuzzer')
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
