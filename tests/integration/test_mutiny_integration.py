from argparse import Namespace
import traceback
import os
import threading
import sys
sys.path.append('../mutiny-fuzzer')
from tests.assets.mock_target import MockTarget
from backend.mutiny import Mutiny
# integration test to simulate a complete interaction between a target 
# and mutiny in order to evaluate the stability of the fuzzer as a whole

def main():
    # create mock target, accept connections in a child thread
    # connect to target using fuzzer
    
    passed_tests = 0
    total_tests = 3
    print('-' * 22 + 'INTEGRATION TESTING RESULTS' + '-' * 21)
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

    print('Results: {passed_tests}/{total_tests} tests passed'.format(passed_tests=passed_tests, total_tests=total_tests))

def test_1():
    '''
    test details:
        - prepped_fuzz: ./tests/assets/test_mutiny_integration_1.fuzzer
        - target_host: 127.0.0.1
        - sleep_time: 0
        - range: 0-19
        - loop: None
        - dump_raw: 0
        - quiet: False
        - log_all: False
        - processor_dir: ./tests/assets/integration_test_1_classes
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
    target_if = '127.0.0.1'
    target_port = 7777
    proto = 'tcp'
    prepped_fuzz = './tests/assets/test_mutiny_integration_1.fuzzer'
    # populate args
    args = Namespace(prepped_fuzz=prepped_fuzz, target_host = target_if, sleep_time = 0, range = '0-19', loop = None, dump_raw = None, quiet = False, log_all = False)

    # stand up target server
    target = target_1(proto, target_if, target_port)
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
    

def test_2():
    pass

def test_3():
    pass

class target_1(MockTarget):

    def accept_fuzz(self):
        #TODO: make message_processor.preconnect available, assert its being called
        # accept initial connection
        self.accept_connection()
        while True:
            # receive hi
            self.receive_packet(2)
            # send hello, addr not required since tcp
            self.send_packet(bytearray('hello', 'utf-8'), addr = None)
            self.receive_packet(4096)
            result = self.incoming_buffer.pop()
            if len(result) > 100 and len(result) < 120:
                # 15th iteration should cause a crash
                # write to file that monitor_target is reading
                assert result == bytearray('magic phrase:ppppppppppppppppppppasswordpasswordpassswordpwordpassswordpassswordpassswordpasswordpasswordpasssword', 'utf-8')
                with open('./tests/assets/integration_test_1_crash.log', 'w') as file:
                    file.write('crashed')
                    self.communication_conn.close()
                    self.listen_conn.close()
                return
            self.send_packet(bytearray('incorrect magic phrase, try again!', 'utf-8'), addr = None)
            self.communication_conn = self.listen_conn.accept()[0]


if __name__ == '__main__':
    main()
