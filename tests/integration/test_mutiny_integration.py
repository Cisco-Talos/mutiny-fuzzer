from argparse import Namespace
from tests.assets.mock_target import MockTarget
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
    except:
        print('[ERROR]: failed test 1')
    try:
        test_2()
        passed_tests += 1
    except:
        print('[ERROR]: failed test 2')
    try:
        test_3()
        passed_tests += 1
    except:
        print('[ERROR]: failed test 3')

    print('Results: {passed_tests}/{total_tests} tests passed'.format(passed_tests=passed_tests, total_tests=total_tests))

def test_1():
    '''
    test details:
        - prepped_fuzz: ./tests/assets/test_mutiny_integration_1.fuzzer
        - target_host: 127.0.0.1
        - sleep_time: 0
        - range: None
        - loop: None
        - dump_raw: 0
        - quiet: False
        - log_all: False
        - processor_dir: default
        - failure_threshold: 3
        - failure_timeout: 5.0
        - receive_timeout: 3.0
        - should_perform_test_run 1
        - proto: tcp
        - port: 7777
        - source_port: -1
        - source_ip: 0.0.0.0
    '''
    target_if = '127.0.0.1'
    target_port = '7777'
    proto = 'tcp'
    args = Namespace()

    # stand up target server
    target = target_1()
    # populate args
    # run mutiny

def test_2():
    pass

def test_3():
    pass

class target_1(MockTarget):


if __name__ == '__main__':
    main()
