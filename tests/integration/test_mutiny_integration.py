# integration test to simulate a complete interaction between a target 
# and mutiny in order to evaluate the stability of the fuzzer as a whole

def main():
    # create mock target, accept connections in a child thread
    # connect to target using fuzzer
    
    passed_tests = 0
    total_tests = 3
    print('-' * 10 + 'INTEGRATION TESTING RESULTS' + '-' * 10)
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
    pass
def test_2():
    pass
def test_3():
    pass

if __name__ == '__main__':
    main()
