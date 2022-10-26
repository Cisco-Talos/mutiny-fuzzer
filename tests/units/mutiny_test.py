import unittest
import socket
import mutiny
from argparse import Namespace
import threading


class TestMutiny(unittest.TestCase):



    def setUp(self):
        self.args = Namespace(prepped_fuzz='tests/units/input_files/test_FuzzDataRead.fuzzer', target_host='127.0.0.1', sleeptime=0, range=1, loop=None, dumpraw=None, quiet=False, logAll=False)
        
        pass

    def tearDown(self):
        pass

    def test_sendPacket(self):
        pass

    def test_receivePacket(self):
        pass

    def test_performRun(self):
        pass

    def test_getRunNumbersFromArgs(self):
        pass

    def test_fuzz(self):
        '''
        # setup listening server
        bindip = '127.0.0.1'
        bindport = 9999
        socket_family = socket.AF_INET
        socket_type = socket.SOCK_STREAM
        serv = socket.socket(socket_family, socket_type)
        serv.bind((bindip,bindport))
        serv.listen()
        fuzz_func = threading.Thread(target=mutiny.fuzz, args=([self.args, True]))
        fuzz_func.start()
        cli_sock, cli_addr = serv.accept()
        cli_sock.recv(4096)
        cli_sock.send(b'starting tests')
        # TODO: figure out how to send sigint to the fuzz_func thread or another way to kill
        # NOTE: ^^this can be addressed by just setting MAX_RUN_NUMBER to something other than -1
        fuzz_func.join()
        cli_sock.close()
        serv.close()
        '''

    def test_fuzzSetup(self):
        mutiny.fuzzSetup(self.args, testing=True)
        # let fuzzer_data.readFromFile tests verify correctness of contents, just check that it was called
        self.assertIsNotNone(mutiny.FUZZER_DATA)
        self.assertEqual(len(mutiny.FUZZER_DATA.messageCollection.messages), 7)

    def test_fuzzSetupNonExistentRadamsa(self):
        with self.assertRaises(SystemExit) as contextManager:
            # radamsa doesn't exist
            mutiny.RADAMSA = '/non-existent/file'
            mutiny.fuzzSetup(self.args, testing=True)
            self.assertEqual(contextManager.exception.code, 3)

    def test_fuzzSetupNonNoneRange(self):
        # non-None range
        self.args.range = '1-3'
        mutiny.fuzzSetup(self.args, testing=True)
        self.assertEqual(mutiny.MIN_RUN_NUMBER, 

    def test_fuzzSetupNonNoneLoop(self):
        # non-None loop
        pass

    def test_processorSetup(self):
        pass

    def test_parseFuzzArgs(self):
        pass

    def test_parsePrepArgs(self):
        pass

    def test_parseArguments(self):
        pass
    
