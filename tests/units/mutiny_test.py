import unittest
from time import sleep
import shutil
import os
import socket
import mutiny
from argparse import Namespace
import threading
from backend.fuzzer_data import FuzzerData

class TestMutiny(unittest.TestCase):



    def setUp(self):
        self.fuzzFilePath1 = './tests/units/input_files/test_FuzzDataRead.fuzzer'
        self.logFilePath1 = self.fuzzFilePath1[:-7] + '_logs'
        self.args = Namespace(prepped_fuzz=self.fuzzFilePath1, target_host='127.0.0.1', sleeptime=0, range=None, loop=None, dumpraw=None, quiet=False, logAll=False)
        pass

    def tearDown(self):
        # in case it has been changed 
        mutiny.RADAMSA = os.path.abspath(os.path.join(__file__,"../../../radamsa/bin/radamsa"))
        pass

    def test_sendPacket(self):
        def handle_connection(test_type):
            test_conn = socket.socket(socket_family, socket_type)
            test_conn.bind((test_ip, test_port))
            if test_type == 'tcp': 
                test_conn.listen()
                conn, mutiny_addr = test_conn.accept()
                received_data['data'] = conn.recv(len(out_packet_data))
                conn.close()
            else:
                received_data['data'], addr = test_conn.recvfrom(len(out_packet_data))
            test_conn.close()

        received_data = {}
        mutiny.FUZZER_DATA = FuzzerData()
        mutiny.FUZZER_DATA.receiveTimeout = 3.0
        test_ip = '127.0.0.1'
        test_port = 9999
        socket_family = socket.AF_INET
        socket_type = socket.SOCK_STREAM
        mutiny_conn = socket.socket(socket_family, socket_type)
        mutiny_conn.bind(('0.0.0.0', 0))
        out_packet_data = bytes('test', 'utf-8')

        # tcp test
        conn_thread = threading.Thread(target=handle_connection, args=('tcp',))
        conn_thread.start()
        sleep(1) # avoid race, allow handle_connections to bind and listen
        test_addr = (test_ip, test_port)
        mutiny_conn.connect(test_addr)
        mutiny.sendPacket(mutiny_conn, test_addr, out_packet_data)
        conn_thread.join()
        mutiny_conn.close()
        self.assertEqual(received_data['data'], out_packet_data)
        # non-tcp test
        test_port = 9998 # to avoid issues binding to same port in short time
        socket_type = socket.SOCK_DGRAM
        test_addr = (test_ip, test_port)
        conn_thread = threading.Thread(target=handle_connection, args=('non-tcp',))
        conn_thread.start()
        mutiny_conn = socket.socket(socket_family, socket_type)
        mutiny.sendPacket(mutiny_conn, test_addr, out_packet_data)
        conn_thread.join()
        mutiny_conn.close()
        self.assertEqual(received_data['data'], out_packet_data)


    def test_receivePacket(self):
        def handle_connection(test_type):
            test_conn = socket.socket(socket_family, socket_type)
            test_conn.bind((test_ip, test_port))
            if test_type == 'tcp': 
                test_conn.listen()
                conn, mutiny_addr = test_conn.accept()
                conn.recv
                conn.send(out_packet_data)
            else:
                test_conn.sendto(out_packet_data,(mutiny_ip, mutiny_port))

            conn.close()
            test_conn.close()

        mutiny.FUZZER_DATA = FuzzerData()
        mutiny.FUZZER_DATA.receiveTimeout = 3.0
        test_ip = '127.0.0.1'
        test_port = 8888
        mutiny_ip = '127.0.0.1'
        mutiny_port = 4000
        socket_family = socket.AF_INET
        socket_type = socket.SOCK_STREAM
        mutiny_conn = socket.socket(socket_family, socket_type)
        mutiny_conn.bind((mutiny_ip, mutiny_port))
        out_packet_data = bytes('test', 'utf-8')

        # tcp test
        conn_thread = threading.Thread(target=handle_connection, args=('tcp',))
        conn_thread.start()
        sleep(1) # avoid race, allow handle_connections to bind and listen
        test_addr = (test_ip, test_port)
        mutiny_conn.connect(test_addr)
        response = mutiny.receivePacket(mutiny_conn, test_addr, len(out_packet_data))
        conn_thread.join()
        self.assertEqual(response, out_packet_data)
        mutiny_conn.close()
        ''' # FIXME: SOCK_RAW requires root and the other protocols aren't supported on macOS, should move to linux vm and see which protocol we can use
        # non-tcp test 
        test_port = 9998 # to avoid issues binding to same port in short time
        socket_type = socket.SOCK_RAW
        test_addr = (test_ip, test_port)
        conn_thread = threading.Thread(target=handle_connection, args=('non-tcp',))
        conn_thread.start()
        mutiny_conn = socket.socket(socket_family, socket_type)
        response = mutiny.receivePacket(mutiny_conn, test_addr, len(out_packet_data))
        conn_thread.join()
        mutiny_conn.close()
        self.assertEqual(response, out_packet_data)
        '''
        # greater than 4096
        mutiny_port = 4001
        test_port = 8889
        mutiny_conn = socket.socket(socket_family, socket_type)
        mutiny_conn.bind((mutiny_ip, mutiny_port))
        out_packet_data = bytes('A' * 4096 + 'test', 'utf-8')
        conn_thread = threading.Thread(target=handle_connection, args=('tcp',))
        conn_thread.start()
        sleep(1) # avoid race, allow handle_connections to bind and listen
        test_addr = (test_ip, test_port)
        mutiny_conn.connect(test_addr)
        response = mutiny.receivePacket(mutiny_conn, test_addr, len(out_packet_data))
        conn_thread.join()
        self.assertEqual(response, out_packet_data)
        mutiny_conn.close()


    def test_performRun(self):
        pass

    def test_getRunNumbersFromArgs(self):
        min_run = ''
        max_run = ''
        # subsequent
        str_args = '1-2'
        min_run, max_run = mutiny.getRunNumbersFromArgs(str_args)
        self.assertEqual(min_run, 1)
        self.assertEqual(max_run, 2)
        # --skip-to
        str_args = '1-'
        min_run, max_run = mutiny.getRunNumbersFromArgs(str_args)
        self.assertEqual(min_run, 1)
        self.assertEqual(max_run, -1)
        # single iteration
        str_args = '1'
        min_run, max_run = mutiny.getRunNumbersFromArgs(str_args)
        self.assertEqual(min_run, 1)
        self.assertEqual(max_run,1)

        # reverse order
        str_args = '2-1'
        with self.assertRaises(SystemExit) as contextManager:
            min_run, max_run = mutiny.getRunNumbersFromArgs(str_args)
            self.assertEqual(contextManager.exception.code, 3)

        # invalid format
        str_args = '1-2-5'
        with self.assertRaises(SystemExit) as contextManager:
            min_run, max_run = mutiny.getRunNumbersFromArgs(str_args)
            self.assertEqual(contextManager.exception.code, 3)


    def test_fuzz(self):
        # setup listening server
        bindip = '127.0.0.1'
        bindport = 9999
        socket_family = socket.AF_INET
        socket_type = socket.SOCK_STREAM
        serv = socket.socket(socket_family, socket_type)
        serv.bind((bindip,bindport))
        serv.listen()
        mutiny.MAX_RUN_NUMBER = 1
        fuzz_func = threading.Thread(target=mutiny.fuzz, args=([self.args, True]))
        fuzz_func.start()
        cli_sock, cli_addr = serv.accept()
        cli_sock.recv(4096)
        cli_sock.send(b'starting tests')
        fuzz_func.join()
        cli_sock.close()
        serv.close()

    def test_fuzzSetup(self):
        mutiny.fuzzSetup(self.args, testing=True)
        # let fuzzer_data.readFromFile tests verify correctness of contents, just check that it was called
        self.assertIsNotNone(mutiny.FUZZER_DATA)
        self.assertEqual(len(mutiny.FUZZER_DATA.messageCollection.messages), 7)
        self.assertTrue(os.path.exists(self.logFilePath1))
        shutil.rmtree(self.logFilePath1)

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
        self.assertEqual(mutiny.MIN_RUN_NUMBER, 1)
        self.assertEqual(mutiny.MAX_RUN_NUMBER, 3)
        self.assertTrue(os.path.exists(self.logFilePath1))
        shutil.rmtree(self.logFilePath1)

    def test_fuzzSetupNonNoneLoop(self):
        # non-None loop
        self.args.loop = '1'
        mutiny.fuzzSetup(self.args, testing=True)
        self.assertEqual(mutiny.SEED_LOOP, [1])
        self.assertTrue(os.path.exists(self.logFilePath1))
        shutil.rmtree(self.logFilePath1)
        self.args.loop = '2-4'
        mutiny.fuzzSetup(self.args, testing=True)
        self.assertEqual(mutiny.SEED_LOOP,[2,3,4])
        self.assertTrue(os.path.exists(self.logFilePath1))
        shutil.rmtree(self.logFilePath1)
        self.args.loop = '0, 2-4'
        mutiny.fuzzSetup(self.args, testing=True)
        self.assertEqual(mutiny.SEED_LOOP,[0,2,3,4])
        self.assertTrue(os.path.exists(self.logFilePath1))
        shutil.rmtree(self.logFilePath1)

    def test_processorSetup(self):
        outputDataFolderPath = './tests/units/input_files/test_processorSetup_logs/data'
        fuzzerFolder = os.path.abspath( os.path.join( __file__, '../input_files'))
        mutiny.FUZZER_DATA = FuzzerData()
        mutiny.FUZZER_DATA.readFromFile(self.fuzzFilePath1)
        msgProcessor, exceptProcessor, logger = mutiny.processorSetup(fuzzerFolder, outputDataFolderPath, self.args)
        self.assertTrue(os.path.exists(outputDataFolderPath))
        # just check they arent none, we can verify their correct initialization in their class tests
        self.assertIsNotNone(msgProcessor)
        self.assertIsNotNone(exceptProcessor)
        self.assertIsNotNone(logger)
        shutil.rmtree(outputDataFolderPath[:-5])

    def test_processorSetupNonDefaultFolder(self):
        outputDataFolderPath = './tests/units/input_files/test_processorSetup_logs/data'
        fuzzerFolder = os.path.abspath( os.path.join( __file__, '../input_files'))
        mutiny.FUZZER_DATA = FuzzerData()
        mutiny.FUZZER_DATA.readFromFile(self.fuzzFilePath1)
        mutiny.FUZZER_DATA.processorDirectory = 'testdir'
        msgProcessor, exceptProcessor, logger = mutiny.processorSetup(fuzzerFolder, outputDataFolderPath, self.args)
        self.assertIsNotNone(msgProcessor)
        self.assertIsNotNone(exceptProcessor)
        self.assertIsNotNone(logger)
        shutil.rmtree(outputDataFolderPath[:-5])

    # TODO: create tests for custom processors


    def test_processorSetupNonQuiet(self):
        outputDataFolderPath = './tests/units/input_files/test_processorSetup_logs/data'
        self.args.quiet = True
        fuzzerFolder = os.path.abspath( os.path.join( __file__, '../input_files'))
        mutiny.FUZZER_DATA = FuzzerData()
        mutiny.FUZZER_DATA.readFromFile(self.fuzzFilePath1)
        msgProcessor, exceptProcessor, logger = mutiny.processorSetup(fuzzerFolder, outputDataFolderPath, self.args)
        self.assertIsNotNone(msgProcessor)
        self.assertIsNotNone(exceptProcessor)
        self.assertIsNone(logger)
        self.assertFalse(os.path.exists(outputDataFolderPath))

    def test_processorSetupNonDump(self):
        outputDataFolderPath = './tests/units/input_files/test_processorSetup_logs/data'
        fuzzerFolder = os.path.abspath( os.path.join( __file__, '../input_files'))
        self.args.dumpraw = True
        mutiny.FUZZER_DATA = FuzzerData()
        mutiny.FUZZER_DATA.readFromFile(self.fuzzFilePath1)
        msgProcessor, exceptProcessor, logger = mutiny.processorSetup(fuzzerFolder, outputDataFolderPath, self.args)
        self.assertTrue(os.path.exists(outputDataFolderPath))
        # just check they arent none, we can verify their correct initialization in their class tests
        self.assertIsNotNone(msgProcessor)
        self.assertIsNotNone(exceptProcessor)
        self.assertIsNotNone(logger)
        self.assertEqual(mutiny.DUMPDIR, outputDataFolderPath)
        shutil.rmtree(outputDataFolderPath[:-5])

        # with quiet = True
        self.args.quiet = True
        msgProcessor, exceptProcessor, logger = mutiny.processorSetup(fuzzerFolder, outputDataFolderPath, self.args)
        self.assertFalse(os.path.exists(outputDataFolderPath))
        # just check they arent none, we can verify their correct initialization in their class tests
        self.assertIsNotNone(msgProcessor)
        self.assertIsNotNone(exceptProcessor)
        self.assertIsNone(logger)
        self.assertEqual(mutiny.DUMPDIR, 'dumpraw')
        self.assertTrue(os.path.exists(mutiny.DUMPDIR))
        shutil.rmtree(mutiny.DUMPDIR)

