import unittest
from time import sleep
import shutil
import socket
import os
from backend.mutiny import Mutiny
from argparse import Namespace
import threading
from backend.fuzzer_data import FuzzerData

class TestMutiny(unittest.TestCase):

    def setUp(self):
        self.fuzz_file_path_1 = './tests/assets/test_fuzz_data_read.fuzzer'
        self.log_file_path_1 = self.fuzz_file_path_1[:-7] + '_logs'
        args = Namespace(prepped_fuzz=self.fuzz_file_path_1, target_host='127.0.0.1', sleep_time=0, range=None, loop=None, dump_raw=None, quiet=False, log_all=False)
        self.mutiny = Mutiny(args)
        self.mutiny.radamsa = os.path.abspath(os.path.join(__file__,"../../../radamsa/bin/radamsa"))
        pass

    def tearDown(self):
        os.rmtree(self.log_file_path_1)
        pass

    def test_perform_run(self):
        pass

    def test_get_run_numbers_from_args(self):
        min_run = ''
        max_run = ''
        # subsequent
        str_args = '1-2'
        min_run, max_run = self.mutiny.get_run_numbers_from_args(str_args)
        self.assertEqual(min_run, 1)
        self.assertEqual(max_run, 2)
        # --skip-to
        str_args = '1-'
        min_run, max_run = self.mutiny.get_run_numbers_from_args(str_args)
        self.assertEqual(min_run, 1)
        self.assertEqual(max_run, -1)
        # single iteration
        str_args = '1'
        min_run, max_run = self.mutiny.get_run_numbers_fromArgs(str_args)
        self.assertEqual(min_run, 1)
        self.assertEqual(max_run,1)

        # reverse order
        str_args = '2-1'
        with self.assertRaises(SystemExit) as contextManager:
            min_run, max_run = self.mutiny.get_run_numbers_from_args(str_args)
            self.assertEqual(contextManager.exception.code, 3)

        # invalid format
        str_args = '1-2-5'
        with self.assertRaises(SystemExit) as contextManager:
            min_run, max_run = self.mutiny.get_run_numbers_from_args(str_args)
            self.assertEqual(contextManager.exception.code, 3)


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
        mutiny.MAX_RUN_NUMBER = 1
        fuzz_func = threading.Thread(target=mutiny.fuzz, args=([self.args, True]))
        fuzz_func.start()
        cli_sock, cli_addr = serv.accept()
        cli_sock.recv(4096)
        cli_sock.send(b'starting tests')
        fuzz_func.join()
        cli_sock.close()
        serv.close()
        '''

    def test_processor_setup(self):
        output_data_folder_path = './tests/units/input_files/test_processorSetup_logs/data'
        fuzzerFolder = os.path.abspath( os.path.join( __file__, '../input_files'))
        self.mutiny.fuzzer_data = FuzzerData()
        self.mutiny.fuzzer_data.readFromFile(self.fuzz_file_path_1)
        msgProcessor, exceptProcessor, logger = mutiny.processorSetup(fuzzerFolder, output_data_folder_path, self.args)
        self.assertTrue(os.path.exists(output_data_folder_path))
        # just check they arent none, we can verify their correct initialization in their class tests
        self.assertIsNotNone(msgProcessor)
        self.assertIsNotNone(exceptProcessor)
        self.assertIsNotNone(logger)
        shutil.rmtree(output_data_folder_path[:-5])

    def test_processorSetupNonDefaultFolder(self):
        output_data_folder_path = './tests/units/input_files/test_processorSetup_logs/data'
        fuzzerFolder = os.path.abspath( os.path.join( __file__, '../input_files'))
        self.mutiny.fuzzer_data = FuzzerData()
        self.mutiny.fuzzer_data.readFromFile(self.fuzz_file_path_1)
        self.mutiny.fuzzer_data.processorDirectory = 'testdir'
        msgProcessor, exceptProcessor, logger = mutiny.processorSetup(fuzzerFolder, output_data_folder_path, self.args)
        self.assertIsNotNone(msgProcessor)
        self.assertIsNotNone(exceptProcessor)
        self.assertIsNotNone(logger)
        shutil.rmtree(output_data_folder_path[:-5])

    # TODO: create tests for custom processors


    def test_processorSetupNonQuiet(self):
        output_data_folder_path = './tests/units/input_files/test_processorSetup_logs/data'
        self.args.quiet = True
        fuzzerFolder = os.path.abspath( os.path.join( __file__, '../input_files'))
        self.mutiny.fuzzer_data = FuzzerData()
        self.mutiny.fuzzer_data.readFromFile(self.fuzz_file_path_1)
        msgProcessor, exceptProcessor, logger = mutiny.processorSetup(fuzzerFolder, output_data_folder_path, self.args)
        self.assertIsNotNone(msgProcessor)
        self.assertIsNotNone(exceptProcessor)
        self.assertIsNone(logger)
        self.assertFalse(os.path.exists(output_data_folder_path))

    def test_processorSetupNonDump(self):
        output_data_folder_path = './tests/units/input_files/test_processorSetup_logs/data'
        fuzzerFolder = os.path.abspath( os.path.join( __file__, '../input_files'))
        self.args.dumpraw = True
        self.mutiny.fuzzer_data = FuzzerData()
        self.mutiny.fuzzer_data.readFromFile(self.fuzz_file_path_1)
        msgProcessor, exceptProcessor, logger = mutiny.processorSetup(fuzzerFolder, output_data_folder_path, self.args)
        self.assertTrue(os.path.exists(output_data_folder_path))
        # just check they arent none, we can verify their correct initialization in their class tests
        self.assertIsNotNone(msgProcessor)
        self.assertIsNotNone(exceptProcessor)
        self.assertIsNotNone(logger)
        self.assertEqual(mutiny.DUMPDIR, output_data_folder_path)
        shutil.rmtree(output_data_folder_path[:-5])

        # with quiet = True
        self.args.quiet = True
        msgProcessor, exceptProcessor, logger = mutiny.processorSetup(fuzzerFolder, output_data_folder_path, self.args)
        self.assertFalse(os.path.exists(output_data_folder_path))
        # just check they arent none, we can verify their correct initialization in their class tests
        self.assertIsNotNone(msgProcessor)
        self.assertIsNotNone(exceptProcessor)
        self.assertIsNone(logger)
        self.assertEqual(mutiny.DUMPDIR, 'dumpraw')
        self.assertTrue(os.path.exists(mutiny.DUMPDIR))
        shutil.rmtree(mutiny.DUMPDIR)

