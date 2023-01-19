import unittest
import queue
from time import sleep
import shutil
import socket
import os
from backend.mutiny import Mutiny
from backend.fuzzer_types import Message
from argparse import Namespace
import threading
from backend.fuzzer_data import FuzzerData
from mutiny_classes.mutiny_exceptions import *

class TestMutiny(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fuzz_file_path_1 = './tests/assets/test_fuzz_data_read.fuzzer'
        cls.log_file_path_1 = cls.fuzz_file_path_1[:-7] + '_logs'

        cls.args = Namespace(prepped_fuzz=cls.fuzz_file_path_1, target_host='127.0.0.1', sleep_time=0, range=None, loop=None, dump_raw=None, quiet=False, log_all=False, testing=True)
        cls.mutiny = Mutiny(cls.args)
        cls.mutiny.import_custom_processors()

    def setUp(self):
        # in case its been changed
        self.mutiny.radamsa = os.path.abspath(os.path.join(__file__,"../../../radamsa-0.6/bin/radamsa"))
        self.args = Namespace(prepped_fuzz=self.fuzz_file_path_1, target_host='127.0.0.1', sleep_time=0, range=None, loop=None, dump_raw=None, quiet=False, log_all=False, testing=True)

    def tearDown(self):
        if os.path.exists(self.log_file_path_1):
            shutil.rmtree(self.log_file_path_1)
        if os.path.exists('./dumpraw'):
            shutil.rmtree('./dumpraw')


    def test_mutiny_init(self):
        mutiny = Mutiny(self.args)
        self.assertEqual(mutiny.target_host, self.args.target_host)
        self.assertEqual(mutiny.sleep_time, self.args.sleep_time)
        self.assertEqual(mutiny.dump_raw, self.args.dump_raw)
        self.assertEqual(mutiny.quiet, self.args.quiet)
        self.assertEqual(mutiny.log_all, self.args.log_all if not self.args.quiet else False)
        self.assertEqual(mutiny.fuzzer_folder, os.path.abspath(os.path.dirname(self.args.prepped_fuzz)))
        self.assertTrue(os.path.exists(mutiny.output_data_folder_path))

    def test_mutiny_init_quiet(self):
        self.args.quiet = True
        mutiny = Mutiny(self.args)
        self.assertEqual(mutiny.target_host, self.args.target_host)
        self.assertEqual(mutiny.sleep_time, self.args.sleep_time)
        self.assertEqual(mutiny.dump_raw, self.args.dump_raw)
        self.assertEqual(mutiny.quiet, self.args.quiet)
        self.assertEqual(mutiny.log_all, self.args.log_all if not self.args.quiet else False)
        self.assertEqual(mutiny.fuzzer_folder, os.path.abspath(os.path.dirname(self.args.prepped_fuzz)))
        self.assertFalse(os.path.exists(mutiny.output_data_folder_path))

    def test_mutiny_init_dump(self):
        self.args.dump_raw = 'test'
        mutiny = Mutiny(self.args)
        self.assertEqual(mutiny.target_host, self.args.target_host)
        self.assertEqual(mutiny.sleep_time, self.args.sleep_time)
        self.assertEqual(mutiny.dump_raw, self.args.dump_raw)
        self.assertEqual(mutiny.quiet, self.args.quiet)
        self.assertEqual(mutiny.log_all, self.args.log_all if not self.args.quiet else False)
        self.assertEqual(mutiny.fuzzer_folder, os.path.abspath(os.path.dirname(self.args.prepped_fuzz)))
        self.assertTrue(os.path.exists(mutiny.output_data_folder_path))
        self.assertEqual(mutiny.dump_dir, mutiny.output_data_folder_path)

    def test_mutiny_init_dump_quiet(self):
        self.args.dump_raw = True
        self.args.quiet = True
        mutiny = Mutiny(self.args)
        self.assertEqual(mutiny.target_host, self.args.target_host)
        self.assertEqual(mutiny.sleep_time, self.args.sleep_time)
        self.assertEqual(mutiny.dump_raw, self.args.dump_raw)
        self.assertEqual(mutiny.quiet, self.args.quiet)
        self.assertEqual(mutiny.log_all, self.args.log_all if not self.args.quiet else False)
        self.assertEqual(mutiny.fuzzer_folder, os.path.abspath(os.path.dirname(self.args.prepped_fuzz)))
        self.assertTrue(os.path.exists(mutiny.dump_dir))

    def test_import_custom_processors(self):
        self.mutiny.import_custom_processors()
        self.assertIsNotNone(self.mutiny.exception_processor)
        self.assertIsNotNone(self.mutiny.message_processor)
        self.assertIsNotNone(self.mutiny.monitor)


    def test_import_custom_processors_nondefault(self):
        # FIXME: create custom processors to test this
        pass

    def test_fuzz_subcomponents_radamsa(self):
        # subcomp 1 -fuzz
        message = Message()
        seed = 1
        # subcomp 0 - fuzz
        message.set_message_from(Message.Format.Raw, bytearray('test', 'utf-8'), True)
        # subcomp 1 - dont fuzz
        message.append_message_from(Message.Format.Raw, bytearray('test1', 'utf-8'), False)
        # subcomp 2 -fuzz
        message.append_message_from(Message.Format.Raw, bytearray('test2', 'utf-8'), True)
        # subcomp 3 -fuzz
        message.append_message_from(Message.Format.Raw, bytearray('test3', 'utf-8'), True)

        self.mutiny._fuzz_subcomponents(message, seed) 
        self.assertEqual(message.subcomponents[0].get_original_byte_array(), bytearray('test', 'utf-8'))
        self.assertEqual(message.subcomponents[0].get_altered_byte_array(), bytearray('testtest', 'utf-8'))
        self.assertEqual(message.subcomponents[1].get_original_byte_array(), bytearray('test1', 'utf-8'))
        self.assertEqual(message.subcomponents[1].get_altered_byte_array(), bytearray('test1', 'utf-8'))
        message.reset_altered_message()
        self.mutiny._fuzz_subcomponents(message, seed=2)
        self.assertEqual(message.subcomponents[2].get_original_byte_array(), bytearray('test2', 'utf-8'))
        self.assertEqual(message.subcomponents[2].get_altered_byte_array(), bytearray('testest184467441', 'utf-8'))
        message.reset_altered_message()
        self.mutiny._fuzz_subcomponents(message, seed=3)
        self.assertEqual(message.subcomponents[3].get_original_byte_array(), bytearray('test3', 'utf-8'))
        self.assertEqual(message.subcomponents[3].get_altered_byte_array(), bytearray('test-2', 'utf-8'))

        # run again to check that seeds give same result 
        message.reset_altered_message()
        self.mutiny._fuzz_subcomponents(message, seed) 
        self.assertEqual(message.subcomponents[0].get_original_byte_array(), bytearray('test', 'utf-8'))
        self.assertEqual(message.subcomponents[0].get_altered_byte_array(), bytearray('testtest', 'utf-8'))
        self.assertEqual(message.subcomponents[1].get_original_byte_array(), bytearray('test1', 'utf-8'))
        self.assertEqual(message.subcomponents[1].get_altered_byte_array(), bytearray('test1', 'utf-8'))
        message.reset_altered_message()
        self.mutiny._fuzz_subcomponents(message, seed=2)
        self.assertEqual(message.subcomponents[2].get_original_byte_array(), bytearray('test2', 'utf-8'))
        self.assertEqual(message.subcomponents[2].get_altered_byte_array(), bytearray('testest184467441', 'utf-8'))
        message.reset_altered_message()
        self.mutiny._fuzz_subcomponents(message, seed=3)
        self.assertEqual(message.subcomponents[3].get_original_byte_array(), bytearray('test3', 'utf-8'))
        self.assertEqual(message.subcomponents[3].get_altered_byte_array(), bytearray('test-2', 'utf-8'))

    def test_raise_next_monitor_event_if_any_empty_queue(self):
        self.mutiny.monitor.queue = queue.SimpleQueue()
        self.mutiny._raise_next_monitor_event_if_any(is_paused = True)
        # if execution gets here without raising, pass since empty exception queue
        pass

        
    def test_raise_next_monitor_event_if_any_pause(self):
        self.mutiny.monitor.queue = queue.SimpleQueue()
        self.mutiny.monitor.queue.put(PauseFuzzingException())
        with self.assertRaises(PauseFuzzingException) as cm:
            self.mutiny._raise_next_monitor_event_if_any(False)
            self.assertEqual(cm.exception, 0)

    def  test_raise_next_monitor_event_if_any_double_pause(self):
        self.mutiny.monitor.queue = queue.SimpleQueue()
        self.mutiny.monitor.queue.put(PauseFuzzingException())
        with self.assertRaises(PauseFuzzingException) as cm:
            self.mutiny._raise_next_monitor_event_if_any(True)
            self.assertEqual(cm.exception, 0)

    def test_raise_next_monitor_event_if_any_unpause(self):
        self.mutiny.monitor.queue = queue.SimpleQueue()
        self.mutiny.monitor.queue.put(ResumeFuzzingException())
        with self.assertRaises(ResumeFuzzingException) as cm:
            self.mutiny._raise_next_monitor_event_if_any(True)
            self.assertEqual(cm.exception, 0)

    def test_raise_next_monitor_event_if_any_non_pause_except(self):
        self.mutiny.monitor.queue = queue.SimpleQueue()
        self.mutiny.monitor.queue.put(HaltException())
        self.mutiny._raise_next_monitor_event_if_any(True)
        # shouldnt raise exception

    def test_get_run_numbers_from_args(self):
        pass
        min_run = ''
        max_run = ''
        # subsequent
        str_args = '1-2'
        min_run, max_run = self.mutiny._get_run_numbers_from_args(str_args)
        self.assertEqual(min_run, 1)
        self.assertEqual(max_run, 2)
        # --skip-to
        str_args = '1-'
        min_run, max_run = self.mutiny._get_run_numbers_from_args(str_args)
        self.assertEqual(min_run, 1)
        self.assertEqual(max_run, -1)
        # single iteration
        str_args = '1'
        min_run, max_run = self.mutiny._get_run_numbers_from_args(str_args)
        self.assertEqual(min_run, 1)
        self.assertEqual(max_run,1)

        # reverse order
        str_args = '2-1'
        with self.assertRaises(SystemExit) as contextManager:
            min_run, max_run = self.mutiny._get_run_numbers_from_args(str_args)

        # invalid format
        str_args = '1-2-5'
        with self.assertRaises(SystemExit) as contextManager:
            min_run, max_run = self.mutiny._get_run_numbers_from_args(str_args)
            self.assertEqual(contextManager.exception.code, 3)

