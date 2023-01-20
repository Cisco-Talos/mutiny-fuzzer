import unittest
from backend.fuzzer_types import Logger, MessageCollection, Message, MessageSubComponent
import os
import shutil

class TestLogger(unittest.TestCase):
    def setUp(self):
        self.logger = Logger('./tests/units/test-output')

    def tearDown(self):
        self.logger = None
        if os.path.exists('./tests/units/test-output'):
            shutil.rmtree('./tests/units/test-output')

    def test_loggerInit(self):
        # existant dir
        with self.assertRaises(SystemExit) as contextManager:  
            logger = Logger('./tests/units/test-output')
            self.assertEqual(contextManager.exception.code, 3)
        # non-write dir
        with self.assertRaises(SystemExit) as contextManager:
            logger = Logger('/root/shouldnt-have-write-perms')
            self.assertEqual(contextManager.exception.code, 3, msg='you can ignore this if running as root')
        os.rmdir('./tests/units/test-output')
        if os.path.exists('/root/shouldnt-have-write-perms'):
            os.rmdir('/root/shouldnt-have-write-perms')
        
    def test_set_received_message_data(self):
        idx = 2
        data = b'somedata'
        self.logger.set_received_message_data(idx,data)
        self.assertEqual(self.logger.received_message_data[idx], data)


    def test_set_highest_message_number(self):
        self.logger.set_highest_message_number(43)
        self.assertEqual(self.logger._highest_message_number, 43)

    def test__output_log(self):
        run_num = 0
        error_message =  'this is an error msg'
        received_message_data = {0: bytearray('message1', 'utf-8'), 1: bytearray('message2', 'utf-8'), 2: bytearray('crash', 'utf-8')}
        highest_message_number = 2
        # populate message_collection
        message_collection = MessageCollection()
        m1 = Message()
        m1.set_message_from(Message.Format.Raw, bytearray('message1', 'utf-8'), False)
        m1.direction = 'inbound'
        m2 = Message()
        m2.append_message_from(Message.Format.Raw, bytearray('message2', 'utf-8'), True)
        m2.direction = 'outbound'
        m3 = Message()
        m3.append_message_from(Message.Format.Raw, bytearray('message3', 'utf-8'), False)
        m3.direction = 'inbound'
        message_collection.messages = [m1,m2,m3]

        # call _output_log
        self.logger._output_log(run_num, message_collection, error_message, received_message_data, highest_message_number)

        # check contents of written log file
        with open(os.path.join(self.logger._folder_path,str(run_num)), 'r') as outputFile:
            lines = outputFile.readlines()

            # record data that should be found in the output file
            found_seed = False
            found_error_msg = False
            found_failed_conn = False
            found_first_packet = False
            found_second_packet = False
            found_second_fuzz = False
            found_third_packet = False
            found_first_expected = False
            found_second_expected = False
            found_third_unexpected = False
            found_last_msg = False

            # go through lines to look for data 
            for i in range(0,len(lines)):
                line = lines[i]
                if i == 0 and 'seed 0' in line:
                    found_seed = True
                if i == 1 and 'this is an error msg' in line:
                    found_error_msg = True
                if i == 2 and 'Failed to connect on this run.' in line:
                    found_failed_conn = True
                if i == 4 and ('0: '+ m1.get_serialized()) in line:
                    found_first_packet = True
                if i == 5 and 'Received expected data' in line:
                    found_first_expected = True
                if i == 7 and ('1: ' + m2.get_serialized()) in line:
                    found_second_packet = True
                if i == 8 and m2.get_altered_serialized() in line:
                    found_second_fuzz = True
                if i == 10 and 'Received expected data' in line:
                    found_second_expected = True
                if i == 12 and ('2: ' + m3.get_serialized()) in line:
                    found_third_packet = True
                if i == 13 and ('2: ' + Message.serialize_byte_array(received_message_data[2])) in line:
                    found_third_unexpected = True
                if i == 14 and ('This is the last message received') in line:
                    found_last_msg = True


            
            # make sure we found them all
            self.assertTrue(found_seed)
            self.assertTrue(found_error_msg)
            self.assertTrue(found_failed_conn)
            self.assertTrue(found_first_packet)
            self.assertTrue(found_first_expected)
            self.assertTrue(found_second_packet)
            self.assertTrue(found_second_fuzz)
            self.assertTrue(found_second_expected)
            self.assertTrue(found_third_packet)
            self.assertTrue(found_third_unexpected)
            self.assertTrue(found_last_msg)

        # test again with 
        # run_num != 0 and highest_message_number != -1 
        run_num = 1 

    def test_reset_for_new_run(self):
        # valid attributes
        self.logger.received_message_data = {1 : b'somedata'}
        self.logger._highest_message_number = 10
        self.logger.received_message_data[2] = b'otherdata'
        self.logger.reset_for_new_run()
        # check that last run data is intact
        self.assertEqual(self.logger._last_received_message_data[1], b'somedata' )
        self.assertEqual(self.logger._last_highest_message_number, 10)
        # check that dict was reset
        self.assertNotIn(b'otherdata', self.logger.received_message_data)
        # check that highest message num was reset
        self.assertEqual(self.logger._highest_message_number, -1)

    def test_reset_for_new_run_invalid_attr(self):
        # setUp() makes the call for us through Logger.__init__, just need to check vals
        self.assertEqual(self.logger._last_received_message_data, {})
        self.assertEqual(self.logger._last_highest_message_number, -1)
        self.assertEqual(self.logger.received_message_data, {})
        self.assertEqual(self.logger._highest_message_number, -1)

