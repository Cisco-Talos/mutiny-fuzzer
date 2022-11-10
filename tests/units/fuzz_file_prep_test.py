import unittest
import os
from unittest.mock import patch
from backend.fuzz_file_prep import FuzzFilePrep
from backend.fuzzer_data import FuzzerData
from backend.fuzzer_types import Message
from argparse import Namespace



class TestFuzzFilePrep(unittest.TestCase):
    def setUp(self):
        self.pcap_file_1 = './tests/assets/test_FuzzFilePrep1.pcap'
        self.pcap_file_2 = self.pcap_file_1# FIXME: change to pcap with same ports for both client/server
        self.pcap_file_3 = self.pcap_file_1# FIXME: change to pcap with multiple consecutive inbound/outbounds
        self.cra_file_1 = './tests/assets/test_FuzzFilePrep1.cra'
        self.cra_file_2 = self.cra_file_1  # FIXME: change this to a cArray with multiple consecutive outbound/inbounds
        self.invalid_file = './tests/assets/test_FuzzFilePrep.invalid'
        self.prompt_and_output_file_1 = './tests/assets/test_FuzzFilePrep1-0.fuzzer'
        self.prompt_and_output_file_2 = './tests/assets/test_FuzzFilePrep1-0,2-4.fuzzer'
        self.nonexistent_file = 'non/existent/file'
        args = Namespace(pcap_file=self.pcap_file_1, processor_dir='default', dump_ascii=False, force=True, raw=False)
        self.prepper = FuzzFilePrep(args)

    def tearDown(self):
        if os.path.exists(self.prompt_and_output_file_1):
            os.remove(self.prompt_and_output_file_1)
        if os.path.exists(self.prompt_and_output_file_2):
            os.remove(self.prompt_and_output_file_2)


    def test_FuzzFilePrep_init(self):
        args = Namespace(pcap_file=self.pcap_file_1, processor_dir=['default'], dump_ascii=True, force=True, raw=True)
        prepper = FuzzFilePrep(args)
        self.assertEqual(prepper.last_message_direction, -1)
        self.assertEqual(prepper.fuzzer_data.processor_directory, 'default')
        self.assertTrue(prepper.force_defaults)
        self.assertIsNone(prepper.default_port)
        self.assertTrue(prepper.dump_ascii)
        self.assertTrue(prepper.is_raw)
        self.assertFalse(prepper.c_array)
        

    def test_process_input_file_invalid_type(self):
        # non-pcap/cArray file
        self.prepper.input_file_path = self.invalid_file
        with self.assertRaises(SystemExit) as contextManager: 
            self.prepper._process_input_file()
            self.assertEqual(contextManager.exception.code, 3)


    def test_process_pcap(self):
        # pcap
        self.prepper.input_file_path = self.pcap_file_1
        self.prepper._process_pcap()

        self.assertNotEqual(len(self.prepper.fuzzer_data.message_collection.messages), 0)
        self.assertEqual(self.prepper.default_port, 9999)
        self.assertEqual(self.prepper.last_message_direction, "inbound")
        # --- checking message contents
        self.assertEqual(self.prepper.fuzzer_data.message_collection.messages[0].direction, "outbound")
        self.assertEqual(self.prepper.fuzzer_data.message_collection.messages[0].subcomponents[0].message, b'1234.4321')

        self.assertEqual(self.prepper.fuzzer_data.message_collection.messages[1].direction, "inbound")
        self.assertEqual(self.prepper.fuzzer_data.message_collection.messages[1].subcomponents[0].message, b'[^.^] Launching 4321 testcases for pid 4321')

    def test_process_pcap_non_default(self):
        self.prepper.force_defaults = False
        self.prepper.input_file_path = self.pcap_file_1
        self.prepper._process_pcap(test_port=9999,test_mac='DE:AD:BE:EF:FE:ED', combine_packets=True)

        self.assertEqual(self.prepper.default_port, 9999)
        self.assertEqual(self.prepper.last_message_direction, "inbound")
        # --- checking message contents
        self.assertEqual(self.prepper.fuzzer_data.message_collection.messages[0].direction, "outbound")
        self.assertEqual(self.prepper.fuzzer_data.message_collection.messages[0].subcomponents[0].message, b'1234.4321')

        self.assertEqual(self.prepper.fuzzer_data.message_collection.messages[1].direction, "inbound")
        self.assertEqual(self.prepper.fuzzer_data.message_collection.messages[1].subcomponents[0].message, b'[^.^] Launching 4321 testcases for pid 4321')

    def test_process_pcap_non_default_same_ports(self):
        # --- TODO: create a pcap with hosts connecting via same port so testMac can be used to verify stability
        self.prepper.force_defaults = False
        self.prepper.input_file_path = self.pcap_file_2 # FIXME: change to pcap with same ports for both client/server
        self.prepper._process_pcap(test_port=55161, test_mac='DE:AD:BE:EF:FE:ED', combine_packets=True)
        pass
    
    def test_process_pcap_non_default_dont_combine(self):
        self.prepper.force_defaults = False
        self.prepper.input_file_path = self.pcap_file_3 # FIXME: change to pcap with multiple consecutive inbound/outbounds
        self.prepper._process_pcap(test_port=55161, test_mac='DE:AD:BE:EF:FE:ED', combine_packets=False)


    def test_process_c_array(self):
        # cArray
        self.prepper.input_file_path = self.cra_file_1
        self.prepper._process_c_array()

        self.assertNotEqual(len(self.prepper.fuzzer_data.message_collection.messages), 0)
        self.assertEqual(self.prepper.last_message_direction, "inbound")

        # --- checking message contents
        self.assertEqual(self.prepper.fuzzer_data.message_collection.messages[0].direction, "inbound")
        self.assertEqual(self.prepper.fuzzer_data.message_collection.messages[0].subcomponents[0].message, b'RFB 003.008\n')

        self.assertEqual(self.prepper.fuzzer_data.message_collection.messages[1].direction, "outbound")
        self.assertEqual(self.prepper.fuzzer_data.message_collection.messages[1].subcomponents[0].message, b'RFB 003.008\n')

        self.assertEqual(self.prepper.fuzzer_data.message_collection.messages[2].direction, "inbound")
        self.assertEqual(self.prepper.fuzzer_data.message_collection.messages[2].subcomponents[0].message, b'\x02\x02\x10')

        self.assertEqual(self.prepper.fuzzer_data.message_collection.messages[3].direction, "outbound")
        self.assertEqual(self.prepper.fuzzer_data.message_collection.messages[3].subcomponents[0].message, b'\x02')

        self.assertEqual(self.prepper.fuzzer_data.message_collection.messages[4].direction, "inbound")
        self.assertEqual(self.prepper.fuzzer_data.message_collection.messages[4].subcomponents[0].message, b'\xaa\xc3\xe3\x95\xd3|\xd7\xf9\xfd\x84\xe7\xf5R\x94\x93\x1c')
         
        self.assertEqual(self.prepper.fuzzer_data.message_collection.messages[5].direction, "outbound")
        self.assertEqual(self.prepper.fuzzer_data.message_collection.messages[5].subcomponents[0].message, b'2\xd1\xa0I\x93q\x03\x11e$\x83\x94\xc6t\x8e\x08')

        self.assertEqual(self.prepper.fuzzer_data.message_collection.messages[6].direction, "inbound")
        self.assertEqual(self.prepper.fuzzer_data.message_collection.messages[6].subcomponents[0].message, b'\x00\x00\x00\x00')

    def test_process_c_array_non_default(self):
        self.prepper.input_file_path = self.cra_file_2
        self.prepper._process_c_array(combine_packets = False)
        pass
        # TODO: complete with asserts based on new cArray

    def test_gen_fuzz_config(self):
        self.prepper.default_port = 9999
        self.prepper._gen_fuzz_config()
        self.assertEqual(self.prepper.fuzzer_data.failure_threshold, 3)
        self.assertEqual(self.prepper.fuzzer_data.failure_timeout, 5)
        self.assertEqual(self.prepper.fuzzer_data.proto, "tcp")


    def test_gen_fuzz_config_non_default(self):
        '''
        FIXME: this wont pass because we are reading proto from packet
        # with FORCE_DEFAULTS = false
        self.prepper.force_defaults = False
        self.prepper._gen_fuzz_config(failure_threshold=4, failure_timeout=4, proto='udp',port=30)
        self.assertEqual(self.prepper.fuzzer_data.failure_threshold, 4)
        self.assertEqual(self.prepper.fuzzer_data.failure_timeout, 4)
        self.assertEqual(self.prepper.fuzzer_data.proto, "udp")
        self.assertEqual(self.prepper.fuzzer_data.port, 30)
        '''

    def test_gen_fuzz_config_non_default_raw(self):
        '''
        FIXME: this wont pass because we are reading proto from packet
        # with FORCE_DEFAULTS = false
        self.prepper.force_defaults = False
        self.prepper._gen_fuzz_config(failure_threshold=4, failure_timeout=4, proto='raw',port=30)
        self.assertEqual(self.prepper.fuzzer_data.failure_threshold, 4)
        self.assertEqual(self.prepper.fuzzer_data.failure_timeout, 4)
        self.assertEqual(self.prepper.fuzzer_data.proto, "raw")
        self.assertEqual(self.prepper.fuzzer_data.port, 30)
        '''


    def test_get_next_message(self):
        self.prepper.fuzzer_data = FuzzerData()
        self.prepper.input_file_path = self.cra_file_1 
        with open(self.prepper.input_file_path, 'r') as input_file:
            self.prepper._process_c_array(input_file)
        input_file.close()
        self.assertEqual(self.prepper._get_next_message(0, Message.Direction.Inbound), 0)
        self.assertEqual(self.prepper._get_next_message(0, Message.Direction.Outbound), 1)
        self.assertEqual(self.prepper._get_next_message(3, Message.Direction.Inbound), 4)
        self.assertEqual(self.prepper._get_next_message(3, Message.Direction.Outbound), 3)
        self.assertEqual(self.prepper._get_next_message(6, Message.Direction.Outbound), None)


    def test_prompt_and_output(self):
        self.prepper.fuzzer_data = FuzzerData()
        self.prepper.input_file_path = self.pcap_file_1
        with open(self.prepper.input_file_path, 'r') as input_file:
            self.prepper._process_pcap(input_file)
        input_file.close()
        # with Defaults
        self.prepper._gen_fuzz_config()
        # FUZZER_DATA has been generated, now we can run prompt and output 
        output_message_num = self.prepper._get_next_message(0,Message.Direction.Outbound)
        self.prepper._prompt_and_output(output_message_num, auto_generate_all_client=True)
        with open(self.prompt_and_output_file_1, 'r') as file:
            lines = file.readlines()
            for i in range(0, len(lines)):
                line = lines[i]
                if i == 4:
                    self.assertIn('processor_dir default', line)
                if i == 6:
                    self.assertIn('failure_threshold 3', line)
                if i == 8:
                    self.assertIn('failure_timeout 5', line)
                if i == 10:
                    self.assertIn('receive_timeout 1.0', line)
                if i == 12:
                    self.assertIn('should_perform_test_run 1', line)
                if i == 14:
                    self.assertIn('proto tcp', line)
                if i == 16:
                    self.assertIn('port 9999', line)
                if i == 18:
                    self.assertIn('source_port -1', line)
                if i == 20:
                    self.assertIn('source_ip 0.0.0.0', line)
                if i == 24:
                    self.assertIn('outbound fuzz \'1234.4321\'', line)
                if i == 25:
                    self.assertIn('inbound \'[^.^] Launching 4321 testcases for pid 4321\'', line)


    def test_prompt_and_output_non_default(self):
        self.prepper.fuzzer_data = FuzzerData()
        self.prepper.input_file_path = self.cra_file_1
        with open(self.prepper.input_file_path, 'r') as input_file:
            self.prepper._process_c_array(input_file)
        input_file.close()
        # with Defaults
        self.prepper.default_port = 9999
        self.prepper._gen_fuzz_config()
        self.prepper.force_defaults = False
        # FUZZER_DATA has been generated, now we can run prompt and output 
        output_message_num = self.prepper._get_next_message(0,Message.Direction.Outbound)
        self.prepper._prompt_and_output(output_message_num, final_msg_num=5, msgs_to_fuzz='0,2-4')
        with open(self.prompt_and_output_file_2, 'r') as file:
            lines = file.readlines()
            for i in range(0, len(lines)):
                line = lines[i]
                if i == 4:
                    self.assertIn('processor_dir default', line)
                if i == 6:
                    self.assertIn('failure_threshold 3', line)
                if i == 8:
                    self.assertIn('failure_timeout 5', line)
                if i == 10:
                    self.assertIn('receive_timeout 1.0', line)
                if i == 12:
                    self.assertIn('should_perform_test_run 1', line)
                if i == 14:
                    self.assertIn('proto tcp', line)
                if i == 16:
                    self.assertIn('port 9999', line)
                if i == 18:
                    self.assertIn('source_port -1', line)
                if i == 20:
                    self.assertIn('source_ip 0.0.0.0', line)
                if i == 24:
                    self.assertIn('inbound fuzz \'RFB 003.008\\n\'', line)
                if i == 25:
                    self.assertIn('outbound \'RFB 003.008\\n\'', line)
                if i == 26:
                    self.assertIn('inbound fuzz \'\\x02\\x02\\x10\'', line)
                if i == 27:
                    self.assertIn('outbound fuzz \'\\x02\'', line)
                if i == 28:
                    self.assertIn('inbound fuzz \'\\xaa\\xc3\\xe3\\x95\\xd3|\\xd7\\xf9\\xfd\\x84\\xe7\\xf5R\\x94\\x93\\x1c\'', line)
                if i == 30:
                    self.assertEqual('\n', line)

            os.remove(self.prompt_and_output_file_2)

