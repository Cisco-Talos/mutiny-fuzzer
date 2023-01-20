import unittest
import os
from backend.fuzzer_data import FuzzerData

class TestFuzzerData(unittest.TestCase):

    def setUp(self):
        self.fuzz_data = FuzzerData()
        self.read_file_1 = './tests/assets/test_fuzz_data_read.fuzzer'
        self.read_file_2 = './tests/assets/test_fuzz_data_read_non_default.fuzzer'
        self.write_file_1 = './tests/assets/test_write_to_file.fuzzer'

    def tearDown(self):
        pass

    def test_init(self):
        self.assertIsNotNone(self.fuzz_data.message_collection)
        self.assertEqual(self.fuzz_data.processor_directory, 'default')
        self.assertEqual(self.fuzz_data.failure_threshold, 3)
        self.assertEqual(self.fuzz_data.proto, 'tcp')
        self.assertEqual(self.fuzz_data.target_port, 0)
        self.assertEqual(self.fuzz_data.source_port, -1)
        self.assertEqual(self.fuzz_data.source_ip, '0.0.0.0')
        self.assertEqual(self.fuzz_data.should_perform_test_run, True)
        self.assertEqual(self.fuzz_data.receive_timeout, 1.0)
        self.assertEqual(self.fuzz_data.comments, {})
        self.assertEqual(self.fuzz_data._read_comments, "")
        self.assertEqual(self.fuzz_data.messages_to_fuzz, [])

    def test_read_from_file(self):
        file_path = self.read_file_1
        self.fuzz_data.read_from_file(file_path)
        self.assertEqual(self.fuzz_data.message_collection.messages[0].subcomponents[0].message, bytearray(b'RFB 003.008\n'))
        self.assertEqual(self.fuzz_data.processor_directory, 'default')
        self.assertEqual(self.fuzz_data.failure_threshold, 3)
        self.assertEqual(self.fuzz_data.failure_timeout, 5)
        self.assertEqual(self.fuzz_data.receive_timeout, 1.0)
        self.assertEqual(self.fuzz_data.should_perform_test_run, 1)
        self.assertEqual(self.fuzz_data.proto, 'tcp')
        self.assertEqual(self.fuzz_data.target_port, 9999)
        self.assertEqual(self.fuzz_data.source_port, -1)
        self.assertEqual(self.fuzz_data.source_ip, '0.0.0.0')
        # --- checking message contents
        self.assertEqual(self.fuzz_data.message_collection.messages[0].direction, "inbound")
        self.assertEqual(self.fuzz_data.message_collection.messages[0].subcomponents[0].message, b'RFB 003.008\n')

        self.assertEqual(self.fuzz_data.message_collection.messages[1].direction, "outbound")
        self.assertEqual(self.fuzz_data.message_collection.messages[1].subcomponents[0].message, b'RFB 003.008\n')
        self.assertTrue(self.fuzz_data.message_collection.messages[1].is_fuzzed)

        self.assertEqual(self.fuzz_data.message_collection.messages[2].direction, "inbound")
        self.assertEqual(self.fuzz_data.message_collection.messages[2].subcomponents[0].message, b'\x02\x02\x10')

        self.assertEqual(self.fuzz_data.message_collection.messages[3].direction, "outbound")
        self.assertEqual(self.fuzz_data.message_collection.messages[3].subcomponents[0].message, b'\x02')

        self.assertEqual(self.fuzz_data.message_collection.messages[4].direction, "inbound")
        self.assertEqual(self.fuzz_data.message_collection.messages[4].subcomponents[0].message, b'\xaa\xc3\xe3\x95\xd3|\xd7\xf9\xfd\x84\xe7\xf5R\x94\x93\x1c')
         
        self.assertEqual(self.fuzz_data.message_collection.messages[5].direction, "outbound")
        self.assertEqual(self.fuzz_data.message_collection.messages[5].subcomponents[0].message, b'2\xd1\xa0I\x93q\x03\x11e$\x83\x94\xc6t\x8e\x08')

        self.assertEqual(self.fuzz_data.message_collection.messages[6].direction, "inbound")
        self.assertEqual(self.fuzz_data.message_collection.messages[6].subcomponents[0].message, b'\x00\x00\x00\x00')


    def test_push_comments(self):
        comment_section_name = "processor_dir"
        comment = 'test'
        self.fuzz_data._read_comments = comment
        self.fuzz_data._push_comments(comment_section_name)
        self.assertEqual(self.fuzz_data.comments[comment_section_name], comment)
        self.assertEqual(self.fuzz_data._read_comments, '')

    def test_push_commentsEmpty(self):
        # empty _read_comments
        comment_section_name = "processor_dir"
        self.fuzz_data._push_comments(comment_section_name)
        self.assertEqual(self.fuzz_data.comments[comment_section_name], '')
        self.assertEqual(self.fuzz_data._read_comments, '')

    def test__append_comments(self):
        comment_section_name = "processor_dir"
        comment = 'test'
        # key exists, appending to empty string
        self.fuzz_data._read_comments = comment
        self.fuzz_data._push_comments(comment_section_name)
        self.fuzz_data._append_comments(comment_section_name)
        self.assertEqual(self.fuzz_data.comments[comment_section_name], comment)
        self.assertEqual(self.fuzz_data._read_comments, '')
        # key exists, appending to non empty string
        self.fuzz_data._read_comments = comment
        self.fuzz_data._append_comments(comment_section_name)
        self.assertEqual(self.fuzz_data.comments[comment_section_name], 'test' + comment)
        self.assertEqual(self.fuzz_data._read_comments, '')

        # key does not exist
        comment_section_name = 'notasection'
        self.fuzz_data._read_comments = comment
        self.fuzz_data._append_comments(comment_section_name)
        self.assertEqual(self.fuzz_data.comments[comment_section_name], comment)
        self.assertEqual(self.fuzz_data._read_comments, '')

    def test_read_from_fd(self):
        file = open(self.read_file_1, 'r')
        self.fuzz_data.read_from_fd(file)
        file.close()
        self.assertEqual(self.fuzz_data.message_collection.messages[0].subcomponents[0].message, bytearray(b'RFB 003.008\n'))
        self.assertEqual(self.fuzz_data.processor_directory, 'default')
        self.assertEqual(self.fuzz_data.failure_threshold, 3)
        self.assertEqual(self.fuzz_data.failure_timeout, 5)
        self.assertEqual(self.fuzz_data.receive_timeout, 1.0)
        self.assertEqual(self.fuzz_data.should_perform_test_run, 1)
        self.assertEqual(self.fuzz_data.proto, 'tcp')
        self.assertEqual(self.fuzz_data.target_port, 9999)
        self.assertEqual(self.fuzz_data.source_port, -1)
        self.assertEqual(self.fuzz_data.source_ip, '0.0.0.0')
        # --- checking message contents
        self.assertEqual(self.fuzz_data.message_collection.messages[0].direction, "inbound")
        self.assertEqual(self.fuzz_data.message_collection.messages[0].subcomponents[0].message, b'RFB 003.008\n')

        self.assertEqual(self.fuzz_data.message_collection.messages[1].direction, "outbound")
        self.assertEqual(self.fuzz_data.message_collection.messages[1].subcomponents[0].message, b'RFB 003.008\n')
        self.assertTrue(self.fuzz_data.message_collection.messages[1].is_fuzzed)

        self.assertEqual(self.fuzz_data.message_collection.messages[2].direction, "inbound")
        self.assertEqual(self.fuzz_data.message_collection.messages[2].subcomponents[0].message, b'\x02\x02\x10')

        self.assertEqual(self.fuzz_data.message_collection.messages[3].direction, "outbound")
        self.assertEqual(self.fuzz_data.message_collection.messages[3].subcomponents[0].message, b'\x02')

        self.assertEqual(self.fuzz_data.message_collection.messages[4].direction, "inbound")
        self.assertEqual(self.fuzz_data.message_collection.messages[4].subcomponents[0].message, b'\xaa\xc3\xe3\x95\xd3|\xd7\xf9\xfd\x84\xe7\xf5R\x94\x93\x1c')
         
        self.assertEqual(self.fuzz_data.message_collection.messages[5].direction, "outbound")
        self.assertEqual(self.fuzz_data.message_collection.messages[5].subcomponents[0].message, b'2\xd1\xa0I\x93q\x03\x11e$\x83\x94\xc6t\x8e\x08')

        self.assertEqual(self.fuzz_data.message_collection.messages[6].direction, "inbound")
        self.assertEqual(self.fuzz_data.message_collection.messages[6].subcomponents[0].message, b'\x00\x00\x00\x00')

    def test_read_from_fd_non_default(self):
        file = open(self.read_file_2, 'r')
        self.fuzz_data.read_from_fd(file)
        file.close()
        self.assertEqual(self.fuzz_data.message_collection.messages[0].subcomponents[0].message, bytearray(b'RFB 003.008\n'))
        self.assertEqual(self.fuzz_data.processor_directory, './not/default')
        self.assertEqual(self.fuzz_data.failure_threshold, 20)
        self.assertEqual(self.fuzz_data.failure_timeout, 10)
        self.assertEqual(self.fuzz_data.receive_timeout, 3.5)
        # --- checking message contents
        self.assertEqual(self.fuzz_data.message_collection.messages[0].direction, "inbound")
        self.assertEqual(self.fuzz_data.message_collection.messages[0].subcomponents[0].message, b'RFB 003.008\n')

        self.assertEqual(self.fuzz_data.message_collection.messages[1].direction, "outbound")
        self.assertEqual(self.fuzz_data.message_collection.messages[1].subcomponents[0].message, b'RFB 003.008\n')
        self.assertTrue(self.fuzz_data.message_collection.messages[1].is_fuzzed)

        self.assertEqual(self.fuzz_data.message_collection.messages[2].direction, "inbound")
        self.assertEqual(self.fuzz_data.message_collection.messages[2].subcomponents[0].message, b'\x02\x02\x10')

        self.assertEqual(self.fuzz_data.message_collection.messages[3].direction, "outbound")
        self.assertEqual(self.fuzz_data.message_collection.messages[3].subcomponents[0].message, b'\x02')

        self.assertEqual(self.fuzz_data.message_collection.messages[4].direction, "inbound")
        self.assertEqual(self.fuzz_data.message_collection.messages[4].subcomponents[0].message, b'\xaa\xc3\xe3\x95\xd3|\xd7\xf9\xfd\x84\xe7\xf5R\x94\x93\x1c')
         
        self.assertEqual(self.fuzz_data.message_collection.messages[5].direction, "outbound")
        self.assertEqual(self.fuzz_data.message_collection.messages[5].subcomponents[0].message, b'2\xd1\xa0I\x93q\x03\x11e$\x83\x94\xc6t\x8e\x08')

        self.assertEqual(self.fuzz_data.message_collection.messages[6].direction, "inbound")
        self.assertEqual(self.fuzz_data.message_collection.messages[6].subcomponents[0].message, b'\x00\x00\x00\x00')


    
    def test_get_comments(self):
        # nonexistant section
        comment_section_name = 'foo'
        self.assertEqual(self.fuzz_data._get_comments(comment_section_name), '')
        # existent section
        comment_section_name = 'processor_dir'
        comments = 'test'
        self.fuzz_data.comments[comment_section_name] = comments
        self.assertEqual(self.fuzz_data._get_comments(comment_section_name), comments)
        


    def test_set_messages_to_fuzz_from_string(self):
        file = open(self.read_file_1, 'r')
        self.fuzz_data.read_from_fd(file)
        file.close()
        messages_to_fuzz_str = '1,3-4'
        self.fuzz_data.set_messages_to_fuzz_from_string(messages_to_fuzz_str)
        self.assertIn(1, self.fuzz_data.messages_to_fuzz)
        self.assertIn(3, self.fuzz_data.messages_to_fuzz)
        self.assertIn(4, self.fuzz_data.messages_to_fuzz)
        messages_to_fuzz_str = '2-3,1'
        self.fuzz_data.set_messages_to_fuzz_from_string(messages_to_fuzz_str)
        self.assertIn(2, self.fuzz_data.messages_to_fuzz)
        self.assertIn(3, self.fuzz_data.messages_to_fuzz)
        self.assertIn(1, self.fuzz_data.messages_to_fuzz)
        self.assertNotIn(4, self.fuzz_data.messages_to_fuzz)
        messages_to_fuzz_str = '0'
        self.fuzz_data.set_messages_to_fuzz_from_string(messages_to_fuzz_str)
        self.assertIn(0, self.fuzz_data.messages_to_fuzz)

    def test_write_to_file(self):
        file = open(self.read_file_1, 'r')
        self.fuzz_data.read_from_fd(file)
        file.close()
        file_path = self.write_file_1
        # no dupes, can create file
        self.fuzz_data.write_to_file(file_path)
        self.assertTrue(os.path.exists(file_path))
        #  existant files
        self.fuzz_data.write_to_file(file_path)
        new_file_path = file_path + '-1'
        self.assertTrue(os.path.exists((new_file_path)))
        
        os.remove(file_path)
        os.remove((new_file_path))

    def test_write_to_fd(self):
        in_file = open(self.read_file_1, 'r')
        self.fuzz_data.read_from_fd(in_file)
        in_file.close()
        out_file = open(self.write_file_1, 'w') 
        self.fuzz_data.write_to_fd(out_file, default_comments=True)
        out_file.close()

        # now open both and compare contents
        in_file = open(self.read_file_1, 'r')
        out_file = open(self.write_file_1, 'r') 
        in_lines = in_file.readlines()
        out_lines = out_file.readlines()
        self.assertEqual(len(in_lines), len(out_lines))
        for i in range(len(in_lines)):
            in_line = in_lines[i]
            out_line = out_lines[i]
            self.assertEqual(in_line, out_line)
        in_file.close()
        out_file.close()
        os.remove(self.write_file_1)
