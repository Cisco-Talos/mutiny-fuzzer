import unittest
import os
from backend.fuzzer_data import FuzzerData

class FuzzerDataTests(unittest.TestCase):

    def setUp(self):
        self.fuzz_data = FuzzerData()

    def tearDown(self):
        pass

    def test_init(self):
        self.assertIsNotNone(self.fuzz_data.message_collection)
        self.assertEqual(self.fuzz_data.processor_directory, 'default')
        self.assertEqual(self.fuzz_data.failureThreshold, 3)
        self.assertEqual(self.fuzz_data.proto, 'tcp')
        self.assertEqual(self.fuzz_data.port, 0)
        self.assertEqual(self.fuzz_data.sourcePort, -1)
        self.assertEqual(self.fuzz_data.sourceIP, '0.0.0.0')
        self.assertEqual(self.fuzz_data.shouldPerformTestRun, True)
        self.assertEqual(self.fuzz_data.receiveTimeout, 1.0)
        self.assertEqual(self.fuzz_data.comments, {})
        self.assertEqual(self.fuzz_data._readComments, "")
        self.assertEqual(self.fuzz_data.messagesToFuzz, [])

    def test_readFromFile(self):
        filePath = './tests/units/input_files/test_FuzzDataRead.fuzzer'
        self.fuzz_data.readFromFile(filePath)
        self.assertEqual(self.fuzz_data.message_collection.messages[0].subcomponents[0].message, bytearray(b'RFB 003.008\n'))
        self.assertEqual(self.fuzz_data.processorDirectory, 'default')
        self.assertEqual(self.fuzz_data.failureThreshold, 3)
        self.assertEqual(self.fuzz_data.failureTimeout, 5)
        self.assertEqual(self.fuzz_data.receiveTimeout, 1.0)
        self.assertEqual(self.fuzz_data.shouldPerformTestRun, 1)
        self.assertEqual(self.fuzz_data.proto, 'tcp')
        self.assertEqual(self.fuzz_data.port, 9999)
        self.assertEqual(self.fuzz_data.sourcePort, -1)
        self.assertEqual(self.fuzz_data.sourceIP, '0.0.0.0')
        # --- checking message contents
        self.assertEqual(self.fuzz_data.message_collection.messages[0].direction, "inbound")
        self.assertEqual(self.fuzz_data.message_collection.messages[0].subcomponents[0].message, b'RFB 003.008\n')

        self.assertEqual(self.fuzz_data.message_collection.messages[1].direction, "outbound")
        self.assertEqual(self.fuzz_data.message_collection.messages[1].subcomponents[0].message, b'RFB 003.008\n')
        self.assertTrue(self.fuzz_data.message_collection.messages[1].isFuzzed)

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


    def test__pushComments(self):
        commentSectionName = "processor_dir"
        comment = 'test'
        self.fuzz_data._readComments = comment
        self.fuzz_data._pushComments(commentSectionName)
        self.assertEqual(self.fuzz_data.comments[commentSectionName], comment)
        self.assertEqual(self.fuzz_data._readComments, '')

    def test_pushCommentsEmpty(self):
        # empty _readComments
        commentSectionName = "processor_dir"
        self.fuzz_data._pushComments(commentSectionName)
        self.assertEqual(self.fuzz_data.comments[commentSectionName], '')
        self.assertEqual(self.fuzz_data._readComments, '')

    def test__appendComments(self):
        commentSectionName = "processor_dir"
        comment = 'test'
        # key exists, appending to empty string
        self.fuzz_data._readComments = comment
        self.fuzz_data._pushComments(commentSectionName)
        self.fuzz_data._appendComments(commentSectionName)
        self.assertEqual(self.fuzz_data.comments[commentSectionName], comment)
        self.assertEqual(self.fuzz_data._readComments, '')
        # key exists, appending to non empty string
        self.fuzz_data._readComments = comment
        self.fuzz_data._appendComments(commentSectionName)
        self.assertEqual(self.fuzz_data.comments[commentSectionName], 'test' + comment)
        self.assertEqual(self.fuzz_data._readComments, '')

        # key does not exist
        commentSectionName = 'notasection'
        self.fuzz_data._readComments = comment
        self.fuzz_data._appendComments(commentSectionName)
        self.assertEqual(self.fuzz_data.comments[commentSectionName], comment)
        self.assertEqual(self.fuzz_data._readComments, '')

    def test_readFromFD(self):
        file = open('./tests/units/input_files/test_FuzzDataRead.fuzzer', 'r')
        self.fuzz_data.readFromFD(file)
        file.close()
        self.assertEqual(self.fuzz_data.message_collection.messages[0].subcomponents[0].message, bytearray(b'RFB 003.008\n'))
        self.assertEqual(self.fuzz_data.processorDirectory, 'default')
        self.assertEqual(self.fuzz_data.failureThreshold, 3)
        self.assertEqual(self.fuzz_data.failureTimeout, 5)
        self.assertEqual(self.fuzz_data.receiveTimeout, 1.0)
        self.assertEqual(self.fuzz_data.shouldPerformTestRun, 1)
        self.assertEqual(self.fuzz_data.proto, 'tcp')
        self.assertEqual(self.fuzz_data.port, 9999)
        self.assertEqual(self.fuzz_data.sourcePort, -1)
        self.assertEqual(self.fuzz_data.sourceIP, '0.0.0.0')
        # --- checking message contents
        self.assertEqual(self.fuzz_data.message_collection.messages[0].direction, "inbound")
        self.assertEqual(self.fuzz_data.message_collection.messages[0].subcomponents[0].message, b'RFB 003.008\n')

        self.assertEqual(self.fuzz_data.message_collection.messages[1].direction, "outbound")
        self.assertEqual(self.fuzz_data.message_collection.messages[1].subcomponents[0].message, b'RFB 003.008\n')
        self.assertTrue(self.fuzz_data.message_collection.messages[1].isFuzzed)

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

    def test_readFromFDNonDefault(self):
        file = open('./tests/units/input_files/test_FuzzDataReadNonDefault.fuzzer', 'r')
        self.fuzz_data.readFromFD(file)
        file.close()
        self.assertEqual(self.fuzz_data.message_collection.messages[0].subcomponents[0].message, bytearray(b'RFB 003.008\n'))
        self.assertEqual(self.fuzz_data.processorDirectory, './not/default')
        self.assertEqual(self.fuzz_data.failureThreshold, 20)
        self.assertEqual(self.fuzz_data.failureTimeout, 10)
        self.assertEqual(self.fuzz_data.receiveTimeout, 3.5)
        # --- checking message contents
        self.assertEqual(self.fuzz_data.message_collection.messages[0].direction, "inbound")
        self.assertEqual(self.fuzz_data.message_collection.messages[0].subcomponents[0].message, b'RFB 003.008\n')

        self.assertEqual(self.fuzz_data.message_collection.messages[1].direction, "outbound")
        self.assertEqual(self.fuzz_data.message_collection.messages[1].subcomponents[0].message, b'RFB 003.008\n')
        self.assertTrue(self.fuzz_data.message_collection.messages[1].isFuzzed)

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


    
    def test__getComments(self):
        # nonexistant section
        commentSectionName = 'foo'
        self.assertEqual(self.fuzz_data._getComments(commentSectionName), '')
        # existent section
        commentSectionName = 'processor_dir'
        comments = 'test'
        self.fuzz_data.comments[commentSectionName] = comments
        self.assertEqual(self.fuzz_data._getComments(commentSectionName), comments)
        


    def test_setMessagesToFuzzFromString(self):
        file = open('./tests/units/input_files/test_FuzzDataRead.fuzzer', 'r')
        self.fuzz_data.readFromFD(file)
        file.close()
        messagesToFuzzStr = '1,3-4'
        self.fuzz_data.setMessagesToFuzzFromString(messagesToFuzzStr)
        self.assertIn(1, self.fuzz_data.messagesToFuzz)
        self.assertIn(3, self.fuzz_data.messagesToFuzz)
        self.assertIn(4, self.fuzz_data.messagesToFuzz)
        messagesToFuzzStr = '2-3,1'
        self.fuzz_data.setMessagesToFuzzFromString(messagesToFuzzStr)
        self.assertIn(2, self.fuzz_data.messagesToFuzz)
        self.assertIn(3, self.fuzz_data.messagesToFuzz)
        self.assertIn(1, self.fuzz_data.messagesToFuzz)
        self.assertNotIn(4, self.fuzz_data.messagesToFuzz)
        messagesToFuzzStr = '0'
        self.fuzz_data.setMessagesToFuzzFromString(messagesToFuzzStr)
        self.assertIn(0, self.fuzz_data.messagesToFuzz)

    def test_writeToFile(self):
        file = open('./tests/units/input_files/test_FuzzDataRead.fuzzer', 'r')
        self.fuzz_data.readFromFD(file)
        file.close()
        filePath = './tests/units/input_files/test_writeToFile.fuzzer'
        # no dupes, can create file
        self.fuzz_data.writeToFile(filePath)
        self.assertTrue(os.path.exists(filePath))
        #  existant files
        self.fuzz_data.writeToFile(filePath)
        newFilePath = filePath + '-1'
        self.assertTrue(os.path.exists((newFilePath)))
        
        os.remove(filePath)
        os.remove((newFilePath))

    def test_writeToFD(self):
        infile = open('./tests/units/input_files/test_FuzzDataRead.fuzzer', 'r')
        self.fuzz_data.readFromFD(infile)
        infile.close()
        outfile = open('./tests/units/input_files/test_FuzzDataWrite.fuzzer', 'w') 
        self.fuzz_data.writeToFD(outfile, defaultComments=True)
        outfile.close()

        # now open both and compare contents
        infile = open('./tests/units/input_files/test_FuzzDataRead.fuzzer', 'r')
        outfile = open('./tests/units/input_files/test_FuzzDataWrite.fuzzer', 'r') 
        inlines = infile.readlines()
        outlines = outfile.readlines()
        self.assertEqual(len(inlines), len(outlines))
        for i in range(len(inlines)):
            inline = inlines[i]
            outline = outlines[i]
            self.assertEqual(inline, outline)
        infile.close()
        outfile.close()
        os.remove('./tests/units/input_files/test_FuzzDataWrite.fuzzer')
