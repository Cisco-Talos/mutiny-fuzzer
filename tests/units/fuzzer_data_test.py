import unittest
from backend.fuzzer_data import FuzzerData

class FuzzerDataTests(unittest.TestCase):

    def setUp(self):
        self.fuzzdata = FuzzerData()

    def tearDown(self):
        pass

    def test_init(self):
        self.assertIsNotNone(self.fuzzdata.messageCollection)
        self.assertEqual(self.fuzzdata.processorDirectory, 'default')
        self.assertEqual(self.fuzzdata.failureThreshold, 3)
        self.assertEqual(self.fuzzdata.proto, 'tcp')
        self.assertEqual(self.fuzzdata.port, 0)
        self.assertEqual(self.fuzzdata.sourcePort, -1)
        self.assertEqual(self.fuzzdata.sourceIP, '0.0.0.0')
        self.assertEqual(self.fuzzdata.shouldPerformTestRun, True)
        self.assertEqual(self.fuzzdata.receiveTimeout, 1.0)
        self.assertEqual(self.fuzzdata.comments, {})
        self.assertEqual(self.fuzzdata._readComments, "")
        self.assertEqual(self.fuzzdata.messagesToFuzz, [])

    def test_readFromFile(self):
        filePath = './tests/units/input_files/test_FuzzDataRead.fuzzer'
        self.fuzzdata.readFromFile(filePath)
        self.assertEqual(self.fuzzdata.messageCollection.messages[0].subcomponents[0].message, bytearray(b'RFB 003.008\n'))
        self.assertEqual(self.fuzzdata.processorDirectory, 'default')
        self.assertEqual(self.fuzzdata.failureThreshold, 3)
        self.assertEqual(self.fuzzdata.failureTimeout, 5)
        self.assertEqual(self.fuzzdata.receiveTimeout, 1.0)
        self.assertEqual(self.fuzzdata.shouldPerformTestRun, 1)
        self.assertEqual(self.fuzzdata.proto, 'tcp')
        self.assertEqual(self.fuzzdata.port, 9999)
        self.assertEqual(self.fuzzdata.sourcePort, -1)
        self.assertEqual(self.fuzzdata.sourceIP, '0.0.0.0')
        # --- checking message contents
        self.assertEqual(self.fuzzdata.messageCollection.messages[0].direction, "inbound")
        self.assertEqual(self.fuzzdata.messageCollection.messages[0].subcomponents[0].message, b'RFB 003.008\n')

        self.assertEqual(self.fuzzdata.messageCollection.messages[1].direction, "outbound")
        self.assertEqual(self.fuzzdata.messageCollection.messages[1].subcomponents[0].message, b'RFB 003.008\n')
        self.assertTrue(self.fuzzdata.messageCollection.messages[1].isFuzzed)

        self.assertEqual(self.fuzzdata.messageCollection.messages[2].direction, "inbound")
        self.assertEqual(self.fuzzdata.messageCollection.messages[2].subcomponents[0].message, b'\x02\x02\x10')

        self.assertEqual(self.fuzzdata.messageCollection.messages[3].direction, "outbound")
        self.assertEqual(self.fuzzdata.messageCollection.messages[3].subcomponents[0].message, b'\x02')

        self.assertEqual(self.fuzzdata.messageCollection.messages[4].direction, "inbound")
        self.assertEqual(self.fuzzdata.messageCollection.messages[4].subcomponents[0].message, b'\xaa\xc3\xe3\x95\xd3|\xd7\xf9\xfd\x84\xe7\xf5R\x94\x93\x1c')
         
        self.assertEqual(self.fuzzdata.messageCollection.messages[5].direction, "outbound")
        self.assertEqual(self.fuzzdata.messageCollection.messages[5].subcomponents[0].message, b'2\xd1\xa0I\x93q\x03\x11e$\x83\x94\xc6t\x8e\x08')

        self.assertEqual(self.fuzzdata.messageCollection.messages[6].direction, "inbound")
        self.assertEqual(self.fuzzdata.messageCollection.messages[6].subcomponents[0].message, b'\x00\x00\x00\x00')


    def test__pushComments(self):
        commentSectionName = "processor_dir"
        comment = 'test'
        self.fuzzdata._readComments = comment
        self.fuzzdata._pushComments(commentSectionName)
        self.assertEqual(self.fuzzdata.comments[commentSectionName], comment)
        self.assertEqual(self.fuzzdata._readComments, '')

    def test_pushCommentsEmpty(self):
        # empty _readComments
        commentSectionName = "processor_dir"
        self.fuzzdata._pushComments(commentSectionName)
        self.assertEqual(self.fuzzdata.comments[commentSectionName], '')
        self.assertEqual(self.fuzzdata._readComments, '')

    def test__appendComments(self):
        commentSectionName = "processor_dir"
        comment = 'test'
        # key exists, appending to empty string
        self.fuzzdata._readComments = comment
        self.fuzzdata._pushComments(commentSectionName)
        self.fuzzdata._appendComments(commentSectionName)
        self.assertEqual(self.fuzzdata.comments[commentSectionName], comment)
        self.assertEqual(self.fuzzdata._readComments, '')
        # key exists, appending to non empty string
        self.fuzzdata._readComments = comment
        self.fuzzdata._appendComments(commentSectionName)
        self.assertEqual(self.fuzzdata.comments[commentSectionName], 'test' + comment)
        self.assertEqual(self.fuzzdata._readComments, '')

        # key does not exist
        commentSectionName = 'notasection'
        self.fuzzdata._readComments = comment
        self.fuzzdata._appendComments(commentSectionName)
        self.assertEqual(self.fuzzdata.comments[commentSectionName], comment)
        self.assertEqual(self.fuzzdata._readComments, '')

    def test_readFromFD(self):
        file = open('./tests/units/input_files/test_FuzzDataRead.fuzzer', 'r')
        self.fuzzdata.readFromFD(file)
        file.close()
        self.assertEqual(self.fuzzdata.messageCollection.messages[0].subcomponents[0].message, bytearray(b'RFB 003.008\n'))
        self.assertEqual(self.fuzzdata.processorDirectory, 'default')
        self.assertEqual(self.fuzzdata.failureThreshold, 3)
        self.assertEqual(self.fuzzdata.failureTimeout, 5)
        self.assertEqual(self.fuzzdata.receiveTimeout, 1.0)
        self.assertEqual(self.fuzzdata.shouldPerformTestRun, 1)
        self.assertEqual(self.fuzzdata.proto, 'tcp')
        self.assertEqual(self.fuzzdata.port, 9999)
        self.assertEqual(self.fuzzdata.sourcePort, -1)
        self.assertEqual(self.fuzzdata.sourceIP, '0.0.0.0')
        # --- checking message contents
        self.assertEqual(self.fuzzdata.messageCollection.messages[0].direction, "inbound")
        self.assertEqual(self.fuzzdata.messageCollection.messages[0].subcomponents[0].message, b'RFB 003.008\n')

        self.assertEqual(self.fuzzdata.messageCollection.messages[1].direction, "outbound")
        self.assertEqual(self.fuzzdata.messageCollection.messages[1].subcomponents[0].message, b'RFB 003.008\n')
        self.assertTrue(self.fuzzdata.messageCollection.messages[1].isFuzzed)

        self.assertEqual(self.fuzzdata.messageCollection.messages[2].direction, "inbound")
        self.assertEqual(self.fuzzdata.messageCollection.messages[2].subcomponents[0].message, b'\x02\x02\x10')

        self.assertEqual(self.fuzzdata.messageCollection.messages[3].direction, "outbound")
        self.assertEqual(self.fuzzdata.messageCollection.messages[3].subcomponents[0].message, b'\x02')

        self.assertEqual(self.fuzzdata.messageCollection.messages[4].direction, "inbound")
        self.assertEqual(self.fuzzdata.messageCollection.messages[4].subcomponents[0].message, b'\xaa\xc3\xe3\x95\xd3|\xd7\xf9\xfd\x84\xe7\xf5R\x94\x93\x1c')
         
        self.assertEqual(self.fuzzdata.messageCollection.messages[5].direction, "outbound")
        self.assertEqual(self.fuzzdata.messageCollection.messages[5].subcomponents[0].message, b'2\xd1\xa0I\x93q\x03\x11e$\x83\x94\xc6t\x8e\x08')

        self.assertEqual(self.fuzzdata.messageCollection.messages[6].direction, "inbound")
        self.assertEqual(self.fuzzdata.messageCollection.messages[6].subcomponents[0].message, b'\x00\x00\x00\x00')

    def test_readFromFDNonDefault(self):
        file = open('./tests/units/input_files/test_FuzzDataReadNonDefault.fuzzer', 'r')
        self.fuzzdata.readFromFD(file)
        file.close()
        self.assertEqual(self.fuzzdata.messageCollection.messages[0].subcomponents[0].message, bytearray(b'RFB 003.008\n'))
        self.assertEqual(self.fuzzdata.processorDirectory, './not/default')
        self.assertEqual(self.fuzzdata.failureThreshold, 20)
        self.assertEqual(self.fuzzdata.failureTimeout, 10)
        self.assertEqual(self.fuzzdata.receiveTimeout, 3.5)
        # --- checking message contents
        self.assertEqual(self.fuzzdata.messageCollection.messages[0].direction, "inbound")
        self.assertEqual(self.fuzzdata.messageCollection.messages[0].subcomponents[0].message, b'RFB 003.008\n')

        self.assertEqual(self.fuzzdata.messageCollection.messages[1].direction, "outbound")
        self.assertEqual(self.fuzzdata.messageCollection.messages[1].subcomponents[0].message, b'RFB 003.008\n')
        self.assertTrue(self.fuzzdata.messageCollection.messages[1].isFuzzed)

        self.assertEqual(self.fuzzdata.messageCollection.messages[2].direction, "inbound")
        self.assertEqual(self.fuzzdata.messageCollection.messages[2].subcomponents[0].message, b'\x02\x02\x10')

        self.assertEqual(self.fuzzdata.messageCollection.messages[3].direction, "outbound")
        self.assertEqual(self.fuzzdata.messageCollection.messages[3].subcomponents[0].message, b'\x02')

        self.assertEqual(self.fuzzdata.messageCollection.messages[4].direction, "inbound")
        self.assertEqual(self.fuzzdata.messageCollection.messages[4].subcomponents[0].message, b'\xaa\xc3\xe3\x95\xd3|\xd7\xf9\xfd\x84\xe7\xf5R\x94\x93\x1c')
         
        self.assertEqual(self.fuzzdata.messageCollection.messages[5].direction, "outbound")
        self.assertEqual(self.fuzzdata.messageCollection.messages[5].subcomponents[0].message, b'2\xd1\xa0I\x93q\x03\x11e$\x83\x94\xc6t\x8e\x08')

        self.assertEqual(self.fuzzdata.messageCollection.messages[6].direction, "inbound")
        self.assertEqual(self.fuzzdata.messageCollection.messages[6].subcomponents[0].message, b'\x00\x00\x00\x00')


    
    def test__getComments(self):
        # nonexistant section
        commentSectionName = 'foo'
        self.assertEqual(self.fuzzdata._getComments(commentSectionName), '')
        # existent section
        commentSectionName = 'processor_dir'
        comments = 'test'
        self.fuzzdata.comments[commentSectionName] = comments
        self.assertEqual(self.fuzzdata._getComments(commentSectionName), comments)
        


    def test_setMessagesToFuzzFromString(self):
        file = open('./tests/units/input_files/test_FuzzDataRead.fuzzer', 'r')
        self.fuzzdata.readFromFD(file)
        file.close()
        messagesToFuzzStr = '1,3-4'
        self.fuzzdata.setMessagesToFuzzFromString(messagesToFuzzStr)
        self.assertIn(1, self.fuzzdata.messagesToFuzz)
        self.assertIn(3, self.fuzzdata.messagesToFuzz)
        self.assertIn(4, self.fuzzdata.messagesToFuzz)
        messagesToFuzzStr = '2-3,1'
        self.fuzzdata.setMessagesToFuzzFromString(messagesToFuzzStr)
        self.assertIn(2, self.fuzzdata.messagesToFuzz)
        self.assertIn(3, self.fuzzdata.messagesToFuzz)
        self.assertIn(1, self.fuzzdata.messagesToFuzz)
        self.assertNotIn(4, self.fuzzdata.messagesToFuzz)
        messagesToFuzzStr = '0'
        self.fuzzdata.setMessagesToFuzzFromString(messagesToFuzzStr)
        self.assertIn(0, self.fuzzdata.messagesToFuzz)

    def test_writeToFile(self):
        file = open('./tests/units/input_files/test_FuzzDataRead.fuzzer', 'r')
        self.fuzzdata.readFromFD(file)
        file.close()
        pass

    def test_writeToFD(self):
        infile = open('./tests/units/input_files/test_FuzzDataRead.fuzzer', 'r')
        self.fuzzdata.readFromFD(infile)
        infile.close()
        outfile = open('./tests/units/input_files/test_FuzzDataWrite.fuzzer', 'w') 
        self.fuzzdata.writeToFD(outfile, defaultComments=True)
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
