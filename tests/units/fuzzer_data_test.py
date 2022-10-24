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
        pass

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
        fileno = file.fileno()
        self.fuzzdata.readFromFD(file)
        file.close()
        self.assertEqual(self.fuzzdata.messageCollection.messages[0].subcomponents[0].message, bytearray(b'RFB 003.008\n'))
        self.assertEqual(self.fuzzdata.processorDirectory, 'default')
        self.assertEqual(self.fuzzdata.failureThreshold, 3)
        self.assertEqual(self.fuzzdata.failureTimeout, 3)
        self.assertEqual(self.fuzzdata.receiveTimeout, 3)



    
    def test__getComments(self):
        pass

    def test_setMessagesToFuzzFromString(self):
        pass

    def test_writeToFile(self):
        pass

    def test_writeToFD(self):
        pass
