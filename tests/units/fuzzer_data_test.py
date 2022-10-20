import unittest
from backend.fuzzer_data import FuzzerData

class FuzzerDataTestCase(unittest.TestCase):

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
        pass

    def test__appendComments(self):
        pass

    def test_readFromFD(self):
        pass
    
    def test__getComments(self):
        pass

    def test_setMessagesToFuzzFromString(self):
        pass

    def test_writeToFile(self):
        pass

    def test_writeToFD(self):
        pass
