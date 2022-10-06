import unittest
import backend.fuzz_file_prep as prep
from backend.fuzzer_data import FuzzerData



class TestFuzzFilePrep(unittest.TestCase):
    def setUp(self):
        prep.INPUT_FILE_PATH = '../trace.pcap'
        prep.FORCE_DEFAULTS = False
        prep.FUZZER_DATA = FuzzerData()
        prep.FUZZER_DATA.processorDirectory = 'default'


        # TODO: annotate with expected fail
    def test_processInputFileExpectedFails(self):
        # nonexistent file
        prep.INPUT_FILE_PATH = 'non-existent.file'
        prep.processInputFile()
        self.assertEqual(len(prep.FUZZER_DATA.messageCollection.messages), 0)
        
        # non-pcap/cArray file
        prep.INPUT_FILE_PATH = 'input_files/test.nonvalid'
        prep.processInputFile()
        self.assertEqual(len(prep.FUZZER_DATA.messageCollection.messages), 0)

    def test_processInputFile(self):

        # pcap
        prep.INPUT_FILE_PATH = './tests/units/input_files/test.pcap'
        prep.processInputFile()
        self.assertNotEqual(len(prep.FUZZER_DATA.messageCollection.messages), 0)

        # cArray
        prep.INPUT_FILE_PATH = './test/units/input_files/test.cra'
        prep.processInputFile()
        self.assertNotEqual(len(prep.FUZZER_DATA.messageCollection.messages), 0)

    def test_processPcap(self):
        pass

    def test_processCArray(self):
        pass

    def test_genFuzzConfig(self):
        pass

    def test_writeFuzzerFile(self):
        pass

    def test_getNextMessage(self):
        pass

    def test_promptAndOutput(self):
        pass


