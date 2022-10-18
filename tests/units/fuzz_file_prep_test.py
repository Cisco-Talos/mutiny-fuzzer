import unittest
from unittest.mock import patch
import backend.fuzz_file_prep as prep
from backend.fuzzer_data import FuzzerData



class TestFuzzFilePrep(unittest.TestCase):
    def setUp(self):
        prep.INPUT_FILE_PATH = '../trace.pcap'
        prep.FUZZER_DATA = FuzzerData()
        prep.FUZZER_DATA.processorDirectory = 'default'
        prep.FORCE_DEFAULTS = True


    # TODO: annotate with expected fail
    '''
    def test_processInputFileExpectedFails(self):
        # nonexistent file
        prep.INPUT_FILE_PATH = 'non-existent.file'
        prep.processInputFile()
        self.assertEqual(len(prep.FUZZER_DATA.messageCollection.messages), 0)
        
        # non-pcap/cArray file
        prep.INPUT_FILE_PATH = 'input_files/test.nonvalid'
        prep.processInputFile()
        self.assertEqual(len(prep.FUZZER_DATA.messageCollection.messages), 0)

    '''


    @patch('backend.menu_functions.prompt', return_value=True)
    def test_processPcap(self, mock):
        # pcap
        prep.INPUT_FILE_PATH = './tests/units/input_files/test0.pcap'
        prep.processInputFile()

        self.assertNotEqual(len(prep.FUZZER_DATA.messageCollection.messages), 0)
        self.assertEqual(prep.DEFAULT_PORT, 9999)
        self.assertEqual(prep.LAST_MESSAGE_DIRECTION, "inbound")
        # --- checking message contents
        self.assertEqual(prep.FUZZER_DATA.messageCollection.messages[0].direction, "outbound")
        self.assertEqual(prep.FUZZER_DATA.messageCollection.messages[0].subcomponents[0].message, b'1234.4321')

        self.assertEqual(prep.FUZZER_DATA.messageCollection.messages[1].direction, "inbound")
        self.assertEqual(prep.FUZZER_DATA.messageCollection.messages[1].subcomponents[0].message, b'[^.^] Launching 4321 testcases for pid 4321')
        # --- TODO: with FORCE_DEFAULTS=false




    @patch('backend.menu_functions.prompt', return_value=True)
    def test_processCArray(self, mock):
        # cArray
        prep.INPUT_FILE_PATH = './tests/units/input_files/test0.cra'
        prep.processInputFile()

        self.assertNotEqual(len(prep.FUZZER_DATA.messageCollection.messages), 0)
        self.assertEqual(prep.LAST_MESSAGE_DIRECTION, "inbound")

        # --- checking message contents
        self.assertEqual(prep.FUZZER_DATA.messageCollection.messages[0].direction, "inbound")
        self.assertEqual(prep.FUZZER_DATA.messageCollection.messages[0].subcomponents[0].message, b'RFB 003.008\n')

        self.assertEqual(prep.FUZZER_DATA.messageCollection.messages[1].direction, "outbound")
        self.assertEqual(prep.FUZZER_DATA.messageCollection.messages[1].subcomponents[0].message, b'RFB 003.008\n')

        self.assertEqual(prep.FUZZER_DATA.messageCollection.messages[2].direction, "inbound")
        self.assertEqual(prep.FUZZER_DATA.messageCollection.messages[2].subcomponents[0].message, b'\x02\x02\x10')

        self.assertEqual(prep.FUZZER_DATA.messageCollection.messages[3].direction, "outbound")
        self.assertEqual(prep.FUZZER_DATA.messageCollection.messages[3].subcomponents[0].message, b'\x02')

        self.assertEqual(prep.FUZZER_DATA.messageCollection.messages[4].direction, "inbound")
        self.assertEqual(prep.FUZZER_DATA.messageCollection.messages[4].subcomponents[0].message, b'\xaa\xc3\xe3\x95\xd3|\xd7\xf9\xfd\x84\xe7\xf5R\x94\x93\x1c')
         
        self.assertEqual(prep.FUZZER_DATA.messageCollection.messages[5].direction, "outbound")
        self.assertEqual(prep.FUZZER_DATA.messageCollection.messages[5].subcomponents[0].message, b'2\xd1\xa0I\x93q\x03\x11e$\x83\x94\xc6t\x8e\x08')

        self.assertEqual(prep.FUZZER_DATA.messageCollection.messages[6].direction, "inbound")
        self.assertEqual(prep.FUZZER_DATA.messageCollection.messages[6].subcomponents[0].message, b'\x00\x00\x00\x00')

    @patch('backend.menu_functions.promptInt', return_value=1)
    def test_genFuzzConfig(self, mock):
        # --- TODO: with FORCE_DEFAULTS=false
        pass

    def test_writeFuzzerFile(self):
        # --- TODO: with FORCE_DEFAULTS=false
        pass

    def test_getNextMessage(self):
        # --- TODO: with FORCE_DEFAULTS=false
        pass

    def test_promptAndOutput(self):
        # --- TODO: with FORCE_DEFAULTS=false
        pass

