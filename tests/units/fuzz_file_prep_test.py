import unittest
import os
from unittest.mock import patch
import backend.fuzz_file_prep as prep
from backend.fuzzer_data import FuzzerData
from backend.fuzzer_types import Message



class TestFuzzFilePrep(unittest.TestCase):
    def setUp(self):
        prep.INPUT_FILE_PATH = '../trace.pcap'
        prep.FUZZER_DATA = FuzzerData()
        prep.FUZZER_DATA.processorDirectory = 'default'
        prep.FORCE_DEFAULTS = True

    def tearDown(self):
        prep.LAST_MESSAGE_DIRECTION = None

        if os.path.exists('tests/units/input_files/test0-0.fuzzer'):
            os.remove('tests/units/input_files/test0-0.fuzzer')
        if os.path.exists('tests/units/input_files/test0-0,2-4.fuzzer'):
            os.remove('tests/units/input_files/test0-0,2-4.fuzzer')

    def test_processInputFileNonExistent(self):
        # nonexistent file
        prep.INPUT_FILE_PATH = 'non-existent.file'
        with self.assertRaises(SystemExit) as contextManager:
            prep.processInputFile()
            self.assertEqual(contextManager.exception.code, 3)

    def test_processInputfileInvalidType(self):
        # non-pcap/cArray file
        prep.INPUT_FILE_PATH = 'input_files/test.nonvalid'
        with self.assertRaises(SystemExit) as contextManager: 
            prep.processInputFile()
            self.assertEqual(contextManager.exception.code, 3)


    def test_processPcap(self):
        # pcap
        prep.INPUT_FILE_PATH = './tests/units/input_files/test0.pcap'
        with open(prep.INPUT_FILE_PATH, 'r') as inputFile:
            prep.processPcap(inputFile)
        inputFile.close()

        self.assertNotEqual(len(prep.FUZZER_DATA.messageCollection.messages), 0)
        self.assertEqual(prep.DEFAULT_PORT, 9999)
        self.assertEqual(prep.LAST_MESSAGE_DIRECTION, "inbound")
        # --- checking message contents
        self.assertEqual(prep.FUZZER_DATA.messageCollection.messages[0].direction, "outbound")
        self.assertEqual(prep.FUZZER_DATA.messageCollection.messages[0].subcomponents[0].message, b'1234.4321')

        self.assertEqual(prep.FUZZER_DATA.messageCollection.messages[1].direction, "inbound")
        self.assertEqual(prep.FUZZER_DATA.messageCollection.messages[1].subcomponents[0].message, b'[^.^] Launching 4321 testcases for pid 4321')

    def test_processPcapNonDefault(self):
        prep.FORCE_DEFAULTS = False
        prep.INPUT_FILE_PATH = './tests/units/input_files/test0.pcap'
        with open(prep.INPUT_FILE_PATH, 'r') as inputFile:
            prep.processPcap(inputFile, testPort=9999,combinePackets=True)
        inputFile.close()

        self.assertEqual(prep.DEFAULT_PORT, 9999)
        self.assertEqual(prep.LAST_MESSAGE_DIRECTION, "inbound")
        # --- checking message contents
        self.assertEqual(prep.FUZZER_DATA.messageCollection.messages[0].direction, "outbound")
        self.assertEqual(prep.FUZZER_DATA.messageCollection.messages[0].subcomponents[0].message, b'1234.4321')

        self.assertEqual(prep.FUZZER_DATA.messageCollection.messages[1].direction, "inbound")
        self.assertEqual(prep.FUZZER_DATA.messageCollection.messages[1].subcomponents[0].message, b'[^.^] Launching 4321 testcases for pid 4321')

    def test_processPcapNonDefaultSamePorts(self):
        # --- TODO: create a pcap with hosts connecting via same port so testMac can be used to verify stability
        prep.FORCE_DEFAULTS = False
        prep.INPUT_FILE_PATH = './tests/units/input_files/test0.pcap' # FIXME: change to pcap with same ports for both client/server
        with open(prep.INPUT_FILE_PATH, 'r') as inputFile:
            prep.processPcap(inputFile, testPort=55161,combinePackets=True)
        inputFile.close()
        pass
    
    def test_processPcapNonDefaultDontCombine(self):
        prep.FORCE_DEFAULTS = False
        prep.INPUT_FILE_PATH = './tests/units/input_files/test0.pcap' # FIXME: change to pcap with multiple consecutive inbound/outbounds
        with open(prep.INPUT_FILE_PATH, 'r') as inputFile:
            prep.processPcap(inputFile, testPort=55161,combinePackets=False)
        inputFile.close()


    def test_processCArray(self):
        # cArray
        prep.INPUT_FILE_PATH = './tests/units/input_files/test0.cra'
        with open(prep.INPUT_FILE_PATH, 'r') as inputFile:
            prep.processCArray(inputFile)
        inputFile.close()

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

    def test_processCArrayNonDefault(self):
        prep.INPUT_FILE_PATH = './tests/units/input_files/test0.cra' # FIXME: change this to a cArray with multiple consecutive outbound/inbounds
        with open(prep.INPUT_FILE_PATH, 'r') as inputFile:
            prep.processCArray(inputFile, combinePackets = False)
        inputFile.close()
        # TODO: complete with asserts based on new cArray

    def test_genFuzzConfig(self):
        prep.genFuzzConfig()
        self.assertEqual(prep.FUZZER_DATA.failureThreshold, 3)
        self.assertEqual(prep.FUZZER_DATA.failureTimeout, 5)
        self.assertEqual(prep.FUZZER_DATA.proto, "tcp")


    def test_genFuzzConfigNonDefault(self):
        # with FORCE_DEFAULTS = false
        prep.FORCE_DEFAULTS = False
        prep.genFuzzConfig(failureThreshold=4, failureTimeout=4, proto='udp',port=30)
        self.assertEqual(prep.FUZZER_DATA.failureThreshold, 4)
        self.assertEqual(prep.FUZZER_DATA.failureTimeout, 4)
        self.assertEqual(prep.FUZZER_DATA.proto, "udp")
        self.assertEqual(prep.FUZZER_DATA.port, 30)

    def test_genFuzzConfigNonDefaultRaw(self):
        # with FORCE_DEFAULTS = false
        prep.FORCE_DEFAULTS = False
        prep.genFuzzConfig(failureThreshold=4, failureTimeout=4, proto='raw',port=30)
        self.assertEqual(prep.FUZZER_DATA.failureThreshold, 4)
        self.assertEqual(prep.FUZZER_DATA.failureTimeout, 4)
        self.assertEqual(prep.FUZZER_DATA.proto, "raw")
        self.assertEqual(prep.FUZZER_DATA.port, 30)


    def test_getNextMessage(self):
        prep.FUZZER_DATA = FuzzerData()
        prep.INPUT_FILE_PATH = './tests/units/input_files/test0.cra'
        with open(prep.INPUT_FILE_PATH, 'r') as inputFile:
            prep.processCArray(inputFile)
        inputFile.close()
        self.assertEqual(prep.getNextMessage(0, Message.Direction.Inbound), 0)
        self.assertEqual(prep.getNextMessage(0, Message.Direction.Outbound), 1)
        self.assertEqual(prep.getNextMessage(3, Message.Direction.Inbound), 4)
        self.assertEqual(prep.getNextMessage(3, Message.Direction.Outbound), 3)
        self.assertEqual(prep.getNextMessage(6, Message.Direction.Outbound), None)


    def test_promptAndOutput(self):
        prep.FUZZER_DATA = FuzzerData()
        prep.INPUT_FILE_PATH = './tests/units/input_files/test0.pcap'
        with open(prep.INPUT_FILE_PATH, 'r') as inputFile:
            prep.processPcap(inputFile)
        inputFile.close()
        # with Defaults
        prep.genFuzzConfig()
        # FUZZER_DATA has been generated, now we can run prompt and output 
        outputMessageNum = prep.getNextMessage(0,Message.Direction.Outbound)
        prep.promptAndOutput(outputMessageNum, autoGenerateAllClient=True)
        with open('tests/units/input_files/test0-0.fuzzer', 'r') as file:
            lines = file.readlines()
            for i in range(0, len(lines)):
                line = lines[i]
                if i == 4:
                    self.assertIn('processor_dir default', line)
                if i == 6:
                    self.assertIn('failureThreshold 3', line)
                if i == 8:
                    self.assertIn('failureTimeout 5', line)
                if i == 10:
                    self.assertIn('receiveTimeout 1.0', line)
                if i == 12:
                    self.assertIn('shouldPerformTestRun 1', line)
                if i == 14:
                    self.assertIn('proto tcp', line)
                if i == 16:
                    self.assertIn('port 9999', line)
                if i == 18:
                    self.assertIn('sourcePort -1', line)
                if i == 20:
                    self.assertIn('sourceIP 0.0.0.0', line)
                if i == 24:
                    self.assertIn('outbound fuzz \'1234.4321\'', line)
                if i == 25:
                    self.assertIn('inbound \'[^.^] Launching 4321 testcases for pid 4321\'', line)



    def test_promptAndOutputNonDefault(self):
        prep.FUZZER_DATA = FuzzerData()
        prep.INPUT_FILE_PATH = './tests/units/input_files/test0.cra'
        with open(prep.INPUT_FILE_PATH, 'r') as inputFile:
            prep.processCArray(inputFile)
        inputFile.close()
        # with Defaults
        prep.genFuzzConfig()
        prep.FORCE_DEFAULTS = False
        # FUZZER_DATA has been generated, now we can run prompt and output 
        outputMessageNum = prep.getNextMessage(0,Message.Direction.Outbound)
        prep.promptAndOutput(outputMessageNum, finalMsgNum=6, msgsToFuzz='0,2-4')
        with open('tests/units/input_files/test0-0,2-4.fuzzer', 'r') as file:
            lines = file.readlines()
            print(''.join(lines))
            for i in range(0, len(lines)):
                line = lines[i]
                if i == 4:
                    self.assertIn('processor_dir default', line)
                if i == 6:
                    self.assertIn('failureThreshold 3', line)
                if i == 8:
                    self.assertIn('failureTimeout 5', line)
                if i == 10:
                    self.assertIn('receiveTimeout 1.0', line)
                if i == 12:
                    self.assertIn('shouldPerformTestRun 1', line)
                if i == 14:
                    self.assertIn('proto tcp', line)
                if i == 16:
                    self.assertIn('port 9999', line)
                if i == 18:
                    self.assertIn('sourcePort -1', line)
                if i == 20:
                    self.assertIn('sourceIP 0.0.0.0', line)
                if i == 24:
                    self.assertIn('outbound fuzz \'1234.4321\'', line)
                if i == 25:
                    self.assertIn('inbound \'[^.^] Launching 4321 testcases for pid 4321\'', line)

