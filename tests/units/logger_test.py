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
        
    def test_setReceivedMessageData(self):
        idx = 2
        data = b'somedata'
        self.logger.setReceivedMessageData(idx,data)
        self.assertEqual(self.logger.receivedMessageData[idx], data)


    def test_setHighestMessageNumber(self):
        self.logger.setHighestMessageNumber(43)
        self.assertEqual(self.logger._highestMessageNumber, 43)

    def test__outputLog(self):
        runNum = 0
        errorMessage =  'this is an error msg'
        receivedMessageData = {0: bytearray('message1', 'utf-8'), 1: bytearray('message2', 'utf-8'), 2: bytearray('crash', 'utf-8')}
        highestMessageNumber = 2
        # populate messageCollection
        messageCollection = MessageCollection()
        m1 = Message()
        m1.setMessageFrom(Message.Format.Raw, bytearray('message1', 'utf-8'), False)
        m1.direction = 'inbound'
        m2 = Message()
        m2.appendMessageFrom(Message.Format.Raw, bytearray('message2', 'utf-8'), True)
        m2.direction = 'outbound'
        m3 = Message()
        m3.appendMessageFrom(Message.Format.Raw, bytearray('message3', 'utf-8'), False)
        m3.direction = 'inbound'
        messageCollection.messages = [m1,m2,m3]

        # call _outputLog
        self.logger._outputLog(runNum, messageCollection, errorMessage, receivedMessageData, highestMessageNumber)

        # check contents of written log file
        with open(os.path.join(self.logger._folderPath,str(runNum)), 'r') as outputFile:
            lines = outputFile.readlines()

            # record data that should be found in the output file
            foundSeed = False
            foundErrorMsg = False
            foundFailedConn = False
            foundFirstPacket = False
            foundSecondPacket = False
            foundSecondFuzz = False
            foundThirdPacket = False
            foundFirstExpected = False
            foundSecondExpected = False
            foundThirdUnexpected = False
            foundLastMsg = False

            # go through lines to look for data 
            for i in range(0,len(lines)):
                line = lines[i]
                if i == 0 and 'seed 0' in line:
                    foundSeed = True
                if i == 1 and 'this is an error msg' in line:
                    foundErrorMsg = True
                if i == 2 and 'Failed to connect on this run.' in line:
                    foundFailedConn = True
                if i == 4 and ('0: '+ m1.getSerialized()) in line:
                    foundFirstPacket = True
                if i == 5 and 'Received expected data' in line:
                    foundFirstExpected = True
                if i == 7 and ('1: ' + m2.getSerialized()) in line:
                    foundSecondPacket = True
                if i == 8 and m2.getAlteredSerialized() in line:
                    foundSecondFuzz = True
                if i == 10 and 'Received expected data' in line:
                    foundSecondExpected = True
                if i == 12 and ('2: ' + m3.getSerialized()) in line:
                    foundThirdPacket = True
                if i == 13 and ('2: ' + Message.serializeByteArray(receivedMessageData[2])) in line:
                    foundThirdUnexpected = True
                if i == 14 and ('This is the last message received') in line:
                    foundLastMsg = True


            
            # make sure we found them all
            self.assertTrue(foundSeed)
            self.assertTrue(foundErrorMsg)
            self.assertTrue(foundFailedConn)
            self.assertTrue(foundFirstPacket)
            self.assertTrue(foundFirstExpected)
            self.assertTrue(foundSecondPacket)
            self.assertTrue(foundSecondFuzz)
            self.assertTrue(foundSecondExpected)
            self.assertTrue(foundThirdPacket)
            self.assertTrue(foundThirdUnexpected)
            self.assertTrue(foundLastMsg)

        # test again with 
        # runNum != 0 and highestMessageNumber != -1 
        runNum = 1 

    def test_resetForNewRun(self):
        # valid attributes
        self.logger.receivedMessageData = {1 : b'somedata'}
        self.logger._highestMessageNumber = 10
        self.logger.receivedMessageData[2] = b'otherdata'
        self.logger.resetForNewRun()
        # check that last run data is intact
        self.assertEqual(self.logger._lastReceivedMessageData[1], b'somedata' )
        self.assertEqual(self.logger._lastHighestMessageNumber, 10)
        # check that dict was reset
        self.assertNotIn(b'otherdata', self.logger.receivedMessageData)
        # check that highest message num was reset
        self.assertEqual(self.logger._highestMessageNumber, -1)

    def test_resetForNewRunInvalidAttr(self):
        # setUp() makes the call for us through Logger.__init__, just need to check vals
        self.assertEqual(self.logger._lastReceivedMessageData, {})
        self.assertEqual(self.logger._lastHighestMessageNumber, -1)
        self.assertEqual(self.logger.receivedMessageData, {})
        self.assertEqual(self.logger._highestMessageNumber, -1)

