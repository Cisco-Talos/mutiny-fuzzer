import unittest
import backend.fuzzer_types 

class TestfuzzerTypes(unittest.TestCase):

    def setUp(self):
        self.MessageSubComponent = MessageSubComponent('message', False)

    def tearDown(self):
        self.MessageSubComponent = None

    # MessageSubComponent Class ------
    def test_subComponentInit(self):
        self.assertEqual(self.MessageSubComponent.message, 'message')
        self.assertEqual(self.MessageSubComponent.isFuzzed,False)

        self.MessageSubComponent = MessageSubComponent('', True)
        self.assertEqual(self.MessageSubComponent.message, '')
        self.assertEqual(self.MessageSubComponent.isFuzzed,True)


    def test_setAlteredByteArray(self):
        ba = bytearray([0,1,2])
        self.assertEqual(self.MessageSubComponent.setAlteredByteArray(ba), ba)

        ba = bytearray()
        self.assertEqual(self.MessageSubComponent.setAlteredByteArray(ba), ba)

    def test_getAlteredByteArray(self):
        self.assertEqual(self.MessageSubComponent.getAlteredByteArray(),self.MessageSubComponent._altered)

    def test_getOriginalByteArray(self):
        self.assertEqual(self.MessageSubComponent.getOriginalByteArray(),self.message)

    # Message Class ----------------
    def test_MessageInit(self):
        pass

    def test_getOriginalSubComponents(self):
        pass

    def test_getAlteredSubComponents(self):

    def test_getOriginalMessage(self):
        pass

    def test_resetAlteredMessage(self):
        pass

    def test_setMessageFrom(self):
        pass

    def test_appendMessageFrom(self):
        pass

    def test_isOutbound(self):
        pass
    
    def test___eq__(self):
        pass

    def test_serializeByteArray(self):
        pass

    def test_deserializeByteArray(self):
        pass

    def test_getAlteredSerialized(self):
        pass

    def test_getSerialized(self):
        pass

    def test__extractMessageComponents(self):
        pass

    def test_setFromSerialized(self):
        pass

    def test_appendFromSerialized(self):
        pass

    # MessageCollection Class ----
    def test_MessageCollectioninit(self):
        pass

    def test_addMessage(self):
        pass

    def test_doClientMessagesMatch(self):
        pass

    # Logger Class ------------------
    def test_loggerInit(self):
        pass

    def test_setReceivedMessageData(self):
        pass

    def test_setHighestMessageNumber(self):
        pass

    def test_outputLasLog(self):
        pass

    def test_outputLog(self):
        pass

    def test__outputLog(self):
        pass

    def test_resetForNewRun(self):
        pass

