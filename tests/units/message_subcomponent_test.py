import unittest
import backend.fuzzer_types 

class TestMessageSubComponent(unittest.TestCase):
    def setUp(self):
        self.MessageSubComponent = MessageSubComponent('message', False)
    def tearDown(self):
        self.MessageSubComponent = None


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
