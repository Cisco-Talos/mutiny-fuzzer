import unittest
from backend.fuzzer_types import MessageSubComponent

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
        self.MessageSubComponent.setAlteredByteArray(ba)
        self.assertEqual(self.MessageSubComponent._altered, ba)

        ba = bytearray()


    def test_getAlteredByteArray(self):
        self.assertEqual(self.MessageSubComponent.getAlteredByteArray(),self.MessageSubComponent._altered)


    def test_getOriginalByteArray(self):
        self.assertEqual(self.MessageSubComponent.getOriginalByteArray(),self.MessageSubComponent.message)
