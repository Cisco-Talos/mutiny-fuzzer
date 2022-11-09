import unittest
from backend.fuzzer_types import MessageSubComponent

class Testmessage_sub_component(unittest.TestCase):
    def setUp(self):
        self.message_sub_momponent = MessageSubComponent('message', False)

    def tearDown(self):
        self.message_sub_component = None


    def test_subComponentInit(self):
        self.assertEqual(self.message_sub_component.message, 'message')
        self.assertEqual(self.message_sub_component.is_fuzzed,False)

        self.message_sub_component = message_sub_component('', True)
        self.assertEqual(self.message_sub_component.message, '')
        self.assertEqual(self.message_sub_component.is_fuzzed,True)


    def test_set_altered_byte_array(self):
        ba = bytearray([0,1,2])
        self.message_sub_component.set_altered_byte_array(ba)
        self.assertEqual(self.message_sub_component._altered, ba)
        ba = bytearray()


    def test_get_altered_byte_array(self):
        self.assertEqual(self.message_sub_component.get_altered_byte_array(),self.message_sub_component._altered)


    def test_get_original_byte_array(self):
        self.assertEqual(self.message_sub_component.get_original_byte_array(),self.message_sub_component.message)
