import unittest
import ast
from backend.fuzzer_types import Message, MessageSubComponent

class TestMessage(unittest.TestCase):
    def setUp(self):
        self.message = Message()

    def tearDown(self):
        self.message = None


    def test_MessageInit(self):
        self.assertEqual(self.message.direction, -1)
        self.assertEqual(self.message.is_fuzzed, False)
        self.assertEqual(len(self.message.subcomponents), 0)


    def test_get_original_subcomponents(self):
        self.assertEqual(len(self.message.get_original_subcomponents()), 0)

        sub1 = MessageSubComponent(bytearray('foo','utf-8'), False)
        sub2 = MessageSubComponent(bytearray('bar','utf-8'), False)
        sub3 = MessageSubComponent(bytearray('poo','utf-8'), False)
        self.message.subcomponents.append(sub1)
        self.message.subcomponents.append(sub2)
        self.message.subcomponents.append(sub3)
        self.assertEqual(len(self.message.get_original_subcomponents()), 3)
        self.assertEqual(self.message.get_original_subcomponents()[2],bytearray('poo', 'utf-8'))

        self.message.subcomponents.pop()
        self.assertEqual(len(self.message.get_original_subcomponents()), 2)
        self.assertEqual(self.message.get_original_subcomponents()[-1], bytearray('bar', 'utf-8'))


    def test_get_altered_subcomponents(self):
        sub1 = MessageSubComponent(bytearray('foo','utf-8'), False)
        sub2 = MessageSubComponent(bytearray('bar','utf-8'), False)
        sub3 = MessageSubComponent(bytearray('poo','utf-8'), False)
        self.message.subcomponents.append(sub1)
        self.message.subcomponents.append(sub2)
        self.message.subcomponents.append(sub3)
        self.assertEqual(len(self.message.get_original_subcomponents()), 3)
        self.assertEqual(self.message.get_original_subcomponents()[2],sub3._altered)

        self.message.subcomponents.pop()
        self.assertEqual(len(self.message.get_original_subcomponents()), 2)
        self.assertEqual(self.message.get_original_subcomponents()[-1], sub2._altered)



    def test_get_original_message(self):
        sub1 = MessageSubComponent(bytearray('foo','utf-8'), False)
        sub2 = MessageSubComponent(bytearray('bar','utf-8'), False)
        sub3 = MessageSubComponent(bytearray('poo','utf-8'), False)
        self.message.subcomponents.append(sub1)
        self.message.subcomponents.append(sub2)
        self.message.subcomponents.append(sub3)
        orig = b'foobarpoo'
        self.assertEqual(self.message.get_original_message(),orig)


    def test_get_altered_message(self):
        sub1 = MessageSubComponent(bytearray('foo','utf-8'), False)
        sub2 = MessageSubComponent(bytearray('bar','utf-8'), False)
        sub3 = MessageSubComponent(bytearray('poo','utf-8'), False)
        self.message.subcomponents.append(sub1)
        self.message.subcomponents.append(sub2)
        self.message.subcomponents.append(sub3)
        subs = [sub1,sub2,sub3]
        orig_alt = bytearray().join([sub._altered for sub in subs])
        self.assertEqual(self.message.get_altered_message(), orig_alt)
        

    def test_reset_altered_message(self):
        sub1 = MessageSubComponent(bytearray('foo','utf-8'), False)
        # change _altered message
        self.message.subcomponents.append(sub1)
        self.message.subcomponents[0].set_altered_byte_array(bytearray('notfoo','utf-8'))
        # reset altered message
        self.message.reset_altered_message()
        self.assertEqual(self.message.subcomponents[0].message, bytearray('foo', 'utf-8'))



    def test_set_message_from(self):
        is_fuzzed = False
        # commaSeperatedHex
        source_type = 0
        message = '01,02,20,2a'.replace(',','')
        message_bytes = bytearray.fromhex(message)
        self.message.set_message_from(source_type, message, is_fuzzed)
        self.assertEqual(self.message.subcomponents[0].message, message_bytes)

        # Ascii
        source_type = 1
        message = "'foo'"
        message_bytes = bytearray(ast.literal_eval(f'b{message}'))
        self.message.set_message_from(source_type, message, is_fuzzed)
        self.assertEqual(self.message.subcomponents[0].message, message_bytes)

        # Raw
        source_type = 2
        message = bytearray('foo', 'utf-8')
        self.message.set_message_from(source_type, message, is_fuzzed)
        self.assertEqual(self.message.subcomponents[0].message, message)

        # List
        source_type = 3
        message = [1,2,3]
        with self.assertRaises(RuntimeError, msg='Invalid source_type'):
            self.message.set_message_from(source_type, message, is_fuzzed)

        
        # is_fuzzed=True
        is_fuzzed = True
        # commaSeperatedHex
        source_type = 0
        message = '01,02,20,2a'.replace(',','')
        message_bytes = bytearray.fromhex(message)
        self.message.set_message_from(source_type, message, is_fuzzed)
        self.assertEqual(self.message.subcomponents[0].message, message_bytes)

        # Ascii
        source_type = 1
        message = "'foo'"
        message_bytes = bytearray(ast.literal_eval(f'b{message}'))
        self.message.set_message_from(source_type, message, is_fuzzed)
        self.assertEqual(self.message.subcomponents[0].message, message_bytes)

        # Raw
        source_type = 2
        message = bytearray('foo', 'utf-8')
        self.message.set_message_from(source_type, message, is_fuzzed)
        self.assertEqual(self.message.subcomponents[0].message, message)


    def test_append_message_from(self):
        is_fuzzed = False
        # commaSeperatedHex
        source_type = 0
        message = '01,02,20,2a'.replace(',','')
        message_bytes = bytearray.fromhex(message)
        self.message.append_message_from(source_type, message, is_fuzzed)
        self.assertEqual(self.message.subcomponents[0].message, message_bytes)
        # Ascii
        source_type = 1
        message = "'foo'"
        message_bytes = bytearray(ast.literal_eval(f'b{message}'))
        self.message.append_message_from(source_type, message, is_fuzzed)
        self.assertEqual(self.message.subcomponents[1].message, message_bytes)
        # Raw
        source_type = 2
        message = bytearray('foo', 'utf-8')
        self.message.append_message_from(source_type, message, is_fuzzed)
        self.assertEqual(self.message.subcomponents[2].message, message)

        # ---- is_fuzzed  = True
        is_fuzzed = True
        # commaSeperatedHex
        source_type = 0
        message = '01,02,20,2a'.replace(',','')
        message_bytes = bytearray.fromhex(message)
        self.message.append_message_from(source_type, message, is_fuzzed)
        self.assertEqual(self.message.subcomponents[3].message, message_bytes)
        self.assertTrue(self.message.is_fuzzed)
        # Ascii
        source_type = 1
        message = "'foo'"
        message_bytes = bytearray(ast.literal_eval(f'b{message}'))
        self.message.append_message_from(source_type, message, is_fuzzed)
        self.assertEqual(self.message.subcomponents[4].message, message_bytes)
        self.assertTrue(self.message.is_fuzzed)
        # Raw
        source_type = 2
        message = bytearray('foo', 'utf-8')
        self.message.append_message_from(source_type, message, is_fuzzed)
        self.assertEqual(self.message.subcomponents[5].message, message)
        self.assertTrue(self.message.is_fuzzed)

        # ----- create_new_subcomponent = False
        appended_message = message
        create_new_subcomponent = False
        # commaSeperatedHex
        source_type = 0
        message = '01,02,20,2a'.replace(',','')
        message_bytes = bytearray.fromhex(message)
        appended_message  += message_bytes
        self.message.append_message_from(source_type, message, is_fuzzed)
        self.assertEqual(self.message.subcomponents[5].message, appended_message)
        # Ascii
        source_type = 1
        message = "'foo'"
        message_bytes = bytearray(ast.literal_eval(f'b{message}'))
        appended_message += message_bytes
        self.message.append_message_from(source_type, message, is_fuzzed)
        self.assertEqual(self.message.subcomponents[5].message, appended_message)
        # Raw
        source_type = 2
        message = bytearray('foo', 'utf-8')
        appended_message += message
        self.message.append_message_from(source_type, message, is_fuzzed, create_new_subcomponent)
        self.assertEqual(self.message.subcomponents[5].message, appended_message)


    def test_is_outbound(self):
        self.message.direction =  "outbound"
        self.assertTrue(self.message.is_outbound())

        self.message.direction = "inbound"
        self.assertFalse(self.message.is_outbound())

        self.message.direction = "invalidDirection"
        self.assertFalse(self.message.is_outbound())
    

    def test___eq__(self):
        m1 = Message()
        m2 = Message()
        # --- equal message, varying direction
        m1.message = b'foo'
        m2.message = b'foo'
        m1.direction = "outbound"
        m2.direction = "outbound"
        self.assertTrue(m1 == m2)
        m1.direction = "inbound"
        m2.direction = "outbound"
        self.assertFalse(m1 == m2)
        m1.direction = "inbound"
        m2.direction = "inbound"
        self.assertTrue(m1 == m2)

        # --- unequal message
        m1.message = b'foo'
        m1.message = b'bar'
        m1.direction = "outbound"
        m2.direction = "outbound"
        self.assertFalse(m1 == m2)
        m1.direction = "inbound"
        m2.direction = "outbound"
        self.assertFalse(m1 == m2)
        m1.direction = "inbound"
        m2.direction = "inbound"
        self.assertFalse(m1 == m2)

    def test_get_altered_serialized_zero_subcomponents(self):
        message = Message()
        message.direction = Message.Direction.Outbound
        self.assertEqual(message.get_altered_serialized(), 'outbound ERROR: No data in message.\n')
        
    def test_get_altered_serialized_one_subcomponent(self):
        message = Message()
        message.direction = Message.Direction.Outbound
        data = bytearray('test', 'utf-8')
        message.set_message_from(Message.Format.Raw, data, False)
        expected_output = "outbound {}\n".format(message.serialize_byte_array(message.subcomponents[0].get_altered_byte_array()))
        self.assertEqual(message.get_altered_serialized(), expected_output)

    def test_get_altered_serialized_one_fuzzed_subcomponent(self):
        message = Message()
        message.direction = Message.Direction.Outbound
        data = bytearray('test', 'utf-8')
        message.set_message_from(Message.Format.Raw, data, True)
        expected_output = "fuzz outbound {}\n".format(message.serialize_byte_array(message.subcomponents[0].get_altered_byte_array()))
        self.assertEqual(message.get_altered_serialized(), expected_output)
        
    def test_get_altered_serialized_multiple_subcomponents(self):
        message = Message()
        message.direction = Message.Direction.Outbound
        data = bytearray('test', 'utf-8')
        message.set_message_from(Message.Format.Raw, data, False)
        data = bytearray('foo', 'utf-8')
        message.append_message_from(Message.Format.Raw, data, False)
        data = bytearray('bar', 'utf-8')
        message.append_message_from(Message.Format.Raw, data, False)
        expected_output = "outbound {}\n".format(message.serialize_byte_array(message.subcomponents[0].get_altered_byte_array()))
        expected_output += "sub {}\n".format(message.serialize_byte_array(message.subcomponents[1].get_altered_byte_array()))
        expected_output += "sub {}\n".format(message.serialize_byte_array(message.subcomponents[2].get_altered_byte_array()))

        self.assertEqual(message.get_altered_serialized(), expected_output)
        
    def test_get_altered_serialized_multiple_fuzzed_subcomponents(self):
        message = Message()
        message.direction = Message.Direction.Outbound
        data = bytearray('test', 'utf-8')
        message.set_message_from(Message.Format.Raw, data, True)
        data = bytearray('foo', 'utf-8')
        message.append_message_from(Message.Format.Raw, data, False)
        data = bytearray('bar', 'utf-8')
        message.append_message_from(Message.Format.Raw, data, True)
        expected_output = "fuzz outbound {}\n".format(message.serialize_byte_array(message.subcomponents[0].get_altered_byte_array()))
        expected_output += "sub {}\n".format(message.serialize_byte_array(message.subcomponents[1].get_altered_byte_array()))
        expected_output += "sub fuzz {}\n".format(message.serialize_byte_array(message.subcomponents[2].get_altered_byte_array()))
        self.assertEqual(message.get_altered_serialized(), expected_output)

    def test_serialization(self):
        data = ''
        for i in range(0,256):
            data += chr(i)
        data = bytearray(data, 'utf-8')
        serialized = Message.serialize_byte_array(data)
        deserialized = Message.deserialize_byte_array(serialized)
        self.assertEqual(data, deserialized)

    def test_serialization_of_message(self):
        data = ''
        for i in range(0,256):
            data += chr(i)
        data = bytearray(data, 'utf-8')
        message = Message()
        message.direction = Message.Direction.Outbound
        message.set_message_from(Message.Format.Raw, data, False)
        serialized = message.get_serialized()
        message.set_from_serialized(serialized)
        deserialized = message.get_original_message()
        self.assertEqual(data, deserialized)

    def test_serialization_single_quote(self):
        data = "test'"
        data = bytearray(data, 'utf-8')
        serialized = Message.serialize_byte_array(data)
        deserialized = Message.deserialize_byte_array(serialized)
        self.assertEqual(data, deserialized)
        message = Message()
        message.direction = Message.Direction.Outbound
        message.set_message_from(Message.Format.Raw, data, False)
        serialized = message.get_serialized()
        message.set_from_serialized(serialized)
        deserialized = message.get_original_message()
        self.assertEqual(data, deserialized)

    def test_serialization_xml_regression(self):
        data = "<?xml version='1.0' ?><stream:stream to='testwebsite.com' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
        data = bytearray(data, 'utf-8')
        serialized = Message.serialize_byte_array(data)
        deserialized = Message.deserialize_byte_array(serialized)
        self.assertEqual(data, deserialized)
        message = Message()
        message.direction = Message.Direction.Outbound
        message.set_message_from(Message.Format.Raw, data, False)
        serialized = message.get_serialized()
        message.set_from_serialized(serialized)
        deserialized = message.get_original_message()
        self.assertEqual(data, deserialized)
