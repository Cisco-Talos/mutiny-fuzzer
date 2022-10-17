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
        self.assertEqual(self.message.isFuzzed, False)
        self.assertEqual(len(self.message.subcomponents), 0)


    def test_getOriginalSubComponents(self):
        self.assertEqual(len(self.message.getOriginalSubcomponents()), 0)

        sub1 = MessageSubComponent(bytearray('foo','utf-8'), False)
        sub2 = MessageSubComponent(bytearray('bar','utf-8'), False)
        sub3 = MessageSubComponent(bytearray('poo','utf-8'), False)
        self.message.subcomponents.append(sub1)
        self.message.subcomponents.append(sub2)
        self.message.subcomponents.append(sub3)
        self.assertEqual(len(self.message.getOriginalSubcomponents()), 3)
        self.assertEqual(self.message.getOriginalSubcomponents()[2],bytearray('poo', 'utf-8'))

        self.message.subcomponents.pop()
        self.assertEqual(len(self.message.getOriginalSubcomponents()), 2)
        self.assertEqual(self.message.getOriginalSubcomponents()[-1], bytearray('bar', 'utf-8'))


    def test_getAlteredSubComponents(self):
        sub1 = MessageSubComponent(bytearray('foo','utf-8'), False)
        sub2 = MessageSubComponent(bytearray('bar','utf-8'), False)
        sub3 = MessageSubComponent(bytearray('poo','utf-8'), False)
        self.message.subcomponents.append(sub1)
        self.message.subcomponents.append(sub2)
        self.message.subcomponents.append(sub3)
        self.assertEqual(len(self.message.getOriginalSubcomponents()), 3)
        self.assertEqual(self.message.getOriginalSubcomponents()[2],sub3._altered)

        self.message.subcomponents.pop()
        self.assertEqual(len(self.message.getOriginalSubcomponents()), 2)
        self.assertEqual(self.message.getOriginalSubcomponents()[-1], sub2._altered)



    def test_getOriginalMessage(self):
        sub1 = MessageSubComponent(bytearray('foo','utf-8'), False)
        sub2 = MessageSubComponent(bytearray('bar','utf-8'), False)
        sub3 = MessageSubComponent(bytearray('poo','utf-8'), False)
        self.message.subcomponents.append(sub1)
        self.message.subcomponents.append(sub2)
        self.message.subcomponents.append(sub3)
        orig = b'foobarpoo'
        self.assertEqual(self.message.getOriginalMessage(),orig)


    def test_getAlteredMessage(self):
        sub1 = MessageSubComponent(bytearray('foo','utf-8'), False)
        sub2 = MessageSubComponent(bytearray('bar','utf-8'), False)
        sub3 = MessageSubComponent(bytearray('poo','utf-8'), False)
        self.message.subcomponents.append(sub1)
        self.message.subcomponents.append(sub2)
        self.message.subcomponents.append(sub3)
        subs = [sub1,sub2,sub3]
        orig_alt = bytearray().join([sub._altered for sub in subs])
        self.assertEqual(self.message.getAlteredMessage(), orig_alt)
        

    def test_resetAlteredMessage(self):
        sub1 = MessageSubComponent(bytearray('foo','utf-8'), False)
        # change _altered message
        self.message.subcomponents.append(sub1)
        self.message.subcomponents[0].setAlteredByteArray(bytearray('notfoo','utf-8'))
        # reset altered message
        self.message.resetAlteredMessage()
        self.assertEqual(self.message.subcomponents[0].message, bytearray('foo', 'utf-8'))



    def test_setMessageFrom(self):
        isFuzzed = False
        # commaSeperatedHex
        sourceType = 0
        message = '01,02,20,2a'.replace(',','')
        messageBytes = bytearray.fromhex(message)
        self.message.setMessageFrom(sourceType, message, isFuzzed)
        self.assertEqual(self.message.subcomponents[0].message, messageBytes)

        # Ascii
        sourceType = 1
        message = "'foo'"
        messageBytes = bytearray(ast.literal_eval(f'b{message}'))
        self.message.setMessageFrom(sourceType, message, isFuzzed)
        self.assertEqual(self.message.subcomponents[0].message, messageBytes)

        # Raw
        sourceType = 2
        message = bytearray('foo', 'utf-8')
        self.message.setMessageFrom(sourceType, message, isFuzzed)
        self.assertEqual(self.message.subcomponents[0].message, message)

        # Invalid
        message = [1,2,3]
        # TODO: assert failure
        #self.message.setMessageFrom(sourceType, message, isFuzzed)
        
        # isFuzzed=True
        isFuzzed = True
        # commaSeperatedHex
        sourceType = 0
        message = '01,02,20,2a'.replace(',','')
        messageBytes = bytearray.fromhex(message)
        self.message.setMessageFrom(sourceType, message, isFuzzed)
        self.assertEqual(self.message.subcomponents[0].message, messageBytes)

        # Ascii
        sourceType = 1
        message = "'foo'"
        messageBytes = bytearray(ast.literal_eval(f'b{message}'))
        self.message.setMessageFrom(sourceType, message, isFuzzed)
        self.assertEqual(self.message.subcomponents[0].message, messageBytes)

        # Raw
        sourceType = 2
        message = bytearray('foo', 'utf-8')
        self.message.setMessageFrom(sourceType, message, isFuzzed)
        self.assertEqual(self.message.subcomponents[0].message, message)


    def test_appendMessageFrom(self):
        isFuzzed = False
        # commaSeperatedHex
        sourceType = 0
        message = '01,02,20,2a'.replace(',','')
        messageBytes = bytearray.fromhex(message)
        self.message.appendMessageFrom(sourceType, message, isFuzzed)
        self.assertEqual(self.message.subcomponents[0].message, messageBytes)
        # Ascii
        sourceType = 1
        message = "'foo'"
        messageBytes = bytearray(ast.literal_eval(f'b{message}'))
        self.message.appendMessageFrom(sourceType, message, isFuzzed)
        self.assertEqual(self.message.subcomponents[1].message, messageBytes)
        # Raw
        sourceType = 2
        message = bytearray('foo', 'utf-8')
        self.message.appendMessageFrom(sourceType, message, isFuzzed)
        self.assertEqual(self.message.subcomponents[2].message, message)

        # ---- isFuzzed  = True
        isFuzzed = True
        # commaSeperatedHex
        sourceType = 0
        message = '01,02,20,2a'.replace(',','')
        messageBytes = bytearray.fromhex(message)
        self.message.appendMessageFrom(sourceType, message, isFuzzed)
        self.assertEqual(self.message.subcomponents[3].message, messageBytes)
        self.assertTrue(self.message.isFuzzed)
        # Ascii
        sourceType = 1
        message = "'foo'"
        messageBytes = bytearray(ast.literal_eval(f'b{message}'))
        self.message.appendMessageFrom(sourceType, message, isFuzzed)
        self.assertEqual(self.message.subcomponents[4].message, messageBytes)
        self.assertTrue(self.message.isFuzzed)
        # Raw
        sourceType = 2
        message = bytearray('foo', 'utf-8')
        self.message.appendMessageFrom(sourceType, message, isFuzzed)
        self.assertEqual(self.message.subcomponents[5].message, message)
        self.assertTrue(self.message.isFuzzed)

        # ----- createNewSubcomponent = False
        appendedMessage = message
        createNewSubcomponent = False
        # commaSeperatedHex
        sourceType = 0
        message = '01,02,20,2a'.replace(',','')
        messageBytes = bytearray.fromhex(message)
        appendedMessage  += messageBytes
        self.message.appendMessageFrom(sourceType, message, isFuzzed)
        self.assertEqual(self.message.subcomponents[5].message, appendedMessage)
        # Ascii
        sourceType = 1
        message = "'foo'"
        messageBytes = bytearray(ast.literal_eval(f'b{message}'))
        appendedMessage += messageBytes
        self.message.appendMessageFrom(sourceType, message, isFuzzed)
        self.assertEqual(self.message.subcomponents[5].message, appendedMessage)
        # Raw
        sourceType = 2
        message = bytearray('foo', 'utf-8')
        appendedMessage += message
        self.message.appendMessageFrom(sourceType, message, isFuzzed, createNewSubcomponent)
        self.assertEqual(self.message.subcomponents[5].message, appendedMessage)



    def test_isOutbound(self):
        self.message.direction =  "outbound"
        self.assertTrue(self.message.isOutbound())

        self.message.direction = "inbound"
        self.assertFalse(self.message.isOutbound())

        self.message.direction = "invalidDirection"
        self.assertFalse(self.message.isOutbound())
    

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
