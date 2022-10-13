import unittest
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
        st = 0
        message = '00,01,02,20,2a'
        self.message.setMessageFrom(st,message,isFuzzed)
        self.assertEqual(self.subcomponents[0], 

        # Ascii
        st = 1
        message = 'foo\x00\x01'
        self.message.setMessageFrom(

        # Raw
        st = 2
        message = bytearray('foo')

        # Invalid
        message = [1,2,3]
        
        # isFuzzed=True
        isFuzzed = True
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
