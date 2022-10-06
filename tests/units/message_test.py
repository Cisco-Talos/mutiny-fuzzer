import unittest
from backend.fuzzer_types import Message, MessageSubComponent

class TestMessage(unittest.TestCase):
    def setUp(self):
        self.message = Message()

    def tearDown(self):
        self.message = None


    def test_MessageInit(self):
        self.assertEqual(self.message.direction, -1)
        self.assertEqual(self.messsage.isFuzzed, False)
        self.assertEqual(len(self.message.subcomponents), 0)


    def test_getOriginalSubComponents(self):
        self.assertEqual(len(self.message.getOriginalSubcomponents()), 0)

        sub1 = MessageSubComponent('foo', False)
        sub2 = MessageSubComponent('bar', False)
        sub3 = MessageSubComponent('poo', False)
        self.message.subcomponents.append(sub1,sub2,sub3)
        self.assertEqual(len(self.message.getOriginalSubcomponents()), 3)
        self.assertEqual(self.message.getOriginalSubcomponents()[2],'poo')

        self.message.subcomponenets.pop()
        self.assertEqual(len(self.message.getOriginalSubcomponents()), 2)
        self.assertEqual(self.message.getOriginalSubcomponents()[-1], 'bar')


    def test_getAlteredSubComponents(self):
        sub1 = MessageSubComponent('foo', False)
        sub2 = MessageSubComponent('bar', False)
        sub3 = MessageSubComponent('poo', False)
        self.message.subcomponents.append(sub1)
        self.message.subcomponenets.append(sub2)
        self.message.subcomponents.append(sub3)
        self.assertEqual(len(self.message.getOriginalSubcomponents()), 3)
        self.assertEqual(self.message.getOriginalSubcomponents()[2],sub3._altered)

        self.message.subcomponenets.pop()
        self.assertEqual(len(self.message.getOriginalSubcomponents()), 2)
        self.assertEqual(self.message.getOriginalSubcomponents()[-1], sub2._altered)



    def test_getOriginalMessage(self):
        sub1 = MessageSubComponent('foo', False)
        sub2 = MessageSubComponent('bar', False)
        sub3 = MessageSubComponent('poo', False)
        self.message.subcomponents.append(sub1)
        self.message.subcomponenets.append(sub2)
        self.message.subcomponents.append(sub3)
        orig = b'foobarpoo'
        assertEqual(self.message.getOriginalMessage(),orig)


    def test_getAlteredMessage(self):
        sub1 = MessageSubComponent('foo', False)
        sub2 = MessageSubComponent('bar', False)
        sub3 = MessageSubComponent('poo', False)
        self.message.subcomponents.append(sub1)
        self.message.subcomponenets.append(sub2)
        self.message.subcomponents.append(sub3)
        subs = [sub1,sub2,sub3]
        orig_alt = bytearray().join([sub._altered for sub in subs])
        assertEqual(self.message.getAlteredMessage(), orig_alt)
        

    def test_resetAlteredMessage(self):
        sub1 = MessageSubComponent('foo', False)
        self.message.subcomponents.append(sub1)
        self.message.subcomponents[0].setAlteredByteArray(b'notfoo')
        self.message.resetAlteredMessage()
        assertEqual(self.message.subcomponents[0].message, 'foo')



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
