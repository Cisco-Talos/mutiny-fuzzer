import unittest
from backend.fuzzer_types import Message, MessageCollection

class TestMessageCollection(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_MessageCollection_init(self):
        mc = MessageCollection()
        self.assertIsInstance(mc.messages, list)
        self.assertEqual(len(mc.messages), 0)

    def test_add_message(self):
        mc = MessageCollection()
        message = Message()
        message.message = 'test'
        mc.add_message(message)
        self.assertEqual(len(mc.messages), 1)
        self.assertEqual(mc.messages[0].message,  'test')


    def test_do_client_messages_match(self):
        '''
        since Message objects implement __eq__ and we already have tests for that,
        no need to be super exhaustive
        '''
        mc1 = MessageCollection()
        mc2 = MessageCollection()

        # matching client
        message1 = Message()
        message1.message = 'test'
        message1.direction = 'inbound'
        message2 = Message()
        message2.message = 'test'
        message2.direction = 'outbound'
        mc1.add_message(message1)
        mc1.add_message(message2)
        # shouldn't matter since only client messages are compared
        message3 = Message()
        message3.message = 'nottest'
        message3.direction = 'inbound'
        mc2.add_message(message3)
        mc2.add_message(message2)
        self.assertTrue(mc1.do_client_messages_match(mc2))
        # non matching client
        mc1 = MessageCollection()
        mc2 = MessageCollection()
        mc1.add_message(message1)
        mc1.add_message(message2)
        # should matter
        message3 = Message
        message3.message = 'nottest'
        message3.direction = 'outbound'
        mc2.add_message(message1)
        mc2.add_message(message3)
        self.assertFalse(mc1.do_client_messages_match(mc2))

        # Index Error
        mc1 = MessageCollection()
        mc2 = MessageCollection()
        mc1.add_message(message1)
        mc1.add_message(message2)
        mc2.add_message(message3)
        self.assertFalse(mc1.do_client_messages_match(mc2))



