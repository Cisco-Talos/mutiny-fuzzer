from tests.assets.mock_target import MockTarget

class Target3(MockTarget):

    def accept_fuzz(self):
        #TODO: make message_processor.preconnect available, assert its being called
        # accept initial connection
        self.accept_connection()
        # receive 'greetings <fuzzzed subcomponent>'
        self.receive_packet(4096)
        self.communication_conn = self.listen_conn.accept()[0]
        while self.communication_conn:
            try:
                # receive 'greetings <fuzzzed subcomponent>'
                self.receive_packet(4096)
                self.communication_conn = self.listen_conn.accept()[0]
            except ConnectionAbortedError:
                return


