from tests.assets.mock_target import MockTarget
import socket

class Target1(MockTarget):

    def accept_fuzz(self):
        #TODO: make message_processor.preconnect available, assert its being called
        # accept initial connection
        self.accept_connection()
        while True:
            # receive hi
            self.receive_packet(2)
            # send hello, addr not required since tcp
            self.send_packet(bytearray('hello', 'utf-8'))
            self.receive_packet(4096)
            result = self.incoming_buffer.pop()
            if len(result) == 539:
                # 7th iteration should cause a crash
                # write to file that monitor_target is reading
                assert result == bytearray(b'magic phrase:passworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassworpassword')
                with open('./tests/assets/integration_test_1/crash.log', 'w') as file:
                    file.write('crashed')
                    if self.communication_conn.type == socket.SOCK_STREAM:
                        self.listen_conn.close()
                    self.communication_conn.close()
                return
            self.send_packet(bytearray('incorrect magic phrase, try again!', 'utf-8'))
            if self.communication_conn.type == socket.SOCK_STREAM:
                self.communication_conn = self.listen_conn.accept()[0]

