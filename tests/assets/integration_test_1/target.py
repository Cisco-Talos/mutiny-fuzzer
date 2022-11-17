from tests.assets.mock_target import MockTarget

class Target1(MockTarget):

    def accept_fuzz(self):
        #TODO: make message_processor.preconnect available, assert its being called
        # accept initial connection
        self.accept_connection()
        while True:
            # receive hi
            self.receive_packet(2)
            # send hello, addr not required since tcp
            self.send_packet(bytearray('hello', 'utf-8'), addr = None)
            self.receive_packet(4096)
            result = self.incoming_buffer.pop()
            if len(result) > 100 and len(result) < 120:
                # 15th iteration should cause a crash
                # write to file that monitor_target is reading
                assert result == bytearray('magic phrase:ppppppppppppppppppppasswordpasswordpassswordpwordpassswordpassswordpassswordpasswordpasswordpasssword', 'utf-8')
                with open('./tests/assets/integration_test_1/crash.log', 'w') as file:
                    file.write('crashed')
                    self.communication_conn.close()
                    self.listen_conn.close()
                return
            self.send_packet(bytearray('incorrect magic phrase, try again!', 'utf-8'), addr = None)
            self.communication_conn = self.listen_conn.accept()[0]

