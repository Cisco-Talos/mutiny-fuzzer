from backend.fuzzer_connection import FuzzerConnection
from backend.fuzzer_data import FuzzerData
from tests.assets.mock_target import MockTarget
from backend.menu_functions import print_warning
import threading
from time import sleep
import unittest
import socket
from getmac import get_mac_address as gma
import platform

class TestFuzzerConnection(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.platform = platform.uname().system
        cls.received_data = []

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_FuzzerConnectionInit_tcp_ipv4(self):
        proto = 'tcp'
        mock_if = '127.0.0.1'
        mock_port = 9999
        src_if = '127.0.0.1'
        src_port = 8889
        
        target = MockTarget(proto, mock_if, mock_port)
        if self.platform == 'Darwin':
            print_warning('Skipping Raw Fuzzer Connection Init Test\n Raw Packet\'s are currently unsupported on OSX')
            return
        listener_thread = threading.Thread(target=target.accept_connection)
        listener_thread.start()
        sleep(.5) # avoid race, allow handle_connections to bind and listen
        conn = FuzzerConnection(proto, mock_if, mock_port, src_if, src_port)
        self.assertEqual(conn.proto, proto)
        self.assertEqual(conn.host, mock_if)
        self.assertEqual(conn.target_port, mock_port)
        self.assertEqual(conn.source_ip, src_if)
        self.assertEqual(conn.source_port, src_port)
        self.assertEqual(conn.addr, (mock_if, mock_port))
        self.assertEqual(conn.connection.family, socket.AF_INET)
        self.assertEqual(conn.connection.type, socket.SOCK_STREAM)
        listener_thread.join()
        target.conn.close()
        conn.close()
    
    def test_FuzzerConnectionInit_tcp_ipv6(self):
        proto = 'tcp'
        mock_if = '::1'
        mock_port = 9998
        src_if = '::1'
        src_port = 8888
        
        target = MockTarget(proto, mock_if, mock_port)
        listener_thread = threading.Thread(target=target.accept_connection)
        listener_thread.start()
        sleep(.5) # avoid race, allow handle_connections to bind and listen
        conn = FuzzerConnection(proto, mock_if, mock_port, src_if, src_port)
        self.assertEqual(conn.proto, proto)
        self.assertEqual(conn.host, mock_if)
        self.assertEqual(conn.target_port, mock_port)
        self.assertEqual(conn.source_ip, src_if)
        self.assertEqual(conn.source_port, src_port)
        self.assertEqual(conn.addr, (mock_if, mock_port))
        self.assertEqual(conn.connection.family, socket.AF_INET6)
        self.assertEqual(conn.connection.type, socket.SOCK_STREAM)
        listener_thread.join()
        target.conn.close()
        conn.close()
    
    def test_FuzzerConnectionInit_udp_ipv4(self):
        proto = 'udp'
        mock_if = '127.0.0.1'
        mock_port = 9997
        src_if = '127.0.0.1'
        src_port = 8887
        
        target = MockTarget(proto, mock_if, mock_port)
        listener_thread = threading.Thread(target=target.accept_connection)
        listener_thread.start()
        sleep(.5) # avoid race, allow handle_connections to bind and listen
        conn = FuzzerConnection(proto, mock_if, mock_port, src_if, src_port)
        self.assertEqual(conn.proto, proto)
        self.assertEqual(conn.host, mock_if)
        self.assertEqual(conn.target_port, mock_port)
        self.assertEqual(conn.source_ip, src_if)
        self.assertEqual(conn.source_port, src_port)
        self.assertEqual(conn.addr, (mock_if, mock_port))
        self.assertEqual(conn.connection.family, socket.AF_INET)
        self.assertEqual(conn.connection.type, socket.SOCK_DGRAM)
        listener_thread.join()
        conn.close()
        target.conn.close()

    def test_FuzzerConnectionInit_udp_ipv6(self):
        proto = 'udp'
        mock_if = '::1'
        mock_port = 9996
        src_if = '::1'
        src_port = 8886
        
        target = MockTarget(proto, mock_if, mock_port)
        listener_thread = threading.Thread(target=target.accept_connection)
        listener_thread.start()
        sleep(.5) # avoid race, allow handle_connections to bind and listen
        conn = FuzzerConnection(proto, mock_if, mock_port, src_if, src_port)
        self.assertEqual(conn.proto, proto)
        self.assertEqual(conn.host, mock_if)
        self.assertEqual(conn.target_port, mock_port)
        self.assertEqual(conn.source_ip, src_if)
        self.assertEqual(conn.source_port, src_port)
        self.assertEqual(conn.addr, (mock_if, mock_port))
        self.assertEqual(conn.connection.family, socket.AF_INET6)
        self.assertEqual(conn.connection.type, socket.SOCK_DGRAM)
        listener_thread.join()
        conn.close()
    
    def test_FuzzerConnectionInit_tls_ipv4(self):
        return #FIXME: remove after addressing issue #29
        proto = 'tls'
        mock_if = '127.0.0.1'
        mock_port = 9995
        src_if = '127.0.0.1'
        src_port = 8885
        
        target = MockTarget(proto, mock_if, mock_port)
        listener_thread = threading.Thread(target=target.accept_connection)
        listener_thread.start()
        sleep(.5) # avoid race, allow handle_connections to bind and listen
        conn = FuzzerConnection(proto, mock_if, mock_port, src_if, src_port)
        self.assertEqual(conn.proto, proto)
        self.assertEqual(conn.host, mock_if)
        self.assertEqual(conn.target_port, mock_port)
        self.assertEqual(conn.source_ip, src_if)
        self.assertEqual(conn.source_port, src_port)
        self.assertEqual(conn.addr, (mock_if, mock_port))
        self.assertEqual(conn.connection.family, socket.AF_INET)
        self.assertEqual(conn.connection.type, socket.SOCK_STREAM)
        # TODO: add a check to verify tls is being used
        listener_thread.join()
        conn.close()
        target.conn.close()
    
    def test_FuzzerConnectionInit_tls_ipv6(self):
        return #FIXME: remove after addressing issue #29
        proto = 'tls'
        mock_if = '::1'
        mock_port = 9994
        src_if = '::1'
        src_port = 8884
        
        target = MockTarget(proto, mock_if, mock_port)
        listener_thread = threading.Thread(target=target.accept_connection)
        listener_thread.start()
        sleep(.5) # avoid race, allow handle_connections to bind and listen
        conn = FuzzerConnection(proto, mock_if, mock_port, src_if, src_port)
        self.assertEqual(conn.proto, proto)
        self.assertEqual(conn.host, mock_if)
        self.assertEqual(conn.target_port, mock_port)
        self.assertEqual(conn.source_ip, src_if)
        self.assertEqual(conn.source_port, src_port)
        self.assertEqual(conn.addr, (mock_if, mock_port))
        self.assertEqual(conn.connection.family, socket.AF_INET6)
        self.assertEqual(conn.connection.type, socket.SOCK_STREAM)
        #TODO: add a check to verify tls is being used
        listener_thread.join()
        conn.close()
        target.conn.close()
    
    def test_FuzzerConnectionInit_raw(self):
        if self.platform == 'Darwin':
            print_warning('Skipping Raw Fuzzer Connection Init Test\n Raw Packet\'s are currently unsupported on OSX')
            return
        proto = 'L2raw'
        mock_if = gma()
        mock_port = 0
        src_if = gma()
        src_port = 0
        
        target = MockTarget(proto, mock_if, mock_port)
        listener_thread = threading.Thread(target=target.accept_connection)
        listener_thread.start()
        sleep(.5) # avoid race, allow handle_connections to bind and listen
        conn = FuzzerConnection(proto, mock_if, mock_port, src_if, src_port)
        self.assertEqual(conn.proto, proto)
        self.assertEqual(conn.host, mock_if)
        self.assertEqual(conn.target_port, mock_port)
        self.assertEqual(conn.source_ip, src_if)
        self.assertEqual(conn.source_port, src_port)
        self.assertEqual(conn.addr, (mock_if, mock_port))
        self.assertEqual(conn.connection.family, socket.AF_INET)
        self.assertEqual(conn.connection.type, socket.SOCK_STREAM)
        listener_thread.join()
        conn.close()
        target.conn.close()

    def test_send_packet_tcp_ipv4(self):
        proto = 'tcp'
        mock_if = '127.0.0.1'
        mock_port = 9994
        src_if = '127.0.0.1'
        src_port = 8884
        
        target = MockTarget(proto, mock_if, mock_port)
        listener_thread = threading.Thread(target=target.accept_connection)
        listener_thread.start()
        data = bytes('test', 'utf-8')
        sleep(.1) # avoid race, allow handle_connections to bind and listen
        conn = FuzzerConnection(proto, mock_if, mock_port, src_if, src_port)
        listener_thread.join()
        reception_thread = threading.Thread(target=target.receive_packet, args=(len(data),))
        reception_thread.start()
        sleep(.1)
        conn.send_packet(data, 3.0)
        reception_thread.join()
        conn.connection.close()
        target.conn.close()
        self.assertEqual(target.incoming_buffer.pop(), data)

    def test_send_packet_tcp_ipv6(self):
        proto = 'tcp'
        mock_if = '::1'
        mock_port = 9993
        src_if = '::1'
        src_port = 8883

        target = MockTarget(proto, mock_if, mock_port)
        listener_thread = threading.Thread(target=target.accept_connection)
        listener_thread.start()
        data = bytes('test', 'utf-8')
        sleep(.1) # avoid race, allow handle_connections to bind and listen
        conn = FuzzerConnection(proto, mock_if, mock_port, src_if, src_port)
        listener_thread.join()
        reception_thread = threading.Thread(target=target.receive_packet, args=(len(data),))
        reception_thread.start()
        conn.send_packet(data, 3.0)
        reception_thread.join()
        conn.connection.close()
        target.conn.close()
        self.assertEqual(target.incoming_buffer.pop(), data)

    def test_send_packet_udp_ipv4(self):
        proto = 'udp'
        mock_if = '127.0.0.1'
        mock_port = 9992
        src_if = '127.0.0.1'
        src_port = 8882
        
        target = MockTarget(proto, mock_if, mock_port)
        listener_thread = threading.Thread(target=target.accept_connection)
        listener_thread.start()
        data = bytes('test', 'utf-8')
        sleep(.1)
        conn = FuzzerConnection(proto, mock_if, mock_port, src_if, src_port)
        listener_thread.join()
        reception_thread = threading.Thread(target=target.receive_packet, args=(len(data),))
        reception_thread.start()
        conn.send_packet(data, 3.0)
        reception_thread.join()
        conn.connection.close()
        target.conn.close()
        self.assertEqual(target.incoming_buffer.pop(),data)
    
    def test_send_packet_udp_ipv6(self):
        proto = 'udp'
        mock_if = '::1'
        mock_port = 9991
        src_if = '::1'
        src_port = 8881
        
        target = MockTarget(proto, mock_if, mock_port)
        listener_thread = threading.Thread(target=target.accept_connection)
        listener_thread.start()
        data = bytes('test', 'utf-8')
        sleep(.1)
        conn = FuzzerConnection(proto, mock_if, mock_port, src_if, src_port)
        listener_thread.join()
        reception_thread = threading.Thread(target=target.receive_packet, args=(len(data),))
        reception_thread.start()
        conn.send_packet(data, 3.0)
        reception_thread.join()
        conn.connection.close()
        target.conn.close()
        self.assertEqual(target.incoming_buffer.pop(),data)

    def test_send_packet_tls_ipv4(self):
        return #FIXME: remove after addressing issue #29
        proto = 'tls'
        mock_if = '127.0.0.1'
        mock_port = 9990
        src_if = '127.0.0.1'
        src_port = 8880
        
        target = MockTarget(proto, mock_if, mock_port)
        listener_thread = threading.Thread(target=target.accept_connection)
        listener_thread.start()
        data = bytes('test', 'utf-8')
        sleep(.1)
        conn = FuzzerConnection(proto, mock_if, mock_port, src_if, src_port)
        listener_thread.join()
        reception_thread = threading.Thread(target=target.receive_packet, args=(len(data),))
        reception_thread.start()
        conn.send_packet(data, 3.0)
        reception_thread.join()
        conn.connection.close()
        target.conn.close()
        self.assertEqual(target.incoming_buffer.pop(),data)

    def test_send_packet_tls_ipv6(self):
        return #FIXME: remove after addressing issue #29
        proto = 'tls'
        mock_if = '::1'
        mock_port = 9989
        src_if = '::1'
        src_port = 8879
        
        target = MockTarget(proto, mock_if, mock_port)
        listener_thread = threading.Thread(target=target.accept_connection)
        listener_thread.start()
        data = bytes('test', 'utf-8')
        sleep(.1)
        conn = FuzzerConnection(proto, mock_if, mock_port, src_if, src_port)
        listener_thread.join()
        reception_thread = threading.Thread(target=target.receive_packet, args=(len(data),))
        reception_thread.start()
        conn.send_packet(data, 3.0)
        reception_thread.join()
        conn.connection.close()
        target.conn.close()
        self.assertEqual(target.incoming_buffer.pop(),data)

    def test_send_packet_raw(self):
        if self.platform == 'Darwin':
            print_warning('Skipping Raw Send Packet Test\n Raw Packet\'s are currently unsupported on OSX')
            return
        proto = 'L2raw'
        mock_if = gma()
        mock_port = 0
        src_if = gma()
        src_port = 0
        
        target = MockTarget(proto, mock_if, mock_port)
        listener_thread = threading.Thread(target=target.accept_connection)
        listener_thread.start()
        data = bytes('test', 'utf-8')
        sleep(.1)
        conn = FuzzerConnection(proto, mock_if, mock_port, src_if, src_port)
        listener_thread.join()
        reception_thread = threading.Thread(target=target.receive_packet, args=(len(data),))
        reception_thread.start()
        conn.send_packet(data, 3.0)
        reception_thread.join()
        conn.connection.close()
        target.conn.close()
        self.assertEqual(target.incoming_buffer.pop(),data)


    def receive_packet_wrapper(self, conn, bytes_to_read, timeout):
        '''
        wrapper around FuzzerConnection.receive_packet that sets the return value of receive_packet
        to self.received_data so that it can be accessed from the main thread
        '''
        self.received_data.append(conn.receive_packet(bytes_to_read, timeout))

    def test_receive_packet_tcp_ipv4(self):
        proto = 'tcp'
        mock_if = '127.0.0.1'
        mock_port = 9988
        src_if = '127.0.0.1'
        src_port = 8878
        
        target = MockTarget(proto, mock_if, mock_port)
        listener_thread = threading.Thread(target=target.accept_connection)
        listener_thread.start()
        data = bytes('test', 'utf-8')
        sleep(.1)
        conn = FuzzerConnection(proto, mock_if, mock_port, src_if, src_port)
        listener_thread.join()
        reception_thread = threading.Thread(target=self.receive_packet_wrapper, args=(conn, len(data), 3.0))
        reception_thread.start()
        target.send_packet(data, (mock_if, mock_port))
        reception_thread.join()
        conn.connection.close()
        target.conn.close()
        self.assertEqual(self.received_data.pop(), data)


    def test_receive_packet_tcp_ipv6(self):
        proto = 'tcp'
        mock_if = '::1'
        mock_port = 9987
        src_if = '::1'
        src_port = 8877
        
        target = MockTarget(proto, mock_if, mock_port)
        listener_thread = threading.Thread(target=target.accept_connection)
        listener_thread.start()
        data = bytes('test', 'utf-8')
        sleep(.1)
        conn = FuzzerConnection(proto, mock_if, mock_port, src_if, src_port)
        listener_thread.join()
        reception_thread = threading.Thread(target=self.receive_packet_wrapper, args=(conn, len(data), 3.0))
        reception_thread.start()
        target.send_packet(data, (mock_if, mock_port))
        reception_thread.join()
        conn.connection.close()
        target.conn.close()
        self.assertEqual(self.received_data.pop(), data)

    def test_receive_packet_udp_ipv4(self):
        proto = 'udp'
        mock_if = '127.0.0.1'
        mock_port = 9986
        src_if = '127.0.0.1'
        src_port = 8876
        
        target = MockTarget(proto, mock_if, mock_port)
        listener_thread = threading.Thread(target=target.accept_connection)
        listener_thread.start()
        data = bytes('test', 'utf-8')
        sleep(.1)
        conn = FuzzerConnection(proto, mock_if, mock_port, src_if, src_port)
        listener_thread.join()
        reception_thread = threading.Thread(target=self.receive_packet_wrapper, args=(conn, len(data), 3.0))
        reception_thread.start()
        target.send_packet(data, (src_if, src_port))
        reception_thread.join()
        conn.connection.close()
        target.conn.close()
        self.assertEqual(self.received_data.pop(), data)


    def test_receive_packet_udp_ipv6(self):
        proto = 'udp'
        mock_if = '::1'
        mock_port = 9985
        src_if = '::1'
        src_port = 8875
        
        target = MockTarget(proto, mock_if, mock_port)
        listener_thread = threading.Thread(target=target.accept_connection)
        listener_thread.start()
        data = bytes('test', 'utf-8')
        sleep(.1)
        conn = FuzzerConnection(proto, mock_if, mock_port, src_if, src_port)
        listener_thread.join()
        reception_thread = threading.Thread(target=self.receive_packet_wrapper, args=(conn, len(data), 3.0))
        reception_thread.start()
        target.send_packet(data, (src_if, src_port))
        reception_thread.join()
        conn.connection.close()
        target.conn.close()
        self.assertEqual(self.received_data.pop(), data)


    def test_receive_packet_tls_ipv4(self):
        return #FIXME: remove after addressing issue #29
        proto = 'tls'
        mock_if = '127.0.0.1'
        mock_port = 9984
        src_if = '127.0.0.1'
        src_port = 8874
        
        target = MockTarget(proto, mock_if, mock_port)
        listener_thread = threading.Thread(target=target.accept_connection)
        listener_thread.start()
        data = bytes('test', 'utf-8')
        sleep(.1)
        conn = FuzzerConnection(proto, mock_if, mock_port, src_if, src_port)
        listener_thread.join()
        reception_thread = threading.Thread(target=self.receive_packet_wrapper, args=(conn, len(data), 3.0))
        reception_thread.start()
        target.send_packet(data, (src_if, src_port))
        reception_thread.join()
        conn.connection.close()
        target.conn.close()
        self.assertEqual(self.received_data.pop(), data)

    def test_receive_packet_tls_ipv6(self):
        return #FIXME: remove after addressing issue #29
        proto = 'tls'
        mock_if = '::1'
        mock_port = 9983
        src_if = '::1'
        src_port = 8873
        
        target = MockTarget(proto, mock_if, mock_port)
        listener_thread = threading.Thread(target=target.accept_connection)
        listener_thread.start()
        data = bytes('test', 'utf-8')
        sleep(.1)
        conn = FuzzerConnection(proto, mock_if, mock_port, src_if, src_port)
        listener_thread.join()
        reception_thread = threading.Thread(target=self.receive_packet_wrapper, args=(conn, len(data), 3.0))
        reception_thread.start()
        target.send_packet(data, (src_if, src_port))
        reception_thread.join()
        conn.connection.close()
        target.conn.close()
        self.assertEqual(self.received_data.pop(), data)


    def test_receive_packet_raw(self):
        if self.platform == 'Darwin':
            print_warning('Skipping Raw Fuzzer Connection Init Test\n Raw Packet\'s are currently unsupported on OSX')
            return
        proto = 'L2raw'
        mock_if = gma()
        mock_port = 0
        src_if = gma()
        src_port = 0
        
        target = MockTarget(proto, mock_if, mock_port)
        listener_thread = threading.Thread(target=target.accept_connection)
        listener_thread.start()
        data = bytes('test', 'utf-8')
        sleep(.1)
        conn = FuzzerConnection(proto, mock_if, mock_port, src_if, src_port)
        listener_thread.join()
        reception_thread = threading.Thread(target=self.receive_packet_wrapper, args=(conn, len(data), 3.0))
        reception_thread.start()
        target.send_packet(data, (src_if, src_port))
        reception_thread.join()
        conn.connection.close()
        target.conn.close()
        self.assertEqual(self.received_data.pop(), data)
