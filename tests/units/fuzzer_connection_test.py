from backend.fuzzer_connection import FuzzerConnection
from backend.fuzzer_data import FuzzerData
from tests.assets.mock_target import MockTarget
import threading
from time import sleep
import unittest
import socket

class TestFuzzerConnection(unittest.TestCase):
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
        self.assertEqual(conn.source_ip, src_ip)
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
        self.assertEqual(conn.source_ip, src_ip)
        self.assertEqual(conn.source_port, src_port)
        self.assertEqual(conn.addr, (mock_if, mock_port))
        self.assertEqual(conn.connection.family, socket.AF_INET6)
        self.assertEqual(conn.connection.type, socket.SOCK_DGRAM)
        listener_thread.join()
        conn.close()
    
    def test_FuzzerConnectionInit_tls_ipv4(self):
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
        self.assertEqual(conn.source_ip, src_ip)
        self.assertEqual(conn.source_port, src_port)
        self.assertEqual(conn.addr, (mock_if, mock_port))
        self.assertEqual(conn.connection.family, socket.AF_INET)
        self.assertEqual(conn.connection.type, socket.SOCK_STREAM)
        # TODO: add a check to verify tls is being used
        listener_thread.join()
        conn.close()
        target.conn.close()
    
    def test_FuzzerConnectionInit_tls_ipv6(self):
        proto = 'tls'
        mock_if = '::1'
        mock_port = 9994
        src_if = '::!'
        src_port = 8884
        
        target = MockTarget(proto, mock_if, mock_port)
        listener_thread = threading.Thread(target=target.accept_connection)
        listener_thread.start()
        sleep(.5) # avoid race, allow handle_connections to bind and listen
        conn = FuzzerConnection(proto, mock_if, mock_port, src_if, src_port)
        self.assertEqual(conn.proto, proto)
        self.assertEqual(conn.host, mock_if)
        self.assertEqual(conn.target_port, mock_port)
        self.assertEqual(conn.source_ip, src_ip)
        self.assertEqual(conn.source_port, src_port)
        self.assertEqual(conn.addr, (mock_if, mock_port))
        self.assertEqual(conn.connection.family, socket.AF_INET6)
        self.assertEqual(conn.connection.type, socket.SOCK_STREAM)
        #TODO: add a check to verify tls is being used
        listener_thread.join()
        conn.close()
        target.conn.close()
    
    def test_FuzzerConnectionInit_raw(self):
        '''FIXME: need to find a way to get autodetect interfaces and use for send/reception
        proto = 'L2raw'
        mock_if = '127.0'
        mock_port = 0
        src_if = '127.0.0.1'
        src_port = 0
        
        target = MockTarget(proto, mock_if, mock_port)
        listener_thread = threading.Thread(target=target.accept_connection)
        listener_thread.start()
        sleep(.5) # avoid race, allow handle_connections to bind and listen
        conn = FuzzerConnection(proto, mock_if, mock_port, src_if, src_port)
        self.assertEqual(conn.proto, proto)
        self.assertEqual(conn.host, mock_if)
        self.assertEqual(conn.target_port, mock_port)
        self.assertEqual(conn.source_ip, src_ip)
        self.assertEqual(conn.source_port, src_port)
        self.assertEqual(conn.addr, (mock_if, mock_port))
        self.assertEqual(conn.connection.family, socket.AF_INET)
        self.assertEqual(conn.connection.type, socket.SOCK_STREAM)
        listener_thread.join()
        conn.close()
        '''
        pass

    def test_send_packet_tcp_ipv4(self):
        data = bytes('test', 'utf-8')
        target = MockTarget(proto, mock_if, mock_port)
        # tcp test
        listen_thread = threading.Thread(target=receive_packet, args=('tcp',))
        listen_thread.start()
        sleep(.5) # avoid race, allow handle_connections to bind and listen
        conn = FuzzerConnection(proto, host, port, src_ip, src_port, seed)
        conn.send_packet(data, 3.0)
        listen_thread.join()
        conn.connection.close()
        self.assertEqual(received_data['data'], data)

    def test_send_packet_tcp_ipv6(self):
        data = bytes('test', 'utf-8')
        # tcp test
        listen_thread = threading.Thread(target=receive_packet, args=('tcp',))
        listen_thread.start()
        sleep(.5) # avoid race, allow handle_connections to bind and listen
        conn = FuzzerConnection(proto, host, port, src_ip, src_port, seed)
        conn.send_packet(data, 3.0)
        listen_thread.join()
        conn.connection.close()
        self.assertEqual(received_data['data'], data)

    def test_send_packet_udp_ipv4(self):
        # non-tcp test
        test_port = 9998 # to avoid issues binding to same port in short time
        socket_type = socket.SOCK_DGRAM
        listen_thread = threading.Thread(target=self.accept_connection, args=('non-tcp',))
        listen_thread.start()
        conn = FuzzerConnection(proto, host, port, src_ip, src_port, seed)
        conn.send_packet(data, 3.0)
        listen_thread.join()
        conn.close()
        self.assertEqual(received_data['data'],data)
    
    def test_send_packet_udp_ipv6(self):
        # non-tcp test
        test_port = 9998 # to avoid issues binding to same port in short time
        socket_type = socket.SOCK_DGRAM
        listen_thread = threading.Thread(target=self.accept_connection, args=('non-tcp',))
        listen_thread.start()
        conn = FuzzerConnection(proto, host, port, src_ip, src_port, seed)
        conn.send_packet(data, 3.0)
        listen_thread.join()
        conn.close()
        self.assertEqual(received_data['data'],data)

    def test_send_packet_tls_ipv4(self):
        pass

    def test_send_packet_tls_ipv6(self):
        pass

    def test_send_packet_raw(self):
        pass

    def test_receive_packet_tcp_ipv4(self):
        data = bytes('test', 'utf-8')

        # tcp test
        conn_thread = threading.Thread(target=handle_incoming_connection, args=('tcp',))
        conn_thread.start()
        sleep(.5) # avoid race, allow handle_connections to bind and listen
        test_addr = (host, port)
        conn = FuzzerConnection(self.proto, self.target_host, self.target_port, self.src_ip, self.src_port, testing=True)
        response = conn.receive_packet(mutiny_conn, test_addr, len(data))
        conn_thread.join()
        self.assertEqual(response, data)
        conn.connection.close()

    def test_receive_packet_tcp_ipv6(self):
        data = bytes('test', 'utf-8')

        # tcp test
        conn_thread = threading.Thread(target=handle_incoming_connection, args=('tcp',))
        conn_thread.start()
        sleep(.5) # avoid race, allow handle_connections to bind and listen
        test_addr = (host, port)
        conn = FuzzerConnection(self.proto, self.target_host, self.target_port, self.src_ip, self.src_port, testing=True)
        response = conn.receive_packet(mutiny_conn, test_addr, len(data))
        conn_thread.join()
        self.assertEqual(response, data)
        conn.connection.close()

    def test_receive_packet_udp_ipv4(self):
        data = bytes('test', 'utf-8')

        # tcp test
        conn_thread = threading.Thread(target=handle_incoming_connection, args=('tcp',))
        conn_thread.start()
        sleep(.5) # avoid race, allow handle_connections to bind and listen
        test_addr = (host, port)
        conn = FuzzerConnection(self.proto, self.target_host, self.target_port, self.src_ip, self.src_port, testing=True)
        response = conn.receive_packet(mutiny_conn, test_addr, len(data))
        conn_thread.join()
        self.assertEqual(response, data)
        conn.connection.close()

    def test_receive_packet_udp_ipv6(self):
        data = bytes('test', 'utf-8')

        # tcp test
        conn_thread = threading.Thread(target=handle_incoming_connection, args=('tcp',))
        conn_thread.start()
        sleep(.5) # avoid race, allow handle_connections to bind and listen
        test_addr = (host, port)
        conn = FuzzerConnection(self.proto, self.target_host, self.target_port, self.src_ip, self.src_port, testing=True)
        response = conn.receive_packet(mutiny_conn, test_addr, len(data))
        conn_thread.join()
        self.assertEqual(response, data)
        conn.connection.close()

    def test_receive_packet_tls_ipv4(self):
        data = bytes('test', 'utf-8')

        # tcp test
        conn_thread = threading.Thread(target=handle_incoming_connection, args=('tcp',))
        conn_thread.start()
        sleep(.5) # avoid race, allow handle_connections to bind and listen
        test_addr = (host, port)
        conn = FuzzerConnection(self.proto, self.target_host, self.target_port, self.src_ip, self.src_port, testing=True)
        response = conn.receive_packet(mutiny_conn, test_addr, len(data))
        conn_thread.join()
        self.assertEqual(response, data)
        conn.connection.close()

    def test_receive_packet_tls_ipv6(self):
        data = bytes('test', 'utf-8')

        # tcp test
        conn_thread = threading.Thread(target=handle_incoming_connection, args=('tcp',))
        conn_thread.start()
        sleep(.5) # avoid race, allow handle_connections to bind and listen
        test_addr = (host, port)
        conn = FuzzerConnection(self.proto, self.target_host, self.target_port, self.src_ip, self.src_port, testing=True)
        response = conn.receive_packet(mutiny_conn, test_addr, len(data))
        conn_thread.join()
        self.assertEqual(response, data)
        conn.connection.close()

    def test_receive_packet_raw(self):
        # non-tcp test 
        test_port = 9998 # to avoid issues binding to same port in short time
        socket_type = socket.SOCK_RAW
        test_addr = (test_ip, test_port)
        conn_thread = threading.Thread(target=handle_connection, args=('non-tcp',))
        conn_thread.start()
        mutiny_conn = socket.socket(socket_family, socket_type)
        response = mutiny.receivePacket(mutiny_conn, test_addr, len(out_packet_data))
        conn_thread.join()
        mutiny_conn.close()
        self.assertEqual(response, out_packet_data)
        # greater than 4096
        mutiny_port = 4001
        test_port = 8889
        mutiny_conn = socket.socket(socket_family, socket_type)
        mutiny_conn.bind((mutiny_ip, mutiny_port))
        out_packet_data = bytes('A' * 4096 + 'test', 'utf-8')
        conn_thread = threading.Thread(target=handle_connection, args=('tcp',))
        conn_thread.start()
        sleep(1) # avoid race, allow handle_connections to bind and listen
        test_addr = (test_ip, test_port)
        mutiny_conn.connect(test_addr)
        response = self.receive_packet(mutiny_conn, test_addr, len(out_packet_data))
        conn_thread.join()
        self.assertEqual(response, out_packet_data)
        mutiny_conn.close()

    def test_connect_to_tcp_socket_ipv4(self):
        conn = FuzzerConnection()
        conn.connection = None # reset to none so we can test connection
        conn._get_addr()
        self.socket_family = socket.AF_INET
        conn._connect_to_tcp_socket()
        # assert connection type is sock_stream 
        # assert connection is connected 
        pass

    def test_connect_to_tcp_socket_ipv6(self):
        conn = FuzzerConnection()
        conn.connection = None # reset to none so we can test connection
        conn._get_addr()
        self.socket_family = socket.AF_INET
        conn._connect_to_tcp_socket()
        # assert connection type is sock_stream 
        # assert connection is connected 
        pass

    def test_connect_to_udp_socket_ipv4(self):
        conn = FuzzerConnection(self.proto, self.target_host, self.port, self.src_ip, self.src_port, testing=True)

    def test_connect_to_udp_socket_ipv6(self):
        conn = FuzzerConnection(self.proto, self.target_host, self.port, self.src_ip, self.src_port, testing=True)

    def test_connect_to_tls_socket_ipv4(self):
        pass

    def test_connect_to_tls_socket_ipv6(self):
        pass

    def test_connect_to_raw_socket(self):
        pass

    def test_get_addr(self):
        self.proto = 'L2raw'
        self.host = '127.0.0.1'
        conn = FuzzerConnection()
        conn.addr = None
        conn._get_addr()
        self.assertEqual(self.addr)
        pass

    def test_get_addr_ipv4(self):
        self.proto = 'L2raw'

    def test_get_addr_ipv6(self):
        self.proto = 'L2raw'

    def test_get_addr_ipv6_localhost(self):
        pass

    def test_bind_to_interface(self):
        pass

