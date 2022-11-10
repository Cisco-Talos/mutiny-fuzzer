from backend.fuzzer_connection import FuzzerConnection
from backend.fuzzer_data import FuzzerData
import threading
from time import sleep
import unittest
import socket

class TestFuzzerConnection(unittest.TestCase):
    def setUp(self):
        self.proto = 'tcp'
        self.target_host = '127.0.0.1'
        self.target_port = 8888
        self.src_ip = '127.0.0.1'
        self.src_port = 4000
        self.socket_family = socket.AF_INET
        self.socket_type = socket.SOCK_STREAM

    def tearDown(self):
        pass

    def test_FuzzerConnectionInit(self):
        listener_thread = threading.Thread(target=self.accept_connection, args=(self.proto,))
        listener_thread.start()
        sleep(.5) # avoid race, allow handle_connections to bind and listen
        conn = FuzzerConnection(self.proto, self.target_host, self.port, self.src_ip, self.src_port)
        self.assertEqual(conn.proto, self.proto)
        self.assertEqual(conn.host, self.target_host)
        self.assertEqual(conn.target_port, self.target_port)
        self.assertEqual(conn.source_ip, self.src_ip)
        self.assertEqual(conn.source_port, self.src_port)
        self.assertEqual(conn.addr, (self.target_host, self.target_port))
        self.assertEqual(conn.connection.family, self.socket_family)
        self.assertEqual(conn.connection.type, self.socket_type)
        listener_thread.join()
        conn.close()
    
    def test_send_packet_tcp_ipv4(self):
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
    
    def test_send_packet_tls_ipv4(self):
        pass

    def test_send_packet_raw_ipv4(self):
        pass

    def test_receive_packet(self):
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

    def test_connect_to_udp_socket(self):
        conn = FuzzerConnection(self.proto, self.target_host, self.port, self.src_ip, self.src_port, testing=True)

    def test_connect_to_tls_socket(self):
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

