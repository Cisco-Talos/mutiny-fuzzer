from backend.fuzzer_connection import FuzzerConnection
from backend.fuzzer_data import FuzzerData
import threading
from time import sleep
import unittest
import socket

class TestFuzzerConnection(unittest.TestCase):
    def setUp(self):
        self.host = '127.0.0.1'
        self.port = 8888
        self.src_ip = '127.0.0.1'
        self.src_port = 4000
        self.socket_family = socket.AF_INET
        self.socket_type = socket.SOCK_STREAM

    def tearDown(self):
        pass

    def test_FuzzerConnectionInit(self):
        def handle_connection():
            test_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_conn.bind((host, port))
            test_conn.listen()
            test_conn.accept()
            test_conn.close()

        proto = 'tcp'
        host = '127.0.0.1'
        port = 9999
        src_ip = '127.0.0.1'
        src_port = 9998
        seed = 1
        # tcp test
        conn_thread = threading.Thread(target=handle_connection)
        conn_thread.start()
        sleep(.5) # avoid race, allow handle_connections to bind and listen
        conn = FuzzerConnection(proto, host, port, src_ip, src_port, seed)
        self.assertEqual(conn.proto, 'tcp')
        self.assertEqual(conn.host, '127.0.0.1')
        self.assertEqual(conn.target_port, 9999)
        self.assertEqual(conn.source_ip, '127.0.0.1')
        self.assertEqual(conn.source_port, 9998)
        self.assertEqual(conn.seed, 1)
        self.assertEqual(conn.addr, ('127.0.0.1',9999))
        self.assertEqual(conn.connection.family, socket.AF_INET)
        self.assertEqual(conn.connection.type, socket.SOCK_STREAM)
        conn_thread.join()
        conn.connection.close()
    
    def test_send_packet(self):
        received_data = {}
        proto = 'tcp'
        host = '127.0.0.1'
        port = 9997
        src_ip = '127.0.0.1'
        src_port = 9996
        seed = 1
        data = bytes('test', 'utf-8')
        socket_family = socket.AF_INET
        socket_type = socket.SOCK_STREAM

        # tcp test
        listen_thread = threading.Thread(target=handle_connection, args=('tcp',))
        listen_thread.start()
        sleep(.5) # avoid race, allow handle_connections to bind and listen
        conn = FuzzerConnection(proto, host, port, src_ip, src_port, seed)
        conn.send_packet(data, 3.0)
        listen_thread.join()
        conn.connection.close()
        self.assertEqual(received_data['data'], data)

        # non-tcp test
        test_port = 9998 # to avoid issues binding to same port in short time
        socket_type = socket.SOCK_DGRAM
        listen_thread = threading.Thread(target=handle_connection, args=('non-tcp',))
        listen_thread.start()
        conn = FuzzerConnection(proto, host, port, src_ip, src_port, seed)
        conn.send_packet(data, 3.0)
        listen_thread.join()
        conn.close()
        self.assertEqual(received_data['data'],data)


    def test_receive_packet(self):
        data = bytes('test', 'utf-8')

        # tcp test
        conn_thread = threading.Thread(target=handle_incoming_connection, args=('tcp',))
        conn_thread.start()
        sleep(.5) # avoid race, allow handle_connections to bind and listen
        test_addr = (host, port)
        conn = FuzzerConnection('tcp',host,port,src_ip,src_port,1)
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

        def test_connect_to_tcp_socket(self):
            conn = FuzzerConnection()
            conn.connection = None # reset to none so we can test connection
            conn.get_addr
            self.socket_family = 
            conn._connect_to_tcp_socket
            # assert connection type is sock_stream 
            # assert connection is connected 
            pass

        def test_connect_to_udp_socket(self):
            pass

        def test_connect_to_tls_socket(self):
            pass

        def test_connect_to_raw_socket(self):
            pass

        def test_get_addr(self):
            pass

        def test_bind_to_interface(self):

    def handle_outbound_connection(self, test_type):
        test_conn = socket.socket(self.socket_family, self.socket_type)
        test_conn.bind((self.host, self.port))
        if test_type == 'tcp': 
            test_conn.listen()
            test_conn, mutiny_addr = test_conn.accept()
            self.inbound_data = test_conn.recv(len(self.outbound_data))
        else:
            self.inbound_data, addr = test_conn.recvfrom(len(self.outbound_data))
        test_conn.close()

    def handle_incoming_connection(self, test_type):
        test_conn = socket.socket(self.socket_family, self.socket_type)
        test_conn.bind((self.host, self.port))
        if test_type == 'tcp': 
            test_conn.listen()
            test_conn, mutiny_addr = test_conn.accept()
            self.inbound_data = test_conn.recv(len(self.outbound_data))
        else:
            self.inbound_data, addr = test_conn.recvfrom(len(self.outbound_data))
        test_conn.close()
