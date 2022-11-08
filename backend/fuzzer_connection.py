import ssl
from fuzzer_types import Message
import socket
import sys
import os
current = os.path.dirname(os.path.realpath(__file__))
parent = os.path.dirname(current)
sys.path.append(parent)
from mutiny_classes import mutiny_exceptions

class Connection(object):
    '''
    isolates connection management functionality including but not limited to;
    - determining type of connection to use based on target protocol
    - creating connections to the target process
    - sending/receiving packets to the target process
    '''
    def __init__(self, proto, host, port, src_ip, src_port, seed):
        '''
        handles the creation of a network connection for the fuzzing session and returns the connection
        '''
        self.proto = proto
        self.host = host
        self.target_port = port
        self.source_ip = src_ip
        self.source_port = src_port
        self.seed = seed
        self.addr = None
        supported_protocols = ['tcp','udp','tls','L2raw']
        if self.proto not in supported_protocols:
            # TODO: after moving print_error to ./util/, call it here
            print("[ERROR] The protocol specified in the .fuzzer file is not currently supported.\nIf you'd like, you can submit an issue or a PR for support!")
            sys.exit(0)

        # determine format of address to use based on protocol
        self._get_addr()

        if self.proto == 'tcp':
            self._connect_to_tcp_socket()
        elif self.proto == 'udp':
            _connect_to_udp_socket()
        elif self.proto == 'tls':
            _connect_to_tls_socket()
        # must be a raw socket since we already checked if protocol was supported
        else :
            _connect_to_raw_socket()

    def send_packet(self, data: bytearray, timeout: float):
        '''
        uses the connection to the target process and outbound data packet (byteArray), sends it out.
        If debug mode is enabled, we print out the raw bytes
        '''
        self._connection.settimeout(timeout)
        if self._connection.type == socket.SOCK_STREAM:
            self._connection.send(data)
        else:
            self._connection.sendto(data, self.addr)

        print("\tSent %d byte packet" % (len(data)))


    def receive_packet(self, bytes_to_read: int, timeout):
        read_buf_size = 4096
        self._connection.settimeout(timeout)

        if self._connection.type == socket.SOCK_STREAM or self._connection.type == socket.SOCK_DGRAM or self._connection.type == socket.SOCK_RAW:
            response = bytearray(self._connection.recv(read_buf_size))
        else:
            response, self.addr = bytearray(self._connection.recvfrom(read_buf_size))
        
        if len(response) == 0:
            # If 0 bytes are recv'd, the server has closed the connection
            # per python documentation
            # FIXME: import this
            raise ConnectionClosedException("Server has closed the connection")
        if bytes_to_read > read_buf_size:
            # If we're trying to read > 4096, don't actually bother trying to guarantee we'll read 4096
            # Just keep reading in 4096 chunks until we should have read enough, and then return
            # whether or not it's as much data as expected
            i = read_buf_size
            while i < bytes_to_read:
                response += bytearray(self._connection.recv(read_buf_size))
                i += read_buf_size
                
        print("\tReceived %d bytes" % (len(response)))
        return response

    def _connect_to_tcp_socket(self):
        # create, bind, and connect to socket
        self._connection = socket.socket(self.socket_family, socket.SOCK_STREAM)
        self._bind_to_interface()
        self._connection.connect(self.addr)

    def _connect_to_udp_socket(self):
        self._connection = socket.socket(self.socket_family, socket.SOCK_DGRAM)
        self._bind_to_interface()

    def _connect_to_tls_socket(self):
        try:
            _create_unverified_https_context = ssl._create_unverified_context
        except AttributeError:
            # Legacy Python that doesn't verify HTTPS certificates by default
            pass
        else:
            # Handle target environment that doesn't support HTTPS verification
            ssl._create_default_https_context = _create_unverified_https_context
        tcp_connection = socket.socket(self.socket_family, socket.SOCK_STREAM)
        self._connection = ssl.wrap_socket(tcp_connection)
        self._bind_to_interface()
        self._connection.connect(self.addr)

    def _connect_toraw_socket(self):
        self._connection = socket.socket(self.socket_family, socket.SOCK_RAW, 0x0300)
        _bind_to_interface()

    def _get_addr(self):
        '''
        using the host parameter and protocol type, determines which format of address to use
        and calls message_processor.preConnect if proto is not L2raw
        '''
        self.socket_family = None
        if self.proto == 'L2raw':
            self.addr = (self.host,0)
            self.socket_family = socket.AF_PACKET
        else:
            addrs = socket.getaddrinfo(self.host, self.port)
            self.host = addrs[0][4][0]
            if self.host == "::1":
                self.host = "127.0.0.1"
            
            # cheap testing for ipv6/ipv4/unix
            # don't think it's worth using regex for this, since the user
            # will have to actively go out of their way to subvert this.
            if "." in self.host:
                self.socket_family = socket.AF_INET
                self.addr = (self.host, self.port)
            elif ":" in self.host:
                self.socket_family = socket.AF_INET6 
                self.addr = (self.host, self.port)
            else:
                self.socket_family = socket.AF_UNIX
                self.addr = (self.host)
            #just in case filename is like "./asdf" !=> af_inet
            if "/" in self.host:
                self.socket_family = socket.AF_UNIX
                self.addr = (self.host)


    def _bind_to_interface():
        if self.proto == 'L2raw':
            self._connection.bind(self.addr)
        else:
            if self.source_port != -1:
                # Only support right now for tcp or udp, but bind source port address to something
                # specific if requested
                if self.source_ip != "" or self.source_ip != "0.0.0.0":
                    self._connection.bind((self.source_ip, self.source_port))
                else:
                    # User only specified a port, not an IP
                    self._connection.bind(('0.0.0.0', self.source_port))
            elif self.source_ip != "" and self.source_ip != "0.0.0.0":
                # No port was specified, so 0 should auto-select
                self._connection.bind((self.source_ip, 0))






