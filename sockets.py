# packets.py
import struct
import socket

def _calculate_checksum(msg: bytes) -> int:
    """
    Calculates the 16-bit one's complement checksum for a given message (bytes).
    This is used for IP, ICMP, and TCP headers.
    """
    s = 0
    # Sum 16-bit words
    for i in range(0, len(msg), 2):
        # For odd-length messages, the last byte is padded with a zero
        if i + 1 < len(msg):
            w = (msg[i] << 8) + msg[i+1]
        else:
            w = msg[i] << 8
        s += w
    
    # Add carries until the result is 16 bits
    while (s >> 16):
        s = (s & 0xFFFF) + (s >> 16)
    
    # One's complement and return
    return ~s & 0xFFFF

# Ethernet Frame Header
class EthernetHeader:
    def __init__(self, dst_mac: str, src_mac: str, eth_type: int = 0x0800):
        self.dst_mac = dst_mac
        self.src_mac = src_mac
        self.eth_type = eth_type

    def pack(self) -> bytes:
        dst = bytes.fromhex(self.dst_mac.replace(':', ''))
        src = bytes.fromhex(self.src_mac.replace(':', ''))
        return struct.pack('!6s6sH', dst, src, self.eth_type)

# ARP Header
class ArpHeader:
    def __init__(self, hw_type=1, proto_type=0x0800, hw_size=6, proto_size=4, opcode=1, 
                 src_mac='00:00:00:00:00:00', src_ip='0.0.0.0', 
                 dst_mac='00:00:00:00:00:00', dst_ip='0.0.0.0'):
        self.hw_type = hw_type
        self.proto_type = proto_type
        self.hw_size = hw_size
        self.proto_size = proto_size
        self.opcode = opcode  # 1=request, 2=reply
        self.src_mac = src_mac
        self.src_ip = src_ip
        self.dst_mac = dst_mac
        self.dst_ip = dst_ip

    def pack(self) -> bytes:
        src_mac_bytes = bytes.fromhex(self.src_mac.replace(':', ''))
        dst_mac_bytes = bytes.fromhex(self.dst_mac.replace(':', ''))
        src_ip_bytes = socket.inet_aton(self.src_ip)
        dst_ip_bytes = socket.inet_aton(self.dst_ip)
        return struct.pack('!HHBBH6s4s6s4s',
                           self.hw_type, self.proto_type, self.hw_size, self.proto_size,
                           self.opcode, src_mac_bytes, src_ip_bytes, dst_mac_bytes, dst_ip_bytes)

# IPv4 Header
class IPHeader:
    def __init__(self, src_ip: str = '0.0.0.0', dst_ip: str = '0.0.0.0', ttl: int = 64, proto: int = socket.IPPROTO_TCP):
        self.version = 4
        self.ihl = 5  # Header Length in 32-bit words
        self.tos = 0
        self.tot_len = 20  # Kernel will fill this if 0, otherwise it's header + data
        self.id = 54321
        self.frag_off = 0
        self.ttl = ttl
        self.proto = proto
        self.check = 0  # To be calculated
        self.src_ip = src_ip
        self.dst_ip = dst_ip

    def pack(self) -> bytes:
        ver_ihl = (self.version << 4) + self.ihl
        src_ip_bytes = socket.inet_aton(self.src_ip)
        dst_ip_bytes = socket.inet_aton(self.dst_ip)
        
        # Pack header with a zero checksum
        header_no_check = struct.pack('!BBHHHBBH4s4s',
                                     ver_ihl, self.tos, self.tot_len, self.id, self.frag_off, 
                                     self.ttl, self.proto, 0, src_ip_bytes, dst_ip_bytes)
        
        # Calculate checksum
        self.check = _calculate_checksum(header_no_check)
        
        # Repack header with the correct checksum
        return struct.pack('!BBHHHBBH4s4s',
                           ver_ihl, self.tos, self.tot_len, self.id, self.frag_off, 
                           self.ttl, self.proto, self.check, src_ip_bytes, dst_ip_bytes)

# ICMP Header
class ICMPHeader:
    def __init__(self, icmp_type: int = 8, code: int = 0, id: int = 0, seq: int = 0):
        self.type = icmp_type
        self.code = code
        self.chksum = 0 # To be calculated
        self.id = id
        self.seq = seq

    def pack(self) -> bytes:
        # Pack header with a zero checksum
        header_no_check = struct.pack('!BBHHH', self.type, self.code, 0, self.id, self.seq)
        self.chksum = _calculate_checksum(header_no_check)
        
        # Repack with correct checksum
        return struct.pack('!BBHHH', self.type, self.code, self.chksum, self.id, self.seq)

# TCP Header
class TCPHeader:
    def __init__(self, src_port=12345, dst_port=80, seq=0, ack_seq=0, flags=2, window=8192):
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq = seq
        self.ack_seq = ack_seq
        self.data_offset = 5  # Header length in 32-bit words
        self.flags = flags  # Default is SYN flag (2)
        self.window = window
        self.check = 0 # To be calculated
        self.urg_ptr = 0

    def pack(self, src_ip: str, dst_ip: str) -> bytes:
        offset_res = (self.data_offset << 4) + 0
        
        # Pack the TCP header with a zero checksum
        tcp_header_no_check = struct.pack('!HHLLBBHHH',
                                 self.src_port, self.dst_port, self.seq, self.ack_seq,
                                 offset_res, self.flags, self.window, 0, self.urg_ptr)

        # Create the pseudo-header for checksum calculation
        pseudo_header = struct.pack('!4s4sBBH',
                                    socket.inet_aton(src_ip),
                                    socket.inet_aton(dst_ip),
                                    0, socket.IPPROTO_TCP, len(tcp_header_no_check))
        
        # Calculate checksum on the pseudo-header and TCP segment
        self.check = _calculate_checksum(pseudo_header + tcp_header_no_check)

        # Repack the header with the correct checksum
        return struct.pack('!HHLLBBHHH',
                           self.src_port, self.dst_port, self.seq, self.ack_seq,
                           offset_res, self.flags, self.window, self.check, self.urg_ptr)

def create_syn_packet(src_ip: str, dst_ip: str, dst_port: int, src_port: int = 12345) -> bytes:
    """
    Creates a complete TCP SYN packet (IP Header + TCP Header).
    A raw socket is required to send this packet.
    """
    # 1. Create the TCP header
    tcp_header = TCPHeader(src_port=src_port, dst_port=dst_port, flags=2) # Flag 2 is SYN
    tcp_packet = tcp_header.pack(src_ip, dst_ip)

    # 2. Create the IP header
    ip_header = IPHeader(src_ip=src_ip, dst_ip=dst_ip, proto=socket.IPPROTO_TCP)
    ip_header.tot_len = 20 + len(tcp_packet) # IP header len (20) + TCP header len
    ip_packet = ip_header.pack()

    # 3. Return the full packet by concatenating the headers
    return ip_packet + tcp_packet

