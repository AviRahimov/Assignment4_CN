import socket
import sys
import time
import struct

# ICMP message types used for identifying reply and destination unreachable packets.
ICMP_ECHO_REPLY = 0
ICMP_ECHO_REQUEST = 8
ICMP_DEST_UNREACHABLE = 3

host = ''  # Stores the IP address or hostname to ping.
cmp_seq_number = 0  # Stores the current sequence number for ICMP packets.


def calculate_checksum(packet) -> int:
    """
    Calculates the checksum of the packet.
    :param packet: Packet to calculate checksum for
    :return: Calculated checksum
    """
    checksum = 0
    count_to = (len(packet) // 2) * 2
    for i in range(0, count_to, 2):
        checksum += (packet[i] << 8) + packet[i + 1]
    if count_to < len(packet):
        checksum += packet[len(packet) - 1] << 8
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum += checksum >> 16
    return (~checksum) & 0xFFFF


def create_packet(payload_size: int) -> bytes:
    """
    Creates an ICMP packet with the specified payload size.
    :param payload_size: Size of the payload
    :return: ICMP packet
    """
    global cmp_seq_number
    cmp_seq_number += 1
    packet = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, 0, 0, 0, cmp_seq_number)  # Create the ICMP header
    data = b'P' * payload_size  # Create the payload data
    packet += data
    checksum = calculate_checksum(packet)
    # creates an header with checksum
    header = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, 0, checksum, 0, cmp_seq_number)
    packet = header + data
    return packet


def send_ping(sock, packet):
    """
    Sends the ICMP packet to the destination.
    :param sock: Raw socket
    :param packet: ICMP packet
    """
    try:
        sock.sendto(packet, (host, 1))
    except socket.error:
        print(f"There is an error in {sock} socket by sending {packet} packet")
        sock.close()
        exit(1)


def receive_ping(receive_socket: socket.socket):
    """
    Receives and processes ICMP ping reply packets.
    :param receive_socket: Raw socket for receiving packets
    :return: Formatted statistics string or None
    """
    receive_socket.settimeout(1)
    try:
        start_time = time.time()
        received_packet, addr = receive_socket.recvfrom(1024)
        end_time = time.time()

        icmp_header = received_packet[20:28]  # Extract ICMP header fields
        icmph = struct.unpack('bbHHh', icmp_header)
        icmp_type = icmph[0]

        if icmp_type == ICMP_ECHO_REPLY:
            ttl = received_packet[8]
            packet_length = len(received_packet) - 28  # Calculate packet length
            elapsed_time = (end_time - start_time) * 1000
            return f'{packet_length} bytes from {addr[0]} icmp_seq={cmp_seq_number} ttl={ttl} time={elapsed_time:.3f} ms'

        elif icmp_type == ICMP_DEST_UNREACHABLE:
            print(f"Host {host} unreachable")
            return None

    except socket.timeout:
        print("Timeout error")
        receive_socket.close()
        exit(1)


def ping():
    """
    Initiates the ping flow by creating a raw socket and continuously sending/receiving ICMP packets.
    """
    global host, raw_socket
    if len(sys.argv) != 2:
        print('Usage: sudo python3 ping.py <ip>')
        exit(1)

    host = sys.argv[1]  # IP address user entered

    try:
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)  # Open raw socket

        first_send = True  # Flag for the first sending

        while True:
            packet = create_packet(12)

            if first_send:
                print(f'PING {host} ({host}) {len(packet) - 8} data bytes')
                first_send = False

            send_ping(raw_socket, packet)

            statistics = receive_ping(raw_socket)

            if statistics is not None:
                print(statistics)
            else:
                print('Request timed out')

            time.sleep(1)

    except KeyboardInterrupt:
        print('\nPing stopped, closing program')
    except socket.error:
        print("Failed to create a socket")
    finally:
        raw_socket.close()


ping()
