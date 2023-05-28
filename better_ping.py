import errno
import socket
import struct
import sys
import threading
import time

from ping import ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST
from watchdog import create_watchdog_tcp_socket

# constants
WATCHDOG_PORT = 3000
WATCHDOG_IP = 'localhost'

# global
host = 0
seq = 0


def calculate_checksum(packet) -> int:
    """
    the code provided in the course
    :param packet: the packet that calculated with the checksum
    :return: calculated checksum
    """
    """
    :param packet: 
    :return: 
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


# Create an ICMP packet
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


# Send an ICMP packet to the specified host
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


def receive_ping(better_ping_socket: socket.socket):
    """
    Receives and processes ICMP ping reply packets.
    :param receive_socket: Raw socket for receiving packets
    :return: Formatted statistics string or 0
    """
    start_time = time.time()
    # not getting anything not blocking the main thread
    better_ping_socket.setblocking(False)

    packet = None
    address = None

    try:
        packet, address = better_ping_socket.recvfrom(1024)

    except socket.error as e:
        # if error occurs cause didn't receive anything
        if e.errno == errno.EWOULDBLOCK:
            better_ping_socket.setblocking(True)
            return 0

    icmp_header = packet[20:28]

    # reads and convert the given back packet data
    respond_type, code, checksum, p_id, seq_number = struct.unpack(
        "bbHHh", icmp_header)
    if respond_type == ICMP_ECHO_REPLY:
        better_ping_socket.setblocking(True)
        return f'{len(packet[28:])} bytes from {address[0]} icmp_seq={int(seq_number / 256)}' \
               f' ttl={packet[8]} time={(time.time() - start_time) * 1000:.3f} ms'


def better_ping_flow(better_ping_socket, watchdog_thread) -> None:
    global host
    host = sys.argv[1]
    raw_socket = None
    try:
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    except socket.error:
        print('Error: Failed to create socket')
        exit(1)

    first_send = True
    status = True
    try:
        while watchdog_thread.is_alive():
            data, packet = create_packet()
            send_ping(raw_socket, packet)
            if first_send is True:
                print(f'PING', host, f'({host})', f'{len(data)} data bytes')
                first_send = False
            # if got a reply - sends alive message to the watchdog
            if status is True:
                better_ping_socket.send("ping".encode())
            statistics = receive_ping(raw_socket)
            if statistics != 0:
                print(statistics)
                status = True
            if statistics == 0:
                time.sleep(1)
                status = False
                continue
            time.sleep(1)
        print(f"server {host} cannot be reached.")
    except KeyboardInterrupt:
        print('\nPing stopped, closing program')
    finally:
        better_ping_socket.close()
        raw_socket.close()
        exit(1)


def create_tcp_socket(watchdog_thread) -> None:
    ping_socket = None
    try:
        ping_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ping_socket.connect((WATCHDOG_IP, WATCHDOG_PORT))
        better_ping_flow(ping_socket, watchdog_thread)
    except socket.error:
        print(f"Socket Error {socket.error}")
        if ping_socket is not None:
            ping_socket.close()
        exit(1)


def better_ping_program() -> None:
    if len(sys.argv) != 2:
        print('Usage: sudo python3 better_ping.py <ip>')
        exit(1)

    # creates watchdog thread, makes it a daemon thread and activates it
    watchdog_thread = threading.Thread(target=create_watchdog_tcp_socket)
    watchdog_thread.daemon = True
    watchdog_thread.start()

    # waits for watchdog's TCP to initialize
    time.sleep(1)
    create_tcp_socket(watchdog_thread)


if __name__ == '__main__':
    better_ping_program()
