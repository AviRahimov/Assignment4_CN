"""
This script implements a better ping functionality using ICMP and a watchdog process with multithreading.
It allows sending ICMP echo request packets to a specified IP address and receiving ICMP echo reply packets.
The script also communicates with a watchdog process over TCP with port 3000.

The script consists of the following functions:
"""
import socket
import struct
import sys
import threading
import time

from ping import ICMP_ECHO_REQUEST, calculate_checksum, receive_ping, send_ping
from watchdog import create_watchdog_tcp_socket

# Constants
WATCHDOG_PORT = 3000
WATCHDOG_IP = 'localhost'

# Global variables
destination_host = 0
sequence_number = 0


def create_icmp_echo_request_packet():
    """
    Creates an ICMP echo request packet.

    return:
        A tuple containing the packet data and the raw packet.
    """
    global sequence_number
    sequence_number += 1

    # Generate a dummy header with a 0 checksum
    header = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, 0, 0, 0, sequence_number)

    # Generate a timestamp for the data
    data = b'Create better_ping request'

    # Calculate the checksum for the packet
    checksum = calculate_checksum(header + data)

    # Create the packet with the correct checksum
    header = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, 0, checksum, 0, sequence_number)
    packet = header + data

    return data, packet


def run_better_ping_flow(ping_socket, watchdog_thread):
    """
    The main flow for sending and receiving ICMP echo request/reply packets.

    param:
        ping_socket: The socket for communication with the watchdog process.
        watchdog_thread: The thread of the watchdog process.

    return:
        None
    """
    global destination_host
    destination_host = sys.argv[1]
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
            data, packet = create_icmp_echo_request_packet()
            send_ping(raw_socket, packet)
            bytes_length = len(data)
            if first_send:
                print(f'PING {destination_host} ({destination_host}) {bytes_length} data bytes')
                first_send = False

            # If a reply is received, send "hello" message to the watchdog
            if status:
                ping_socket.send("hello".encode())

            statistics = receive_ping(raw_socket)

            if statistics != 0:
                print(statistics)
                status = True

            elif statistics == 0:
                time.sleep(1)
                status = False
                continue

            time.sleep(1)

        print(f"Server {destination_host} cannot be reached.")

    except KeyboardInterrupt:
        print('\nPing stopped, closing program')

    finally:
        ping_socket.close()
        raw_socket.close()
        exit(1)


def create_tcp_socket(watchdog_thread):
    """
    Creates a TCP socket and initiates the better_ping flow.

    param:
        watchdog_thread: The thread of the watchdog process.

    return:
        None
    """
    ping_socket = None

    try:
        ping_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ping_socket.connect((WATCHDOG_IP, WATCHDOG_PORT))
        run_better_ping_flow(ping_socket, watchdog_thread)

    except socket.error:
        print(f"Socket Error {socket.error}")
        if ping_socket is not None:
            ping_socket.close()
        exit(1)


def start_better_ping():
    """
    The entry point for starting the better ping process.

    return:
        None
    """
    if len(sys.argv) != 2:
        print('Usage: sudo python3 better_ping.py <ip>')
        exit(1)

    # Create watchdog thread, make it a daemon thread i.e. the program can exit even if this thread is still running.
    # then, starting the thread
    watchdog_thread = threading.Thread(target=create_watchdog_tcp_socket)
    watchdog_thread.daemon = True
    watchdog_thread.start()

    # The purpose is to allow some time for the watchdog's TCP initialization before proceeding.
    time.sleep(1)
    # Create TCP Socket and Start Better Ping Flow:
    create_tcp_socket(watchdog_thread)


if __name__ == '__main__':
    start_better_ping()
