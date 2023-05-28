import socket

# Constant variable
PORT = 3000
IP = ''
TIMER = 10

def create_watchdog_tcp_socket() -> None:
    """
    Creates a watchdog TCP socket and opens the watchdog timer.
    """
    try:
        # Create the watchdog TCP socket and make the port reusable
        watchdog = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        watchdog.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        watchdog.bind((IP, PORT))
        watchdog.listen(1)
        print("Watchdog Is Ready")

        while True:
            better_ping_socket, address = watchdog.accept()
            print(f"PING Program connected...")
            status = watchdog_timer(better_ping_socket)
            if status == -1:
                watchdog.close()
                better_ping_socket.close()
                exit(2)

    except socket.error:
        print(f"Socket Error: {socket.error}")
        exit(1)


def watchdog_timer(better_ping_socket):
    """
    Opens a timer for 10 seconds and resets it if a life signal is received.
    :param better_ping_socket: The socket to receive life signals from
    :return: -1 if no life signal is received for 10 seconds
    """
    better_ping_socket.settimeout(TIMER)
    try:
        while True:
            better_ping_socket.recv(5)
    except socket.timeout:
        return -1


if __name__ == '__main__':
    create_watchdog_tcp_socket()
