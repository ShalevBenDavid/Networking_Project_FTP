import signal

from scapy.all import *
from scapy.layers.inet import IP, UDP

CLIENT_PORT = 20781
SERVER_PORT = 30413
PACKET_SIZE = 4096
WINDOW_SIZE = 5
TIMEOUT = 5  # In seconds
LOCAL_IP = '127.0.0.1'


def rudp_server():
    # Starting server.
    print("(*) Starting application server...")
    # Create UDP socket and bind it to IP address and port
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Make the ports reusable.
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind((LOCAL_IP, SERVER_PORT))
        print("(+) Binding was successful.")
    except socket.error as e:
        print("(-) Binding failed:", e)
        exit(1)
    data, address = server_socket.recvfrom(PACKET_SIZE)
    print("(+) Received message successfully.")
    print("Data is: " + data.decode())

    # Close the socket.
    server_socket.close()


if __name__ == "__main__":
    rudp_server()
