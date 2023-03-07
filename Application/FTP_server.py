import signal

from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP

CLIENT_PORT = 20781
SERVER_PORT = 30413
PACKET_SIZE = 1024
WINDOW_SIZE = 5
TIMEOUT = 5  # In seconds
LOCAL_IP = '127.0.0.1'


def uploadRUDP():
    print("\n*********************************")
    print("(*) Establishing a connection...")
    # Sending SYN-ACK message to client.
    server_socket.sendto("SYN-ACK".encode(), client_address)
    print("(+) Sent SYN-ACK message.")
    # Receiving ACK message to complete establishing a connection.
    msg, addr = server_socket.recvfrom(PACKET_SIZE)
    print("(+) Connection established with: ", addr)


def downloadRUDP():
    print("\n*********************************")


# Close the socket.
def closeSocket():
    server_socket.close()


if __name__ == "__main__":
    # Starting server.
    print("(*) Starting application server...")
    # Create UDP socket to check which protocol to use.
    protocol_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        protocol_socket.bind((LOCAL_IP, SERVER_PORT))
        print("(+) Binding was successful with protocol socket.")
    except socket.error as e:
        print("(-) Binding failed with protocol socket:", e)
        exit(1)
    # Getting from the client the type of the communication.
    protocol_choice, addr = protocol_socket.recvfrom(PACKET_SIZE)

    # Close the socket.
    protocol_socket.close()

# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> RUDP PROTOCOL HANDLE <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< #
    if protocol_choice.decode() == "RUDP":
        # Create UDP socket.
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Make the ports reusable.
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Representation of the client's info.
        client_address = ('localhost', CLIENT_PORT)
        # Binding address and port to the socket.
        try:
            server_socket.bind((LOCAL_IP, SERVER_PORT))
            print("(+) Binding was successful.")
        except socket.error as e:
            print("(-) Binding failed:", e)
            exit(1)
        print("(*) Waiting for domain name to connect...")
        domain, address = server_socket.recvfrom(PACKET_SIZE)
        print("(+) Connected to : " + domain.decode())
        while True:
            print("(*) Listening...")
            request, address = server_socket.recvfrom(PACKET_SIZE)
            if request.decode() == "upload":
                uploadRUDP()
            if request.decode() == "download":
                downloadRUDP()
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> TCP PROTOCOL HANDLE <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< #

    if protocol_choice.decode() == "TCP":
        # Create TCP socket.
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Make the ports reusable.
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Representation of the client's info.
        client_address = ('localhost', CLIENT_PORT)
        # Binding address and port to the socket.
        try:
            server_socket.bind((LOCAL_IP, SERVER_PORT))
            print("(+) Binding was successful.")
        except socket.error as e:
            print("(-) Binding failed:", e)
            exit(1)
        # Allow 100 people at max to connect to the server.
        server_socket.listen(100)
        print("(*) Waiting for domain name to connect...")
        domainTemp, addressTemp = server_socket.accept()
        domain, address = domainTemp.recvfrom(PACKET_SIZE)
        print("(+) Connected to : " + domain.decode())
        while True:
            print("(*) Listening...")
            request, address = server_socket.recvfrom(PACKET_SIZE)
            if request.decode() == "upload":
                uploadRUDP()
            if request.decode() == "download":
                downloadRUDP()
    else:
        print("BABA")