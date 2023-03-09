from time import sleep
from scapy.all import *

MAX_BYTES = 4096
CLIENT_PORT = 20781
SERVER_PORT = 30413
PACKET_SIZE = 1024
WINDOW_SIZE = 5
TIMEOUT = 5  # In seconds
CC_CUBIC = b"cubic"
LOCAL_IP = '127.0.0.1'


# Method to upload a file to the server using RUDP.
def uploadRUDP():
    print("\n<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>")
    print("(*) Establishing a RUDP connection and preparing to upload...")
    # Sending SYN-ACK message to client.
    server_socket.sendto("SYN-ACK".encode(), client_address)
    print("(+) Sent SYN-ACK message.")
    # Receiving ACK message to complete establishing a connection.
    msg, addr = server_socket.recvfrom(PACKET_SIZE)
    print("(+) Connection established with: ", addr)


# Method to send a file to the client using RUDD.
def downloadRUDP():
    print("\n<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>")
    print("(*) Establishing a RUDP connection and preparing to download...")


# Method to upload a file to the server using TCP.
def uploadTCP():
    print("\n<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>")
    print("(*) Establishing a TCP connection and preparing to upload...")
    file_size = int(connection.recv(PACKET_SIZE).decode())
    print("(+) Received the file's size.")
    print("(+) File size:", file_size, "bytes")
    file_name = connection.recv(PACKET_SIZE).decode()
    print("(+) Received the file's name.")
    print("(+) File name:", file_name)
    # Create the file directory (where we want to upload the file).
    file_directory = "../Domains/" + domain.decode() + "/" + file_name
    # ---------------------------------- RECEIVE THE FILE FROM THE CLIENT ----------------------------------#
    with open(file_directory, "wb") as file:
        while True:
            # Read the file's bytes in chunks.
            bytes_to_write = connection.recv(MAX_BYTES)
            # If we are done with sending the file.
            if not bytes_to_write:
                print("(+) Done with uploading file.")
                file.close()
                break
            # Write to the file the bytes we just received
            file.write(bytes_to_write)
    # Close the connection.
    connection.close()


# Method to send a file to the client using TCP.
def downloadTCP():
    print("\n<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>")
    print("(*) Establishing a TCP connection and preparing to download...")
    # Receive the file's name that the client wants to download from the domain.
    file_name = connection.recv(PACKET_SIZE).decode()
    print("(+) File name to download:", file_name)
    # Create the file directory (the location of the requested file).
    file_path = "../Domains/" + domain.decode() + "/" + file_name
    sleep(0.2)
    # ---------------------------------- SEND THE FILE TO THE CLIENT ----------------------------------#
    with open(file_path, "rb") as file:
        print("(*) Sending the file...")
        while True:
            # Read the file's bytes in chunks.
            bytes_to_send = file.read(MAX_BYTES)
            # If we are done with sending the file.
            if not bytes_to_send:
                print("(+) Done with sending file.")
                break
            # Sending the file in chunks.
            connection.send(bytes_to_send)
    # Close the connection.
    connection.close()


if __name__ == "__main__":
    # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> RECEIVE THE PROTOCl <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< #
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
    print("(*) Waiting for the user to choose protocol for communication...")
    # Getting from the client the type of the communication.
    protocol_choice, addr = protocol_socket.recvfrom(PACKET_SIZE)
    # Printing which protocol the user choose.
    print("(*) The user choose to communicate using " + protocol_choice.decode() + ".")
    print("\n*********************************")
    # Close the socket.
    protocol_socket.close()

    # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> RECEIVE THE DOMAIN <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< #
    # Create UDP socket to check what domain to connect.
    domain_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        domain_socket.bind((LOCAL_IP, SERVER_PORT))
        print("(+) Binding was successful with domain socket.")
    except socket.error as e:
        print("(-) Binding failed with domain socket:", e)
        exit(1)
    print("(*) Waiting for the user to enter domain...")
    # Getting from the client the type of the communication.
    domain, addr = domain_socket.recvfrom(PACKET_SIZE)
    # Printing which protocol the user choose.
    print("(+) Connected to : " + domain.decode())
    print("\n*********************************")
    # Close the socket.
    domain_socket.close()

    # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> RUDP PROTOCOL HANDLE <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< #
    if protocol_choice.decode() == "RUDP":
        # Create UDP socket.
        print("(*) Creating the server socket (RUDP)...")
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
        print("(*) Creating the server socket (TCP)...")
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Make the ports reusable.
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Change the CC algorithm (only if using LINUX system).
        # server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_CONGESTION, CC_CUBIC)
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
        try:
            while True:
                print("\n(*) Waiting for request...")
                connection, address = server_socket.accept()
                request = connection.recv(PACKET_SIZE)
                if request.decode() == "upload":
                    print("(+) Client choose to upload.")
                    uploadTCP()
                elif request.decode() == "download":
                    print("(+) Client choose to download.")
                    downloadTCP()
        finally:
            # Closing the server socket.
            server_socket.close()

