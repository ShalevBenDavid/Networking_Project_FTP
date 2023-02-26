import socket

import FTP_client

CLIENT_PORT = 78120
SERVER_PORT = 41330
LOCAL_IP = '127.0.0.1'


def connectToServerTCP(domain):
    domain = FTP_client.getDomain()
    print("(*) Starting TCP Server ...")
    # Create a TCP socket.
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Bind an ip and a port to the socket.
    try:
        server_socket.bind((LOCAL_IP, SERVER_PORT))
        print("(+) Binding was successful.")
    except socket.error as e:
        print("(-) Binding failed:", e)
        exit(1)
    # Make server listen for incoming connections.
    server_socket.listen(True)
    print("(*) Listening...")

    # Keep Listening.
    while True:
        # Accept a connection from the client.
        try:
            client, address = server_socket.accept()
            print("(+) Connection was successful.", address)
        except socket.error as e:
            print("(-) Connection failed:", e)
            exit(1)
