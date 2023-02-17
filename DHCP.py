import socket

MAX_BYTES = 1024
IP = "127.0.0.1"
PORT = 1025

if __name__ == '__main__':
    print("(*) Starting DHCP server...")

    # Create a TCP socket.
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Bind an ip and a port to the socket.
    server_socket.bind((IP, PORT))
    print("(*) Binding was successful.")
    # Make server listen for incoming connections.
    server_socket.listen(True)
    print("(*) Listening...")

    # Keep listening.
    while True:
        # Accept a connection from the client.
        try:
            client, address = server_socket.accept()
            print("(+) Connection was successful.", address)
        except socket.error as e:
            print("(-) Connection failed:", e)
            exit(1)
        # Receive the DHCP request from the client.
        dhcp_request = client.recv(MAX_BYTES).decode("utf-8")
        print("(+) Client request: ", dhcp_request)
        client.send("Your IP is : 184.10.10.50".encode())
        # Closing TCP connection.
        print("(*) Closing connection with client.", address)
        client.close()
