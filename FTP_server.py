import socket

import FTP_client
from FTP_client import gui

CLIENT_PORT = 78120
SERVER_PORT = 41330
LOCAL_IP = '127.0.0.1'


# Create a UDP socket.
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Make the ports reusable.
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Make the socket handle broadcast IP addresses.
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # Bind an ip and a port to the socket.
        try:
            server_socket.bind((client_ip, SERVER_PORT))
            print("(*) Binding was successful.")
        except socket.error as e:
            print("(-) Binding failed:", e)
            exit(1)
        print("(*) Listening...")

        # Keep listening.
        while True:
            # Receive a message from the client.
            data, client_address = server_socket.recvfrom(1024)
            # Extract the DNS request.
            dns_request = data.decode().strip()
            # If the DNS holds the answer then send the client the IP address.

            # Send response to the client.
            server_socket.sendto(response.encode(), client_address)