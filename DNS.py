import socket

MAX_BYTES = 1024
IP = '127.0.0.1'
PORT = 1026

# List of domains and their IP address (All local)
Domains = {
    'ftplace.org': '192.0.0.1',
    'google.com': '192.0.0.1',
    'Outlook.net': '192.0.0.1',
}

if __name__ == '__main__':
    print("(*) Starting DNS server...")

    # Create a UDP socket.
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Bind an ip and a port to the socket.
    try:
        server_socket.bind((IP, PORT))
        print("(*) Binding was successful.")
    except socket.error as e:
        print("(-) Binding failed:", e)
        exit(1)
    print("(*) Listening...")

    # Keep listening.
    while True:
        # Receive a message from the client.
        data, client_address = server_socket.recvfrom(MAX_BYTES)
        # Extract the DNS request.
        dns_request = data.decode().strip()
        # If the DNS holds the answer then send the client the IP address.
        if dns_request in Domains:
            response = Domains[dns_request]
            print("(+) DNS query was successful.")
        else:
            response = 'No matches'
            print("(-) DNS query failed.")
        # Send response to the client.
        server_socket.sendto(response.encode(), client_address)
