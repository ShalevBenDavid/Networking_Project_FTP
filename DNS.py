import socket


# define the host and port to bind the server socket
HOST = '127.0.0.1'
PORT = 5354

# create a UDP socket and bind it to the specified host and port
server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind((HOST, PORT))

# define a dictionary of domain names and their corresponding IP addresses
records = {
    'ftplace.com': '192.0.2.1',
    'www.ftplace.com': '192.0.2.1',
    'example.com': '176.4.2.2',
    'www.example.com': '176.4.2.2'
}

print("Listening in port 5354...")

while True:
    # receive a message from the client
    data, client_address = server_socket.recvfrom(1024)
    query = data.decode().strip()

    # if the query matches one of the domain names in our records, send back the IP address
    if query in records:
        response = records[query]
    else:
        response = 'not found'

    # send the response back to the client
    server_socket.sendto(response.encode(), client_address)
