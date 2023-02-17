import socket


def connectDHCP():
    # define the DHCP server address and port
    SERVER_ADDRESS_DHCP = ('127.0.0.1', 100)

    # create a TCP socket
    DHCP_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # connect to server
    DHCP_server.connect(SERVER_ADDRESS_DHCP)

    # sending request to the server
    DHCP_server.send(bytes("please give me an IP", "utf-8"))

    # get the response
    answer = DHCP_server.recv(1024)
    answer = answer.decode("utf-8")
    print(answer)
    return answer

    # DHCP handling

    # connectDHCP()


# DNS handling

def connectDNS():
    # define the DNS server address and port
    SERVER_ADDRESS_DNS = ('127.0.0.1', 5354)

    # create a UDP socket
    client_socket_DNS = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    while True:
        # get a domain name from the user
        domain = input('Enter a domain name: ')

        # send a DNS query to the server
        client_socket_DNS.sendto(domain.encode(), SERVER_ADDRESS_DNS)

        # receive a response from the DNS server
        response, server_address = client_socket_DNS.recvfrom(1024)

        # print the response
        print(response.decode())
