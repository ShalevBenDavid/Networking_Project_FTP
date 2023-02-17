import socket

MAX_BYTES = 1024
DHCP_PORT = 1025
DNS_PORT = 1026
LOCAL_IP = '127.0.0.1'


def connectDHCP():
    print("Connecting to DHCP server...")

    # Assign the DHCP server's address and port.
    server_address_dhcp = (LOCAL_IP, DHCP_PORT)
    # Create a TCP socket to connect to the DHCP.
    dhcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Connect to the DHCP server.
    dhcp_server.connect(server_address_dhcp)
    # Send out a DHCP request to the server.
    dhcp_server.send(bytes("Please give me an IP", "utf-8"))
    # Receive a DHCP answer from the server.
    answer = dhcp_server.recv(MAX_BYTES).decode("uft-8")
    # Return the answer from the DHCP.
    return answer


def connectDNS():
    print("Connecting to DNS server...")

    # Assign the DNS server's address and port.
    server_address_dns = (LOCAL_IP, DNS_PORT)
    # Create a UDP socket to connect to the DNS.
    client_socket_dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        # Receive a domain name from the user.
        domain_name = input('Enter the domain name: ')
        # Send out a DNS query to the server.
        client_socket_dns.sendto(domain_name.encode(), server_address_dns)
        # Receive a DNS answer from the server.
        answer, server_address = client_socket_dns.recvfrom(MAX_BYTES)
        # Return the answer from the DNS.
        return answer


if __name__ == '__main__':
    connectDHCP()
    connectDNS()
