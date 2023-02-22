import socket

MAX_BYTES = 1024
IP = "127.0.0.1"
PORT = 1025


def offer_get():
    OP = bytes([0x02])
    HTYPE = bytes([0x01])
    HLEN = bytes([0x06])
    HOPS = bytes([0x00])
    XID = bytes([0x39, 0x03, 0xF3, 0x26])
    SECS = bytes([0x00, 0x00])
    FLAGS = bytes([0x00, 0x00])
    CIADDR = bytes([0x00, 0x00, 0x00, 0x00])
    YIADDR = bytes([0xC0, 0xA8, 0x01, 0x64])  # 192.168.1.100
    SIADDR = bytes([0xC0, 0xA8, 0x01, 0x01])  # 192.168.1.1
    GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
    CHADDR1 = bytes([0x00, 0x05, 0x3C, 0x04])
    CHADDR2 = bytes([0x8D, 0x59, 0x00, 0x00])
    CHADDR3 = bytes([0x00, 0x00, 0x00, 0x00])
    CHADDR4 = bytes([0x00, 0x00, 0x00, 0x00])
    CHADDR5 = bytes(192)
    Magiccookie = bytes([0x63, 0x82, 0x53, 0x63])
    DHCPOptions1 = bytes([53, 1, 2])  # DHCP Offer
    DHCPOptions2 = bytes([1, 4, 0xFF, 0xFF, 0xFF, 0x00])  # 255.255.255.0 subnet mask
    DHCPOptions3 = bytes([3, 4, 0xC0, 0xA8, 0x01, 0x01])  # 192.168.1.1 router
    DHCPOptions4 = bytes([51, 4, 0x00, 0x01, 0x51, 0x80])  # 86400s(1 day) IP address lease time
    DHCPOptions5 = bytes([54, 4, 0xC0, 0xA8, 0x01, 0x01])  # DHCP server

    package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR + YIADDR + SIADDR + GIADDR + CHADDR1 + CHADDR2 + CHADDR3 + CHADDR4 + CHADDR5 + Magiccookie + DHCPOptions1 + DHCPOptions2 + DHCPOptions3 + DHCPOptions4 + DHCPOptions5

    return package


def pack_get():
    OP = bytes([0x02])
    HTYPE = bytes([0x01])
    HLEN = bytes([0x06])
    HOPS = bytes([0x00])
    XID = bytes([0x39, 0x03, 0xF3, 0x26])
    SECS = bytes([0x00, 0x00])
    FLAGS = bytes([0x00, 0x00])
    CIADDR = bytes([0x00, 0x00, 0x00, 0x00])
    YIADDR = bytes([0xC0, 0xA8, 0x01, 0x64])
    SIADDR = bytes([0xC0, 0xA8, 0x01, 0x01])
    GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
    CHADDR1 = bytes([0x00, 0x05, 0x3C, 0x04])
    CHADDR2 = bytes([0x8D, 0x59, 0x00, 0x00])
    CHADDR3 = bytes([0x00, 0x00, 0x00, 0x00])
    CHADDR4 = bytes([0x00, 0x00, 0x00, 0x00])
    CHADDR5 = bytes(192)
    Magiccookie = bytes([0x63, 0x82, 0x53, 0x63])
    DHCPOptions1 = bytes([53, 1, 5])  # DHCP ACK(value = 5)
    DHCPOptions2 = bytes([1, 4, 0xFF, 0xFF, 0xFF, 0x00])  # 255.255.255.0 subnet mask
    DHCPOptions3 = bytes([3, 4, 0xC0, 0xA8, 0x01, 0x01])  # 192.168.1.1 router
    DHCPOptions4 = bytes([51, 4, 0x00, 0x01, 0x51, 0x80])  # 86400s(1 day) IP address lease time
    DHCPOptions5 = bytes([54, 4, 0xC0, 0xA8, 0x01, 0x01])  # DHCP server

    package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR + YIADDR + SIADDR + GIADDR + CHADDR1 + CHADDR2 + CHADDR3 + CHADDR4 + CHADDR5 + Magiccookie + DHCPOptions1 + DHCPOptions2 + DHCPOptions3 + DHCPOptions4 + DHCPOptions5

    return package


if __name__ == '__main__':
    print("(*) Starting DHCP server...")

    # Create a TCP socket.
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Make the ports reusable.
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Make the socket handle broadcast IP addresses.
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    # Bind an ip and a port to the socket.
    try:
        server_socket.bind((IP, PORT))
        print("(+) Binding was successful.")
    except socket.error as e:
        print("(-) Binding failed:", e)
        exit(1)
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
        dhcp_request = client.recv(MAX_BYTES)#.decode("utf-8")
        print("(+) Client request: ", dhcp_request)
        # Get the DHCP offer for the client and send him.
        data = offer_get()
        print("Send DHCP offer.")
        client.send(data)
        while True:
            try:
                print("Wait DHCP request.")
                data = client.recv(MAX_BYTES)#.decode("utf-8")
                print("Receive DHCP request.")
                print(data)

                print("Send DHCP pack.\n")
                data = pack_get()
                client.send(data)
                break
            except:
                raise

        client.send("Your IP is : 184.10.10.50".encode())
        # Closing TCP connection.
        print("(*) Closing connection with client.", address)
        client.close()
