from time import sleep

from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, sniff

MAX_BYTES = 4096
DHCP_CLIENT_PORT = 68
DHCP_SERVER_PORT = 67
DNS_CLIENT_PORT = 1024
DNS_SERVER_PORT = 53
CLIENT_PORT = 20781
SERVER_PORT = 30413
PACKET_SIZE = 1024
WINDOW_SIZE = 5
TIMEOUT = 2
LOCAL_IP = '127.0.0.1'
SERVER_ADDRESS = ('localhost', SERVER_PORT)  # A tuple to represent the server.


# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Connect DHCP <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< #
def connectDHCP():
    # -------------------------------- Create a DHCP discover packet -------------------------------- #
    print("(*) Creating DHCP discover packet.")
    # Ethernet layer
    ethernet = Ether()
    ethernet.dst = 'ff:ff:ff:ff:ff:ff'  # Broadcast.
    # Network layer
    ip = IP()
    ip.src = '0.0.0.0'
    ip.dst = '255.255.255.255'
    # Transport layer
    udp = UDP()
    udp.sport = DHCP_CLIENT_PORT
    udp.dport = DHCP_SERVER_PORT
    # Application layer
    bootp = BOOTP()
    bootp.flags = 1  # Request type message.
    bootp.xid = 666666  # XID
    # DHCP type message
    dhcp = DHCP()
    dhcp.options = [("message-type", "discover"), "end"]

    # Constructing the Discover packet and sending it.
    discover_packet = ethernet / ip / udp / bootp / dhcp
    print("(*) Sending DHCP discover...")
    sendp(discover_packet)
    # -------------------------------- Wait For DHCP Offer Packet -------------------------------- #
    print("(*) Waiting for DHCP offer...")
    # Sniff only from DHCP server port an offer packet.
    while True:
        offer = sniff(count=1, filter="udp and (port 67)")
        if offer[0][4].options[0][1] == 2:
            break
    # Pull the client IP the DHCP server offered.
    client_ip = offer[0][3].yiaddr
    # Pull the DHCP server's IP.
    server_ip = offer[0][3].siaddr
    # Pull the DNS server's IP.
    dns_ip = offer[0][4].options[4][1]
    print("(+) Got a DHCP offer packet.")

    # -------------------------------- Create a DHCP request packet -------------------------------- #
    print("(*) Creating DHCP request packet.")
    # Ethernet layer
    ethernet = Ether()
    ethernet.dst = 'ff:ff:ff:ff:ff:ff'  # Broadcast.
    # Network layer
    ip = IP()
    ip.src = '0.0.0.0'
    ip.dst = '255.255.255.255'
    # Transport layer
    udp = UDP()
    udp.sport = DHCP_CLIENT_PORT
    udp.dport = DHCP_SERVER_PORT
    # Application layer
    bootp = BOOTP()
    bootp.flags = 1  # Request type message.
    bootp.xid = 666666  # XID
    # DHCP type message
    dhcp = DHCP()
    dhcp.options = [("message-type", "request"), ('requested_addr', client_ip), ('server_id', server_ip), "end"]

    # Constructing the request packet and sending it.
    request_packet = ethernet / ip / udp / bootp / dhcp
    sendp(request_packet)
    print("(+) Sent DHCP request.")

    # -------------------------------- Wait For DHCP ack Packet -------------------------------- #
    print("(*) Waiting for DHCP ACK...")
    # Sniff only from DHCP server port.
    sniff(count=1, filter="udp and port 67")
    print("(+) Got a DHCP ACK packet.")

    # -------------------------------- Return The New Client IP -------------------------------- #
    return client_ip, dns_ip


# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Connect DNS <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< #
def connectDNS(gui_object, client_ip, dns_ip, protocol):
    print("\n*********************************")
    print("(*) Connecting to DNS server...")

    # -------------------------------- Create a DNS request packet -------------------------------- #
    # Receive a domain name from the user.
    domain_name = gui_object.getDomain()
    print("(*) Creating DNS request packet.")
    # Network layer
    network_layer = IP(src=client_ip, dst=dns_ip)
    # Transport layer
    transport_layer = UDP(sport=DNS_CLIENT_PORT, dport=DNS_SERVER_PORT)
    # DNS layer
    dns = DNS(id=0xABCD, rd=1, qd=DNSQR(qname=domain_name))  # Recursive request (rd=1).

    # Constructing the request packet and sending it.
    request = network_layer / transport_layer / dns
    # -------------------------------- Send DNS Request -------------------------------- #
    send(request)
    print("(+) Sent the DNS request.")

    # -------------------------------- Receive DNS Response -------------------------------- #
    print("(*) Waiting for the DNS response...")
    answer = sniff(count=1, filter="udp and (port 1024)")
    print("(+) Received the DNS response.")
    # Print and return the answer from the DNS or repeat process if no valid IP was found.
    if answer[0][3].rcode != 3:
        gui_object.enable_buttons()
        print("(+) DNS answer: ", answer[0][3].an.rdata)
        if protocol == "RUDP":
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Make the ports reusable.
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Send the chosen protocol to the server.
            client_socket.sendto(domain_name.encode(), SERVER_ADDRESS)
            print("(+) Sent the server the domain.")
            # Close the socket.
            client_socket.close()
        elif protocol == "TCP":
            # Create TCP socket.
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Make the ports reusable.
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Connect to the server.
            client_socket.connect(SERVER_ADDRESS)
            # Send the chosen protocol to the server.
            client_socket.sendall(domain_name.encode())
            # Close the socket.
            client_socket.close()
        return answer[0][3].an.rdata
    else:
        print("(-) DNS failed. Try again.")
        gui_object.clear_entry()
        gui_object.disable_buttons()


def uploadToServerRUDP(file_path):
    # ---------------------------------- CREATE CLIENT SOCKET ----------------------------------#
    print("\n*********************************")
    print("(*) Creating the client socket...")
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Make the ports reusable.
    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Binding address and port to the socket.
    try:
        client_socket.bind((LOCAL_IP, CLIENT_PORT))
        print("(+) Binding was successful.")
    except socket.error as e:
        print("(-) Binding failed:", e)
        exit(1)
    client_socket.sendto("upload".encode(), SERVER_ADDRESS)
    print("(+) Notified the server we want to upload.")
    # Receiving SYN-ACK message from server.
    client_socket.recvfrom(PACKET_SIZE)
    print("(+) Received SYN-ACK message.")
    client_socket.sendto("ACK".encode(), SERVER_ADDRESS)
    print("(+) Sent ACK message.")
    # Close the socket.
    client_socket.close()


def downloadFromServerRUDP(file_name, save_path):
    # ---------------------------------- CREATE CLIENT SOCKET ----------------------------------#
    print("\n*********************************")
    print("(*) Creating the client socket...")
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Make the ports reusable.
    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Binding address and port to the socket.
    try:
        client_socket.bind((LOCAL_IP, CLIENT_PORT))
        print("(+) Binding was successful.")
    except socket.error as e:
        print("(-) Binding failed:", e)
        exit(1)
    client_socket.sendall("download".encode())
    print("(+) Notified the server we want to download.")
    sleep(0.2)
    # Close the socket.
    client_socket.close()


def uploadToServerTCP(file_path):
    # ---------------------------------- CREATE CLIENT SOCKET ----------------------------------#
    print("\n*********************************")
    print("(*) Creating the client socket...")
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Make the ports reusable.
    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Binding address and port to the socket.
    try:
        client_socket.bind((LOCAL_IP, CLIENT_PORT))
        print("(+) Binding was successful.")
    except socket.error as e:
        print("(-) Binding failed:", e)
        exit(1)
    # Connect to the server.
    client_socket.connect(SERVER_ADDRESS)
    client_socket.send("upload".encode())
    print("(+) Notified the server we want to upload.")
    sleep(0.2)
    # ---------------------------------- SEND THE FILE TO THE SERVER ----------------------------------#
    # Get the file size.
    file_size = os.path.getsize(file_path)
    # Send the file's size.
    client_socket.sendall(str(file_size).encode())
    print("(+) Sent the file's size to the server.")
    sleep(0.2)
    # Get the file name.
    file_name = os.path.basename(file_path)
    # Send the file's name.
    client_socket.sendall(file_name.encode())
    print("(+) Sent the file's name to the server.")
    # Open and send the file to the server.
    with open(file_path, "rb") as file:
        seq_num = 0
        total_packets_to_send = file_size // MAX_BYTES
        print("(*) Sending the file...")
        while True:
            # Read the file's bytes in chunks.
            bytes_to_send = file.read(MAX_BYTES)
            # If we are done with sending the file.
            if not bytes_to_send:
                print("(+) Done with sending file.")
                break
            # Sending the file in chunks.
            client_socket.sendall(bytes_to_send)
            print("Sent:", seq_num, "/", total_packets_to_send)
            seq_num += 1
    # Close the byte-stream.
    file.close()
    # Close the socket.
    client_socket.shutdown(socket.SHUT_WR)
    client_socket.close()
    print("closed")


def downloadFromServerTCP(file_name, save_path):
    # ---------------------------------- CREATE CLIENT SOCKET ----------------------------------#
    print("\n*********************************")
    print("(*) Creating the client socket...")
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Make the ports reusable.
    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Binding address and port to the socket.
    try:
        client_socket.bind((LOCAL_IP, CLIENT_PORT))
        print("(+) Binding was successful.")
    except socket.error as e:
        print("(-) Binding failed:", e)
        exit(1)
    # Connect to the server.
    client_socket.connect(SERVER_ADDRESS)
    client_socket.sendall("download".encode())
    print("(+) Notified the server we want to download.")
    sleep(0.2)
    # ---------------------------------- RECEIVE THE FILE FROM THE SERVER ----------------------------------#
    client_socket.sendall(file_name.encode())
    print("(+) Sent request to download:", file_name)
    # Create the file directory (where we want to download the file).
    file_directory = save_path + "/" + file_name
    with open(file_directory, "wb") as file:
        print("(*) Downloading the file...")
        while True:
            # Read the file's bytes in chunks.
            bytes_to_write = client_socket.recv(MAX_BYTES)
            # If we are done with sending the file.
            if not bytes_to_write:
                print("(+) Done with downloading file.")
                break
            # Write to the file the bytes we just received
            file.write(bytes_to_write)
    # Close the byte-stream.
    file.close()
    # Close the socket.
    client_socket.shutdown(socket.SHUT_WR)
    client_socket.close()
    print("closed")


def sendCommunicationType(protocol):
    print("\n*********************************")
    # Create UDP socket.
    protocol_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Make the ports reusable.
    protocol_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Binding address and port to the socket.
    try:
        protocol_socket.bind((LOCAL_IP, CLIENT_PORT))
        print("(+) Binding was successful.")
    except socket.error as e:
        print("(-) Binding failed:", e)
        exit(1)
    # Sending the server which protocol we choose.
    protocol_socket.sendto(protocol.encode(), SERVER_ADDRESS)
    print("(+) Sent the", protocol, "communication protocol to the server.")
    # Close the socket.
    protocol_socket.close()
    print("closed")


if __name__ == '__main__':
    from Graphical_Interface.GUI import GUI
    CLIENT_IP, DNS_IP = connectDHCP()
    gui = GUI(CLIENT_IP, DNS_IP)
    gui.createGUI()
    gui.runGUI()
