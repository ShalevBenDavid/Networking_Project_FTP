from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import UDP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, sniff
from DHCP import IP

MAX_BYTES = 1024
DHCP_CLIENT_PORT = 68
DHCP_SERVER_PORT = 67
DNS_PORT = 53
LOCAL_IP = '127.0.0.1'


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
    print("(+) Sending DHCP discover.")
    sendp(discover_packet)

    # -------------------------------- Wait For DHCP Offer Packet -------------------------------- #
    print("(*) Waiting for DHCP offer...")
    # Sniff only from DHCP server port.
    offer = sniff(count=1, filter="udp and (port 67)")
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
    print("(+) Sending DHCP request.")
    sendp(request_packet)

    # -------------------------------- Wait For DHCP ack Packet -------------------------------- #
    print("(*) Waiting for DHCP ACK...")
    # Sniff only from DHCP server port.
    sniff(count=1, filter="port 67")
    print("(+) Got a DHCP ACK packet.")

    # -------------------------------- Return The New Client IP -------------------------------- #
    return client_ip, dns_ip


# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Connect DNS <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< #
def connectDNS(gui_object, dns_ip):
    print("(*) Connecting to DNS server...")

    # Assign the DNS server's address and port.
    server_address_dns = (dns_ip, DNS_PORT)
    # Create a UDP socket to connect to the DNS.
    client_socket_dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    while True:
        # Receive a domain name from the user.
        domain_name = gui_object.getDomain()
        # Send out a DNS query to the server.
        client_socket_dns.sendto(domain_name.encode(), server_address_dns)
        # Receive a DNS answer from the server.
        answer, server_address = client_socket_dns.recvfrom(MAX_BYTES)
        # Decode the answer in uft-8 formant.
        answer = answer.decode("utf-8")
        # Print and return the answer from the DNS.
        print("DNS: ", answer)
        if answer != "No matches":
            gui_object.enable_buttons()
            return answer
        else:
            gui_object.clear_entry()


if __name__ == '__main__':
    from GUI import GUI
    CLIENT_IP, DNS_IP = connectDHCP()
    gui = GUI(CLIENT_IP, DNS_IP)
    gui.createGUI()
    gui.runGUI()

    # CLIENT_IP, DNS_IP = connectDHCP()
    # connectDNS(CLIENT_IP, DNS_IP)
