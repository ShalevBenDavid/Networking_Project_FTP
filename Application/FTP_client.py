from time import sleep

from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import UDP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, sniff
from Servers.DHCP import IP


MAX_BYTES = 1024
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
    sleep(0.2)
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
def connectDNS(gui_object, client_ip, dns_ip):
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

        #########################################################
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_address = ('localhost', SERVER_PORT)
        sock.sendto(domain_name.encode(), server_address)
        ##########################################################
        return answer[0][3].an.rdata
    else:
        print("(-) DNS failed. Try again.")
        gui_object.clear_entry()


if __name__ == '__main__':
    from Graphical_Interface.GUI import GUI

    CLIENT_IP, DNS_IP = connectDHCP()
    gui = GUI(CLIENT_IP, DNS_IP)
    gui.createGUI()
    gui.runGUI()
