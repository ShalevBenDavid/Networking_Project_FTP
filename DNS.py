import socket

from scapy.layers.dns import DNSRR, DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sniff, sendp, send
from scapy.all import *

MAX_BYTES = 1024
DNS_IP = '127.0.0.1'
CLIENT_PORT = 1024
DNS_PORT = 53

# List of domains and their IP address (All local)
Domains = {
    'ftplace.org.': '192.168.2.1',  # delete the point in the end
    'google.com.': '192.168.2.2',
    'Outlook.net.': '192.168.2.3'
}

if __name__ == '__main__':
    print("(*) Starting DNS server...")
    # -------------------------------- Waiting For DNS Request Packet -------------------------------- #
    print("(*) Waiting for DNS request...")
    request = sniff(count=1, filter="udp port 53 and dst host 127.0.0.1")
    print("Sniffed successfully!")
    # Pull the client IP from the DNS request.
    client_ip = request[0][1].src
    # Pull the domain request from the DNS request.
    domain_name = request[0][2].qd.qname
    print(domain_name.decode("utf-8"))

    # -------------------------------- Create A DNS Response Packet -------------------------------- #
    print("(*) Creating DNS response packet.")
    # Network layer.
    network_layer = IP(src=DNS_IP, dst=client_ip)
    print(client_ip)
    # Transport layer.
    transport_layer = UDP(sport=DNS_PORT, dport=CLIENT_PORT)
    # If the server has the answer.
    print(domain_name.decode("utf-8"))
    if domain_name.decode("utf-8") in Domains:
        print("(+) DNS query was successful.")
        # DNS response.
        response = DNSRR(rrname=domain_name, type="A", rclass="IN", ttl=2000,
                         rdata=Domains[domain_name.decode("utf-8")])
        # DNS layer.
        dns = DNS(id=0xABCD, qr=1, aa=1, rd=0, qdcount=1, rcode=0, ancount=1, qd=DNSQR(qname=domain_name), an=response)
        # Response packet (qr=1), authoritative response (aa=1), not recursive (rd=0),
        # solo query (qdcount=1), solo response (ancount=1).
    else:
        print("(-) DNS query failed.")
        # DNS layer.
        response = DNSRR(rrname=domain_name, type="A", rclass="IN", ttl=2000,
                         rdata="0.0.0.0")  # needs to change values in the fields
        dns = DNS(id=0xABCD, qr=1, aa=1, rd=0, rcode=3, qdcount=1, ancount=1, qd=DNSQR(qname=domain_name), an=response)
        print(dns.rcode)
        # Response packet (qr=1), authoritative response (aa=1), not recursive (rd=0),
        # solo query (qdcount=1), solo response (ancount=1), domain wasn't found (rcode=3)
    # -------------------------------- Send The DNS Response Packet -------------------------------- #
    packet = network_layer / transport_layer / dns
    send(packet)
