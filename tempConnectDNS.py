from scapy.layers.dns import DNSQR, DNS
from scapy.layers.inet import UDP, IP
from scapy.sendrecv import sniff, sendp, send

from FTP_client import DNS_CLIENT_PORT, DNS_SERVER_PORT


def connectDNS():
    print("(*) Connecting to DNS server...")

    while True:

        # -------------------------------- Create a DNS request packet -------------------------------- #
        # Receive a domain name from the user.
        domain_name = "ftplace.org."
        print("(*) Creating DNS request packet.")
        # Network layer
        network_layer = IP(src="8.8.8.8", dst='192.168.4.4')
        # Transport layer
        transport_layer = UDP(sport=DNS_CLIENT_PORT, dport=DNS_SERVER_PORT)
        # DNS layer
        dns = DNS(id=0xABCD, rd=1, qd=DNSQR(qname=domain_name))  # Recursive request (rd=1).

        # Constructing the request packet and sending it.
        request = network_layer / transport_layer / dns
        # -------------------------------- Send DNS Request -------------------------------- #
        print("(+) Sending the DNS request.")
        send(request)
        # request.payload.show()
        # -------------------------------- Receive DNS Response -------------------------------- #
        print("(+) Receiving the DNS response...")
        answer = sniff(count=1, filter="udp and (port 1024)")
        print("SNIFFED")
        # Print and return the answer from the DNS or repeat process if no valid IP was found.
        # answer[0].show()
        print(answer[0][3].rcode)
        if answer[0][3].rcode != 3:

            print("DNS: ", answer[0][3].an.rdata)
            return answer[0][3].an.rdata
        else:
            print("FAILED")
        if 1 == input("if u want to continue press 1"):
            print("balbla")

        else:
            return


domain_ip = connectDNS()
print(domain_ip)
