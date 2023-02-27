import tkinter
from tkinter import *
from tkinter import filedialog

import customtkinter
from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, sniff, sr1
from DHCP import IP
from GUI import Download

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
def connectDNS(client_ip, dns_ip):
    print("(*) Connecting to DNS server...")

    while True:
        # -------------------------------- Create a DNS request packet -------------------------------- #
        # Receive a domain name from the user.
        domain_name = 'ftplace.org'  # getDomain()
        print("(*) Creating DNS request packet.")
        # Network layer
        network_layer = IP(src=client_ip, dst=dns_ip)
        # Transport layer
        transport_layer = UDP(dport=DNS_PORT)
        # DNS layer
        dns = DNS(rd=1, qd=DNSQR(qname=domain_name))

        # Constructing the request packet and sending it.
        request = network_layer / transport_layer / dns
        # -------------------------------- Send DNS Request && Receive Response -------------------------------- #
        print("(+) Sending the DNS request.")
        sendp(request)
        print("(+) Receiving the DNS response.")
        # Print and return the answer from the DNS or repeat process if no valid IP was found.
        print("DNS: ", answer[DNS].summary())
        if answer != "No matches":
            #enable_buttons()
            return answer
        else:
            #clear_entry()


# # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Create GUI <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< #
# # Define thw window appearance.
# customtkinter.set_appearance_mode("dark")
# customtkinter.set_default_color_theme("dark-blue")
# root = customtkinter.CTk()
# root.title("FTPlace")
# root.geometry("500x500")
#
# # Define thw frame.
# frame = customtkinter.CTkFrame(master=root)
# frame.pack(pady=20, padx=60, fill="both", expand=True)
#
#
# # Uploads file from the file explorer.
# def upload_win():
#     domain = getDomain()
#     file_path = filedialog.askopenfilename()
#
#     # directory = "Server/" + domain
#     # new_file_path = os.path.join(directory, os.path.basename(file_path))
#     # shutil.copy(file_path, new_file_path)
#
#
# # ---------------------------------- GUI LABELS ----------------------------------#
# try:
#     label = customtkinter.CTkLabel(master=frame, text="IP: " + connectDHCP())
#     label.pack(pady=12, padx=10)
# except:
#     print("(-) DHCP server problem, run the DHCP server first")
#     exit(-1)
#
# entry1 = customtkinter.CTkEntry(master=frame, placeholder_text="FTP Server Address")
# entry1.pack(pady=12, padx=10)
#
# # ---------------------------------- GUI BUTTONS ----------------------------------#
# # Checks if the domain is correct via 'ok' button or 'ENTER' key.
# okButton = customtkinter.CTkButton(master=frame, text="OK", command=connectDNS)
# okButton.pack(pady=12, padx=10)
# root.bind('<Return>', lambda event: okButton.invoke())
#
# # Opens a new window for downloading files.
# downloadButton = customtkinter.CTkButton(master=frame, text="Download", command=Download.download_win, state=DISABLED)
# downloadButton.pack(pady=12, padx=10)
#
# # Opens a new window for uploading files.
# uploadButton = customtkinter.CTkButton(master=frame, text="Upload", command=upload_win, state=DISABLED)
# uploadButton.pack()
#
# # ---------------------------------- GUI RADIO BUTTONS ----------------------------------#
# radio = tkinter.IntVar(value=1)
#
# # RUDP radio button.
# rudpRadio = customtkinter.CTkRadioButton(frame, text="RUDP", variable=radio, value=2)
# rudpRadio.pack(side="bottom")
#
# # TCP radio button.
# tcpRadio = customtkinter.CTkRadioButton(frame, text="TCP", variable=radio, value=1)
# tcpRadio.pack(side="bottom")
#
#
# # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> GUI Methods <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< #
# # Clear the entry text field.
# def clear_entry():
#     entry1.delete(0, tkinter.END)
#
#
# # Enable the download/upload button's usage.
# def enable_buttons():
#     downloadButton.configure(True, state=NORMAL)
#     uploadButton.configure(True, state=NORMAL)
#
#
# # Returns the domain the user entered.
# def getDomain():
#     if len(entry1.get()) != 0:
#         return entry1.get()
#     else:
#         # Disable the buttons.
#         downloadButton.configure(True, state=DISABLED)
#         uploadButton.configure(True, state=DISABLED)
#         entry1.delete(0, tkinter.END)
#
#
# def createGUI():
#     root.mainloop()


if __name__ == '__main__':
    CLIENT_IP, DNS_IP = connectDHCP()
    connectDNS(CLIENT_IP, DNS_IP)
