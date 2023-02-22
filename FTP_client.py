import os
import shutil
import socket
import tkinter
from tkinter import *
from tkinter import filedialog
import customtkinter
from GUI import Download

MAX_BYTES = 1024
DHCP_PORT = 1025
DNS_PORT = 1027
CLIENT_PORT = 78120
SERVER_PORT = 41330
LOCAL_IP = '127.0.0.1'


# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Connect DHCP <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< #
def connectDHCP():
    def discover_get():
        OP = bytes([0x01])
        HTYPE = bytes([0x01])
        HLEN = bytes([0x06])
        HOPS = bytes([0x00])
        XID = bytes([0x39, 0x03, 0xF3, 0x26])
        SECS = bytes([0x00, 0x00])
        FLAGS = bytes([0x00, 0x00])
        CIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        YIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        SIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR1 = bytes([0x00, 0x05, 0x3C, 0x04])
        CHADDR2 = bytes([0x8D, 0x59, 0x00, 0x00])
        CHADDR3 = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR4 = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR5 = bytes(192)
        Magiccookie = bytes([0x63, 0x82, 0x53, 0x63])
        DHCPOptions1 = bytes([53, 1, 1])
        DHCPOptions2 = bytes([50, 4, 0xC0, 0xA8, 0x01, 0x64])

        package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR + YIADDR + SIADDR + GIADDR + CHADDR1 + CHADDR2 + CHADDR3 + CHADDR4 + CHADDR5 + Magiccookie + DHCPOptions1 + DHCPOptions2

        return package

    def request_get():
        OP = bytes([0x01])
        HTYPE = bytes([0x01])
        HLEN = bytes([0x06])
        HOPS = bytes([0x00])
        XID = bytes([0x39, 0x03, 0xF3, 0x26])
        SECS = bytes([0x00, 0x00])
        FLAGS = bytes([0x00, 0x00])
        CIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        YIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        SIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR1 = bytes([0x00, 0x0C, 0x29, 0xDD])
        CHADDR2 = bytes([0x5C, 0xA7, 0x00, 0x00])
        CHADDR3 = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR4 = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR5 = bytes(192)
        Magiccookie = bytes([0x63, 0x82, 0x53, 0x63])
        DHCPOptions1 = bytes([53, 1, 3])
        DHCPOptions2 = bytes([50, 4, 0xC0, 0xA8, 0x01, 0x64])
        DHCPOptions3 = bytes([54, 4, 0xC0, 0xA8, 0x01, 0x01])

        package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR + YIADDR + SIADDR + GIADDR + CHADDR1 + CHADDR2 + CHADDR3 + CHADDR4 + CHADDR5 + Magiccookie + DHCPOptions1 + DHCPOptions2 + DHCPOptions3

        return package

    print("Connecting to DHCP server...")

    # Assign the DHCP server's address and port.
    server_address_dhcp = (LOCAL_IP, DHCP_PORT)
    # Create a TCP socket to connect to the DHCP.
    dhcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Connect to the DHCP server.
    dhcp_server.connect(server_address_dhcp)
    # Send out a DHCP request to the server.
    print("Send DHCP discovery.")
    data = discover_get()
    dhcp_server.send(data)
    #dhcp_server.send(bytes("Please give me an IP", "utf-8"))
    # Receive a DHCP answer from the server.
    data = dhcp_server.recv(MAX_BYTES)
    print("Receive DHCP offer.")
    print("Send DHCP request.")
    data = request_get();
    dhcp_server.send(data)
    data = dhcp_server.recv(MAX_BYTES)
    print("Receive DHCP pack.\n")
    print(data)
    #answer = dhcp_server.recv(MAX_BYTES).decode("utf-8")
    # Return the answer from the DHCP.
    #print("DHCP: ", answer)
    #return answer


# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Connect DNS <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< #
def connectDNS():
    print("Connecting to DNS server...")

    # Assign the DNS server's address and port.
    server_address_dns = (LOCAL_IP, DNS_PORT)
    # Create a UDP socket to connect to the DNS.
    client_socket_dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    while True:
        # Receive a domain name from the user.
        domain_name = getDomain()
        # Send out a DNS query to the server.
        client_socket_dns.sendto(domain_name.encode(), server_address_dns)
        # Receive a DNS answer from the server.
        answer, server_address = client_socket_dns.recvfrom(MAX_BYTES)
        # Decode the answer in uft-8 formant.
        answer = answer.decode("utf-8")
        # Print and return the answer from the DNS.
        print("DNS: ", answer)
        if answer != "No matches":
            enable_buttons()
            return answer
        else:
            clear_entry()


# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Create GUI <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< #
# Define thw window appearance.
customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("dark-blue")
root = customtkinter.CTk()
root.title("FTPlace")
root.geometry("500x500")

# Define thw frame.
frame = customtkinter.CTkFrame(master=root)
frame.pack(pady=20, padx=60, fill="both", expand=True)


# Uploads file from the file explorer.
def upload_win():
    domain = getDomain()
    file_path = filedialog.askopenfilename()

    # directory = "Server/" + domain
    # new_file_path = os.path.join(directory, os.path.basename(file_path))
    # shutil.copy(file_path, new_file_path)


# ---------------------------------- GUI LABELS ----------------------------------#
try:
    label = customtkinter.CTkLabel(master=frame, text="IP: " + connectDHCP())
    label.pack(pady=12, padx=10)
except:
    print("(-) DHCP server problem, run the DHCP server first")
    exit(-1)

entry1 = customtkinter.CTkEntry(master=frame, placeholder_text="FTP Server Address")
entry1.pack(pady=12, padx=10)

# ---------------------------------- GUI BUTTONS ----------------------------------#
# Checks if the domain is correct via 'ok' button or 'ENTER' key.
okButton = customtkinter.CTkButton(master=frame, text="OK", command=connectDNS)
okButton.pack(pady=12, padx=10)
root.bind('<Return>', lambda event: okButton.invoke())

# Opens a new window for downloading files.
downloadButton = customtkinter.CTkButton(master=frame, text="Download", command=Download.download_win, state=DISABLED)
downloadButton.pack(pady=12, padx=10)

# Opens a new window for uploading files.
uploadButton = customtkinter.CTkButton(master=frame, text="Upload", command=upload_win, state=DISABLED)
uploadButton.pack()

# ---------------------------------- GUI RADIO BUTTONS ----------------------------------#
radio = tkinter.IntVar(value=1)

# RUDP radio button.
rudpRadio = customtkinter.CTkRadioButton(frame, text="RUDP", variable=radio, value=2)
rudpRadio.pack(side="bottom")

# TCP radio button.
tcpRadio = customtkinter.CTkRadioButton(frame, text="TCP", variable=radio, value=1)
tcpRadio.pack(side="bottom")


# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> GUI Methods <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< #
# Clear the entry text field.
def clear_entry():
    entry1.delete(0, tkinter.END)


# Enable the download/upload button's usage.
def enable_buttons():
    downloadButton.configure(True, state=NORMAL)
    uploadButton.configure(True, state=NORMAL)


# Returns the domain the user entered.
def getDomain():
    if len(entry1.get()) != 0:
        return entry1.get()
    else:
        # Disable the buttons.
        downloadButton.configure(True, state=DISABLED)
        uploadButton.configure(True, state=DISABLED)
        entry1.delete(0, tkinter.END)


def createGUI():
    root.mainloop()


if __name__ == '__main__':
    createGUI()
