import socket
import tkinter
from tkinter import *
import customtkinter
from GUI import Download, Upload

MAX_BYTES = 1024
DHCP_PORT = 1025
DNS_PORT = 1026
CLIENT_PORT = 78120
SERVER_PORT = 41330
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
    answer = dhcp_server.recv(MAX_BYTES).decode("utf-8")
    # Return the answer from the DHCP.
    print("DHCP: ", answer)
    return answer


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


# define frame appearance
customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("dark-blue")
root = customtkinter.CTk()
root.title("FTPlace")
root.geometry("500x500")

frame = customtkinter.CTkFrame(master=root)
frame.pack(pady=20, padx=60, fill="both", expand=True)


# Clear the entry text field.
def clear_entry():
    entry1.delete(0, tkinter.END)


# Enable the button's usage
def enable_buttons():
    downloadButton.configure(True, state=NORMAL)
    uploadButton.configure(True, state=NORMAL)


# Returns the domain the user entered
def getDomain():
    if len(entry1.get()) != 0:
        return entry1.get()
    else:
        # Disable buttons
        downloadButton.configure(True, state=DISABLED)
        uploadButton.configure(True, state=DISABLED)
        entry1.delete(0, tkinter.END)


# LABELS
try:
    label = customtkinter.CTkLabel(master=frame, text="IP: " + connectDHCP())
    label.pack(pady=12, padx=10)
except:
    print("(-) DHCP server problem, run the DHCP server first")
    exit(-1)

entry1 = customtkinter.CTkEntry(master=frame, placeholder_text="FTP Server Address")
entry1.pack(pady=12, padx=10)

# BUTTONS

# Checks if the domain is correct via 'ok' button or 'ENTER' key.
okButton = customtkinter.CTkButton(master=frame, text="OK", command=connectDNS)
okButton.pack(pady=12, padx=10)
root.bind('<Return>', lambda event: okButton.invoke())

# Opens a new window for downloading files.
downloadButton = customtkinter.CTkButton(master=frame, text="Download", command=Download.download_win, state=DISABLED)
downloadButton.pack(pady=12, padx=10)

# Opens a new window for uploading files.
uploadButton = customtkinter.CTkButton(master=frame, text="Upload", command=Upload.upload_win, state=DISABLED)
uploadButton.pack()


def createGUI():
    root.mainloop()


if __name__ == '__main__':
    createGUI()
