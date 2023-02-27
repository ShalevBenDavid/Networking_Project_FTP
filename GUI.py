import tkinter
from tkinter import NORMAL, DISABLED, filedialog

import customtkinter

from FTP_client import *
import Download


class GUI:
    def __init__(self, client_ip, dns_ip):
        self.tcpRadio = None
        self.rudpRadio = None
        self.okButton = None
        self.root = None
        self.uploadButton = None
        self.downloadButton = None
        self.entry = None
        self.domain_ip = None
        self.client_ip = client_ip
        self.dns_ip = dns_ip

    def createGUI(self):
        # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Create GUI <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< #
        # Define thw window appearance.
        customtkinter.set_appearance_mode("dark")
        customtkinter.set_default_color_theme("dark-blue")
        self.root = customtkinter.CTk()
        self.root.title("FTPlace")
        self.root.geometry("500x500")

        # Define the frame.
        frame = customtkinter.CTkFrame(master=self.root)
        frame.pack(pady=20, padx=60, fill="both", expand=True)

        # Uploads file from the file explorer.
        def upload_win():
            domain = self.getDomain()
            file_path = filedialog.askopenfilename()

            # directory = "Server/" + domain
            # new_file_path = os.path.join(directory, os.path.basename(file_path))
            # shutil.copy(file_path, new_file_path)

        # ---------------------------------- GUI LABELS ----------------------------------#

        label_client_ip = customtkinter.CTkLabel(master=frame, text="Your IP: " + self.client_ip)
        label_client_ip.pack(pady=1, padx=10)

        label_dns_ip = customtkinter.CTkLabel(master=frame, text="DNS IP: " + self.dns_ip)
        label_dns_ip.pack(pady=8, padx=10)

        self.entry = customtkinter.CTkEntry(master=frame, placeholder_text="FTP Server Address")
        self.entry.pack(pady=12, padx=10)

        # ---------------------------------- GUI BUTTONS ----------------------------------#
        # Checks if the domain is correct via 'ok' button or 'ENTER' key.
        self.okButton = customtkinter.CTkButton(master=frame, text="OK", command=self.callConnectDNS)
        self.okButton.pack(pady=12, padx=10)
        self.root.bind('<Return>', lambda event: self.okButton.invoke())

        # Opens a new window for downloading files.
        self.downloadButton = customtkinter.CTkButton(master=frame, text="Download", command=Download.download_win,
                                                      state=DISABLED)
        self.downloadButton.pack(pady=12, padx=10)

        # Opens a new window for uploading files.
        self.uploadButton = customtkinter.CTkButton(master=frame, text="Upload", command=upload_win, state=DISABLED)
        self.uploadButton.pack()

        # ---------------------------------- GUI RADIO BUTTONS ----------------------------------#
        radio = tkinter.IntVar(value=1)

        # RUDP radio button.
        self.rudpRadio = customtkinter.CTkRadioButton(frame, text="RUDP", variable=radio, value=2)
        self.rudpRadio.pack(side="bottom")

        # TCP radio button.
        self.tcpRadio = customtkinter.CTkRadioButton(frame, text="TCP", variable=radio, value=1)
        self.tcpRadio.pack(side="bottom")

    # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> GUI Methods <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< #

    # Function that calls connectDNS().
    def callConnectDNS(self):
        self.domain_ip = connectDNS(self, self.dns_ip)

    # Clear the entry text field.
    def clear_entry(self):
        self.entry.delete(0, tkinter.END)

    # Enable the download/upload button's usage.
    def enable_buttons(self):
        self.downloadButton.configure(True, state=NORMAL)
        self.uploadButton.configure(True, state=NORMAL)

    # Returns the domain the user entered.
    def getDomain(self):
        if len(self.entry.get()) != 0:
            return self.entry.get()
        else:
            # Disable the buttons.
            self.downloadButton.configure(True, state=DISABLED)
            self.uploadButton.configure(True, state=DISABLED)
            self.entry.delete(0, tkinter.END)
            return ""

    def runGUI(self):
        self.root.mainloop()
