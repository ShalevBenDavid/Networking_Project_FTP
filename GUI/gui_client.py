import tkinter
from tkinter import *

import customtkinter
import Download
import Upload

import FTP_client

# define frame appearance
customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("dark-blue")
root = customtkinter.CTk()
root.title("FTPlace")
root.geometry("500x500")

frame = customtkinter.CTkFrame(master=root)
frame.pack(pady=20, padx=60, fill="both", expand=True)

# LABELS
try:
    label = customtkinter.CTkLabel(master=frame, text="IP: ")  # FTP_client.connectDHCP())
    label.pack(pady=12, padx=10)
except:
    print("(-) DHCP server problem, run the DHCP server first")
    exit(-1)

entry1 = customtkinter.CTkEntry(master=frame, placeholder_text="FTP Server Address", )
entry1.pack(pady=12, padx=10)

# BUTTONS

# Opens a new window for downloading files.
downloadButton = customtkinter.CTkButton(master=frame, text="Download", command=Download.download_win)
downloadButton.pack(pady=12, padx=10)

# Opens a new window for uploading files.
uploadButton = customtkinter.CTkButton(master=frame, text="Upload", command=Upload.upload_win)
uploadButton.pack()

root.mainloop()
