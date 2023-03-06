import os
import tkinter
from tkinter import DISABLED, NORMAL, messagebox

import customtkinter


class Download:

    def __init__(self, domain):
        self.root = None
        self.listbox = None
        self.domain = domain

    def create_download_win(self):
        # Define the window appearance.
        self.root = customtkinter.CTk()
        self.root.title(self.domain)
        self.root.geometry("500x400")
        self.root.winfo_toplevel()

        # Define the frame.
        frame = customtkinter.CTkFrame(master=self.root)
        frame.pack(side="bottom", pady=20, padx=60, expand=True)
        frame.configure(width=90, height=150)

        # Creating the listbox.
        self.listbox = tkinter.Listbox(master=self.root, width=90, height=150, selectmode="SINGLE",
                                       bg="black", fg="white")
        self.listbox.pack(pady=120, padx=10)

        # Creating the download button.
        downloadNowBtn = customtkinter.CTkButton(master=frame, text="Download Now", command=self.downloadNow
                                                 , state=NORMAL, bg_color="green", fg_color="green")
        downloadNowBtn.pack(side="bottom")

        # Get the list of files in the directory.
        directory = "Domains/" + self.domain
        file_list = os.listdir(directory)

        # Create a list to hold all the file names.
        sortedlist = []
        for file_name in file_list:
            sortedlist.append(file_name)
        sortedlist.sort()
        # Loop through the list and add each file name to the Listbox.
        for file in sortedlist:
            self.listbox.insert(tkinter.END, file)

    def runDownloadWindow(self):
        self.root.mainloop()

    def downloadNow(self):
        # Handle selected file.
        index = self.listbox.curselection()
        if not index:
            self.error_message()

    # Define a function to display a pop-up message if bo file selected.
    def error_message(self):
        messagebox.showinfo("Error", "No file was selected!")
