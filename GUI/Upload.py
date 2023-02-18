import os
import shutil
import tkinter
from tkinter import filedialog

import customtkinter
from tkinter import *

files_directory = "GUI/Files"
file_path = ""


def upload_win():
    # upload_window = customtkinter.CTk()
    # upload_window.title("MyFiles")
    # upload_window.geometry("500x400")
    # upload_window.winfo_toplevel()

    file_path = filedialog.askopenfile()
    print(file_path)
    # upload_window.mainloop()
