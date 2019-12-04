from tkinter import filedialog, messagebox
from tkinter import *
from functools import partial
import hashlib
import checksum

def sha256(self):
    hash_sha256 = hashlib.sha256()
    with open(self, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def sha1(self):
    hash_sha1 = hashlib.sha1()
    with open(self, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha1.update(chunk)
    return hash_sha1.hexdigest()

def md5(self):
    hash_md5 = hashlib.md5()
    with open(self, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def choose_file():
    root.filename = filedialog.askopenfilename(
        initialdir="C:/Users/T/Downloads",
        title="Select File"
        #filetypes=(("jpeg files", "*.jpg"), ("all files", "*.*"))
        )
    path_entry.delete(0, END)
    path_entry.insert(0, root.filename)

root = Tk()
root.title("Checksum Checker")
root.geometry('500x300')

frame1 = Frame(root)
frame1.grid(column=0, row=0)
frame2 = Frame(root)
frame2.grid(column=0, row=1)

choose_label = Label(frame1, text="Choose file:")
choose_label.grid(column=0, row=0)
path_entry = Entry(frame1, width=50)
path_entry.grid(column=1, row=0)
browse_button = Button(frame1, text="Browse", command=choose_file)
browse_button.grid(column=2, row=0)

checksum_label = Label(frame1, text="Checksum to compare against:")
checksum_label.grid(column=0, row=1)
checksum_entry = Entry(frame1, width=50)
checksum_entry.grid(column=1, row=1)

#create buttons with for loop
selected = IntVar()
selected.set(1)
type_label = Label(frame2, text="Hash function:")
type_label.grid(column=0, row=0)
sha256_radio = Radiobutton(frame2, text='SHA256', value=1, variable=selected)
sha256_radio.grid(column=1, row=0)
sha1_radio = Radiobutton(frame2, text='SHA1', value=2, variable=selected)
sha1_radio.grid(column=2, row=0)
md5_radio = Radiobutton(frame2, text='MD5', value=3, variable=selected)
md5_radio.grid(column=3, row=0)

results = Label(root, text="results text")
results.grid(column=0, row=2)


def calculate_hash():
    hash = selected.get()
    checksum = checksum_entry.get().lower()
    path = path_entry.get()
    dispatcher = {1: sha256, 2: sha1, 3: md5}
    try:
        results.configure(text=dispatcher[hash](path))
    except NameError:
        #messagebox.showinfo('ERROR', 'Hash function is not available.')
        results.configure(text="ERROR")
    #compare(output, checksum)

check_button = Button(frame2, text="Check", command=calculate_hash)
check_button.grid(column=2, row=1)

# file = path_entry.get()
# check that text is not empty before running, and that file exists (it should, but could be edited)
# c:/users/t/downloads/cmder.7z
# 99D51AD7B1CC518082E7E73A56DE24DE249CD0D5090C78DAE87A591F96E081BA



root.mainloop()
