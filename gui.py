from tkinter import filedialog
import tkinter as tk
import hashlib
import requests
import sys
import os
import json


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
        )
    path_entry.delete(0, tk.END)
    path_entry.insert(0, root.filename)


root = tk.Tk()
root.title("Checksum Checker")
root.geometry('500x300')

frame1 = tk.Frame(root)
frame1.grid(column=0, row=0)
frame2 = tk.Frame(root)
frame2.grid(column=0, row=1)

choose_label = tk.Label(frame1, text="Choose file:")
choose_label.grid(column=0, row=0)
path_entry = tk.Entry(frame1, width=50)
path_entry.grid(column=1, row=0)
browse_button = tk.Button(frame1, text="Browse", command=choose_file)
browse_button.grid(column=2, row=0)

checksum_label = tk.Label(frame1, text="Checksum to compare against:")
checksum_label.grid(column=0, row=1)
checksum_entry = tk.Entry(frame1, width=50)
checksum_entry.grid(column=1, row=1)

# create buttons with for loop
selected = tk.IntVar()
selected.set(1)
type_label = tk.Label(frame2, text="Hash function:")
type_label.grid(column=0, row=0)
sha256_radio = tk.Radiobutton(frame2, text='SHA256', value=1, variable=selected)
sha256_radio.grid(column=1, row=0)
sha1_radio = tk.Radiobutton(frame2, text='SHA1', value=2, variable=selected)
sha1_radio.grid(column=2, row=0)
md5_radio = tk.Radiobutton(frame2, text='MD5', value=3, variable=selected)
md5_radio.grid(column=3, row=0)

results = tk.Label(root, text="results text")
results.grid(column=0, row=2)


def compare(self, checksum):
    """Compare checksums, show results, and call scan with entered checksum."""
    if self == checksum:
        info = "\n", self, "\n", checksum, "\nChecksums match."
        results.configure(text=info)
        # scan(self)
    else:
        info = "\n", self, "\n", checksum, "\nChecksums do not match."
        results.configure(text=info)


def scan(self):
    """Use VT API to analyze calculated checksum.

    The Virustotal public API is limited to 4 requests/second.
    Resource argument can be md5, sha1, or sha256.
    """
    path = os.path.abspath(os.path.dirname(sys.argv[0]))
    key_path = os.path.join(path, "key.txt")
    key = open(key_path, "r")

    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': key, 'resource': self}
    response = requests.get(url, params=params)
    data = json.loads(response.text)
    parse(data)


def parse(self):
    """Parse VT API response and display results."""
    response_code = self['response_code']
    message = self['verbose_msg']

    if response_code == 1:
        print("\n", message, "\n", "Number of positives: ", self['positives'], "\n", sep="")
        print("Total scans: ", self['total'], "\n", self['permalink'], sep="")
    elif response_code == 0:
        print("Item requested is not present in VirusTotal dataset.")
    else:
        print(message)


def calculate_hash(hash, path, checksum):
    dispatcher = {1: sha256, 2: sha1, 3: md5}
    output = dispatcher[hash](path)
    try:
        compare(output, checksum)
    except NameError:
        results.configure(text="ERROR")


def check():  # break up and replace with a lambda?
    """Gather variables & ensure none are blank before comparing hashes."""
    hash = selected.get()
    checksum = checksum_entry.get().lower()
    path = path_entry.get()
    if len(path) != 0 and len(checksum) != 0:
        calculate_hash(hash, path, checksum)
    else:
        results.configure(text="ERROR: File and/or checksum not provided.")


check_button = tk.Button(frame2, text="Check", command=check)
check_button.grid(column=2, row=1)

# check that text is not empty before running, and that file exists (it should, but could be edited)
# c:/users/t/downloads/cmder.7z
# 99D51AD7B1CC518082E7E73A56DE24DE249CD0D5090C78DAE87A591F96E081BA

root.mainloop()
