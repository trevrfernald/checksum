"""This program compares the checksums of a file and retrieves VirusTotal data.

The program displays a gui which asks for a file path, a checksum, and a hash
function. Upon clicking 'check,' the selected hash function is applied to the
file entered. The calculated checksum is compared to the entered checksum, and
the calculated checksum is sent to VirusTotal by API to retrieve scan
information. Results of the comparison and scans are displayed to the user.
"""

from tkinter import filedialog
import tkinter as tk
import hashlib
import requests
import sys
import os
import json
import webbrowser


class DataSet(object):
    """Methods for file + checksum + hash function object.

    Attributes:
        hash_function: sha256, sha1, or md5 (1, 2, or 3 resp.)
        path: path of file to hash and scan
        checksum: checksum of downloaded file from web source
        calculated_checksum: hashlib checksum of downloaded file from file path
    """
    def __init__(self, hash_function, path, checksum):
        self.hash_function = hash_function
        self.path = path
        self.checksum = checksum
        self.calculated_checksum = self.calculate_checksum()

    def calculate_checksum(self):
        """Calculates the checksum of the entered file path.

        Choose hash function with dispatcher using hash_function,
        then calculate the correct digest and return to set
        calulated_checksum.
        """
        dispatcher = {1: hashlib.sha256, 2: hashlib.sha1, 3: hashlib.md5}
        calculated_checksum = dispatcher[self.hash_function]()
        with open(self.path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                calculated_checksum.update(chunk)
        return calculated_checksum.hexdigest()

    def compare(self):
        """Compares calculated and entered checksums, then returns result."""
        if self.calculated_checksum == self.checksum:
            info = '''Checksums match.
                    Calculated checksum:\n{}
                    Entered checksum:\n{}'''
            info = info.format(self.calculated_checksum, self.checksum)
            comparison_results.configure(text=info)
        else:
            info = '''CHECKSUMS DO NOT MATCH.
                    Check to make sure checksum was copied correctly.
                    Check to make sure file path was chosen correctly.
                    Calculated checksum: {}
                    Entered checksum: {}'''
            info = info.format(self.calculated_checksum, self.checksum)
            comparison_results.configure(text=info)

    def scan(self):
        """Uses VT API to analyze calculated checksum, then parses results.

        The Virustotal public API is limited to 4 requests/second.
        Resource argument can be md5, sha1, or sha256.
        """
        path = os.path.abspath(os.path.dirname(sys.argv[0]))
        key_path = os.path.join(path, "key.txt")
        key = open(key_path, "r")

        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': key, 'resource': self.calculated_checksum}
        response = requests.get(url, params=params)
        data = json.loads(response.text)
        response_code = data['response_code']
        message = data['verbose_msg']

        if response_code == 1:
            info = '''{}
                    Number of positives: {}
                    Total scans: {}'''
            info = info.format(message, data['positives'], data['total'])
            scan_results.configure(text=info)
            create_details(data['permalink'])
        elif response_code == 0:
            scan_results.configure(
                text="Item requested is not present in VirusTotal database.")
        else:
            scan_results.configure(text=message)


def choose_file():
    """Action to allow user to select a file with Browse button."""
    root.filename = filedialog.askopenfilename(
        initialdir=str(os.path.join(
            os.path.join(os.environ['USERPROFILE']), 'Downloads')),
        title="Select File")
    path_entry.delete(0, tk.END)
    path_entry.insert(0, root.filename)


def callback(url):
    """Action to allow user to view detailed link after scan completion."""
    webbrowser.open_new(url)


def create_details(details):
    """Creates a button to allow user to open link."""
    details_button = tk.Button(root, text="Details",
                               command=lambda: callback(details))
    details_button.grid(row=4)


def check():  # add functionality to wipe previous results from results frame
    """Gathers variables & ensures none are blank before comparing hashes."""
    hash_function = selected.get()
    checksum = checksum_entry.get().lower()
    path = path_entry.get()
    if len(path) != 0 and len(checksum) != 0:
        dataset = DataSet(hash_function, path, checksum)
        dataset.calculate_checksum()
        dataset.compare()
        dataset.scan()
    else:
        comparison_results.configure(text="ERROR: File and/or checksum not provided.")


root = tk.Tk()
root.title("Checksum Checker")
root.geometry('600x300')

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

# put this into its own frame
comparison_results = tk.Message(root, text="", width=500)
comparison_results.grid(column=0, row=2)
scan_results = tk.Message(root, text="", width=500)
scan_results.grid(column=0, row=3)

check_button = tk.Button(frame2, text="Check", command=check)
check_button.grid(column=2, row=1)

if __name__ == "__main__":
    root.mainloop()
