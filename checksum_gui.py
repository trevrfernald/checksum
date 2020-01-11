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
import os
import webbrowser

KEY = open("./key.txt", "r")
URL = "https://www.virustotal.com/vtapi/v2/file/report"


class DataSet(object):
    """Methods for file + checksum + hash function object.

    Attributes:
        hash_function: sha256, sha1, or md5 (1, 2, or 3 resp.)
        path: path of file to hash and scan
        checksum: checksum of downloaded file from web source
        calculated_checksum: hashlib checksum of downloaded file from file path
    """
    def __init__(self, hash_function, path, checksum=None):
        self.hash_function = hash_function
        self.path = path
        self.checksum = checksum.lower()
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
        """Compares calculated and entered checksums, and returns result."""
        if self.calculated_checksum == self.checksum:
            return True
        else:
            return False

    def scan(self):
        """Uses VT API to analyze calculated checksum, then parses results.

        The Virustotal public API is limited to 4 requests/second.
        Resource argument can be md5, sha1, or sha256.
        """

        params = {"apikey": KEY, "resource": self.calculated_checksum}
        response = requests.get(URL, params=params)
        if response.ok:
            return response.json()
        else:
            return None

        # message = data["verbose_msg"]
        #
        # if data["response_code"] == 1:
        #     info = """{}
        #             Number of positives: {}
        #             Total scans: {}"""
        #     info = info.format(message, data["positives"], data["total"])
        #     return info, data["permalink"]
        # elif response_code == 0:
        #     return "Item requested is not present in VirusTotal database."
        # else:
        #     return message


class MainApplication(tk.Frame):
    def __init__(self, parent, *args, **kwargs):
        tk.Frame.__init__(self, parent, *args, **kwargs)
        self.parent = parent
        root.title("Checksum Checker")
        root.geometry("600x300")

        self.frame1 = tk.Frame(root)
        self.frame1.grid(column=0, row=0)
        self.frame2 = tk.Frame(root)
        self.frame2.grid(column=0, row=1)

        self.choose_label = tk.Label(self.frame1, text="Choose file:")
        self.choose_label.grid(column=0, row=0)
        self.path_entry = tk.Entry(self.frame1, width=50)
        self.path_entry.grid(column=1, row=0)
        self.browse_button = tk.Button(self.frame1, text="Browse", command=self.choose_file)
        self.browse_button.grid(column=2, row=0)

        self.checksum_label = tk.Label(self.frame1, text="Checksum to compare against:")
        self.checksum_label.grid(column=0, row=1)
        self.checksum_entry = tk.Entry(self.frame1, width=50)
        self.checksum_entry.grid(column=1, row=1)

        self.selected = tk.IntVar()
        self.selected.set(1)
        self.type_label = tk.Label(self.frame2, text="Hash function:")
        self.type_label.grid(column=0, row=0)
        self.sha256_radio = tk.Radiobutton(self.frame2, text="SHA256", value=1, variable=self.selected)
        self.sha256_radio.grid(column=1, row=0)
        self.sha1_radio = tk.Radiobutton(self.frame2, text="SHA1", value=2, variable=self.selected)
        self.sha1_radio.grid(column=2, row=0)
        self.md5_radio = tk.Radiobutton(self.frame2, text="MD5", value=3, variable=self.selected)
        self.md5_radio.grid(column=3, row=0)

        # put this into its own frame
        self.comparison_results = tk.Message(root, text="", width=500)
        self.comparison_results.grid(column=0, row=2)
        self.scan_results = tk.Message(root, text="", width=500)
        self.scan_results.grid(column=0, row=3)

        self.check_button = tk.Button(self.frame2, text="Check", command=lambda: self.check())
        self.check_button.grid(column=2, row=1)

    def choose_file(self):
        """Action to allow user to select a file with Browse button."""
        root.filename = filedialog.askopenfilename(
            initialdir=str(os.path.join(
                os.path.join(os.environ["USERPROFILE"]), "Downloads")),
            title="Select File")
        self.path_entry.delete(0, tk.END)
        self.path_entry.insert(0, root.filename)

    def callback(url):
        """Action to allow user to view detailed link after scan completion."""
        webbrowser.open_new(url)

    def create_details(self, details):
        """Creates a button to allow user to open link."""
        self.details_button = tk.Button(root, text="Details",
                                        command=lambda:
                                        MainApplication.callback(details))
        self.details_button.grid(row=4)

    def check(self):  # add functionality to wipe previous results from results frame
        """Gathers variables & ensures none are blank before comparing hashes."""
        hash_function = self.selected.get()
        checksum = self.checksum_entry.get()
        path = self.path_entry.get()

        if len(path) != 0:
            dataset = DataSet(hash_function, path, checksum)
            comparison = dataset.compare()
            if comparison is True:
                result = "Checksums match."
            else:
                result = """CHECKSUMS DO NOT MATCH.
                         Check to make sure checksum was entered correctly.
                         Check to make sure file path was chosen correctly."""
            info = """{}
                   Calculated checksum: {}
                   Entered checksum: {}"""
            info = info.format(result, dataset.calculated_checksum, dataset.checksum)
            self.comparison_results.configure(text=info)
            scan = dataset.scan()
            # self.scan_results.configure(text=scan[0])
            # self.create_details(scan[1])
            self.scan_results.configure(text=scan)
        else:
            self.scan_results.configure(text="ERROR: File path not provided.")


if __name__ == "__main__":
    root = tk.Tk()
    MainApplication(root)
    root.mainloop()
