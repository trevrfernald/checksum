import hashlib
import requests
import sys
import os
import json

# consider modifying to allow for contents of a folder to be scanned
# wouldn't include checking hashes
# Add optional check if positives are found using hybrid-analysis.com


def choose_hash(self, file, checksum):
    output = ""
    hash = self.lower()
    checksum = checksum.lower()
    if hash == "sha256":
        output = sha256(file)
    elif hash == "sha1":
        output = sha1(file)
    elif hash == "md5":
        output = md5(file)
    else:
        print("error: hash function not available.")
        start()
    compare(output, checksum)


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


def compare(self, checksum):
    if self == checksum:
        print("\n", self, "\n", checksum, sep="")
        print("Checksums match.")
        scan(self)
    else:
        print("\n", self, "\n", checksum, sep="")
        print("Checksums do not match.")
        proceed = input("Scan anyway? (y/n) ")
        if proceed == "y":
            scan(self)
        else:
            start()


def scan(self):
    # Virustotal public API limited to 4 requests/second
    # resource argument can be md5, sha1, or sha256
    path = os.path.abspath(os.path.dirname(sys.argv[0]))
    key_path = os.path.join(path, "key.txt")
    key = open(key_path, "r")

    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': key, 'resource': self}
    response = requests.get(url, params=params)
    data = json.loads(response.text)
    parse(data)


def parse(self):
    response_code = self['response_code']
    message = self['verbose_msg']

    if response_code == 1:
        print("\n", message, "\n", "Number of positives: ", self['positives'], "\n", sep="")
        print("Total scans: ", self['total'], "\n", self['permalink'], sep="")
    elif response_code == 0:
        print("Item requested is not present in VirusTotal dataset.")
    else:
        print(message)


def start():
    type = input("Enter hash function: ")
    checksum = input("Enter checksum to compare against: ")
    file = input("Enter path of file to check: ")
    # assert file exists, ask again if not
    choose_hash(type, file, checksum)


start()
