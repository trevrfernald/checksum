# File Checker

## Checksum comparison and VirusTotal scan

#### Sample Output

![alt text](https://github.com/trevrfernald/checksum/blob/master/checksum_example.png)

#### Setup

In order to use the application, it is necessary to sign up for the Virus Total API. More information is available at https://developers.virustotal.com/reference

After signing up, create a file called "key.txt" and paste in a valid API key. Save this file in the parent directory for the application.

#### Using The Application

1. Launch the application from CLI (from parent folder: Python checksum_gui.py)
2. Click "Browse", and choose the file to compare and scan
3. Paste the checksum provided on the page from which the selected file was downloaded
   - Note: if no checksum is available, the calculated checksum can still be scanned with Virus Total, but results will indicate that checksums do not match
4. Choose the appropriate hash function
5. Click Check to compare, scan, and review results
   - Click "Details" to see more information about the Virus Total scan
