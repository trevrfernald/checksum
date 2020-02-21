# File Checker

## Checksum comparison and VirusTotal scan

####Setup

In order to use the application, you need to sign up for the Virus Total API. More information is available at https://developers.virustotal.com/reference

After signing up, create a key.txt file and paste in your API key. Save this file in the parent directory for the application.

####Using The Application

1. Launch the application from CLI (from parent folder: Python checksum_gui.py)
2. Click Browse and choose the file to check and scan
3. Paste the checksum provided on the page from which the file was downloaded
   - Note: if no checksum is available/provided, the calculated checksum can still be scanned with Virus Total.
4. Choose the appropriate hash function
5. Click Check to compare, scan, and review results
6. Click Details to see more information about the Virus Total scan


####Interpreting Results

If the entered checksum does not match the checksum resulting from the hash function being applied to the selected file, the file may be malicious.

When Virus Total reports positives, compare the number of positives to the total number of scans. Consider the scanners which report positives, as some scanners are prone to false-positives.

Always use your best judgement and don't use suspicious files. This tool is meant to be used for informational purposes only, and is not intended to protect against malware.
