# Threat File Scanner

## Overview
Malicious File Scanner is a Python program that integrates with the VirusTotal API to scan files for potential threats. The program generates a SHA-256 hash for a file, checks if VirusTotal already has a scan report for that file, uploads the file if no report exists, and displays the scan results.

## Features
- Generate SHA-256 hashes for files
- Check VirusTotal for existing reports
- Upload files to VirusTotal for scanning
- Retrieve scan results from the VirusTotal API
- Display malicious, suspicious, harmless, and undetected detections
- Store API keys using environment variables

## Technologies Used
- Python
- VirusTotal API v3
- requests
- python-dotenv
- hashlib

## Installation

Install required packages:

```bash
pip install requests python-dotenv
```

Create a `.env` file:

```env
VirusTotal_API_KEY=YOUR_API_KEY_HERE
```

## Usage

Run the program:

```bash
python file-scanner.py
```

Enter the full file path when prompted.

Example:

```text
C:\Users\Username\Desktop\example.txt
```

## Example Output

```text
----Scan Results----
Malicious: 0
Suspicious: 0
Harmless: 62
Undetected: 3

No threats detected
```

## Notes
- Do not upload your real `.env` file to GitHub.
- Do not upload sensitive files to VirusTotal.
- The program scans individual files, not folders.
