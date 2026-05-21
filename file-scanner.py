import hashlib
import os
import time
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VirusTotal_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3"

# authenticates you
HEADERS = {
    "x-apikey": API_KEY
}

# takes the path
def calcHash (filePath):
    # creates sha256 hasher
    sha256 = hashlib.sha256()
    # opens the file
    with open(filePath, 'rb') as file:
        # Reads the file in chunks in case of larger files
        for chunk in iter(lambda: file.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

# Asks VirusTotal first before uploading
def matchingReport (file_hash):
    url = f"{BASE_URL}/files/{file_hash}"
    # This sends the GET request and checks status
    response = requests.get(url, headers=HEADERS)
    if response.status_code == 200:
        print("Success")

    elif response.status_code == 404 : 
        print("No existing report found. Uploading file...")
        return None
    
    else: 
        print("Error, please try again")
        return None
    # returns scan data as Python dictionary
    return response.json()

# If VirusTotal does not know the hash, it uploads the file
def  upload_file(file_path):
  with open(file_path, "rb") as file:
      # Creates multipart data
      files = {"file": (os.path.basename(file_path), file)}
      # Uploads to VirusTotal and returns analysis_id
      response = requests.post(url= f"{BASE_URL}/files", headers=HEADERS, files=files)
      return response.json()["data"]["id"]

def get_analysis_result(analysis_id):
    # Checks until complete
    while True:
        response = requests.get(url= f"{BASE_URL}/analyses/{analysis_id}", headers=HEADERS)
        result = response.json()
        
        status = result["data"]["attributes"]["status"]
      
        if status == "completed":
            return result
        time.sleep(15)

def scan_file(file_path):
    file_hash = calcHash(file_path)
    report = matchingReport(file_hash)

    if report:
        stats = report["data"]["attributes"]["last_analysis_stats"]
    else:
        analysis_id = upload_file(file_path)
        result = get_analysis_result(analysis_id)
        stats = result["data"]["attributes"]["stats"]
    
    print("----Scan Results----")
    print(f"Malicious: {stats.get('malicious', 0)}")
    print(f"Suspicious: {stats.get('suspicious', 0)}")
    print(f"Harmless: {stats.get('harmless', 0)}")
    print(f"Undetected: {stats.get('undetected', 0)}")

    if stats.get("malicious", 0) > 0 or stats.get("suspicious", 0) > 0:
        return "Potential threat detected"
    return "No threats detected"

if __name__ == "__main__":
    file_to_scan = input ("Enter the file path to scan: ").strip('""')
    result = scan_file(file_to_scan)
    print(result)