from Utils.hashing import get_sha256
import json
import requests

class SignatureDetector:
    def __init__(self, signatures_file: str = "antivirus/Data/signatures.json"):
        with open(signatures_file) as f:
            self.known_hashes = set(json.load(f))  # list of SHA-256 strings

    def scan(self, file_path: str) -> bool:
        try:
            file_hash = get_sha256(file_path).upper()
            
            if file_hash in self.known_hashes:
                # Simple family lookup (you can extend this later)
                return True, "Known Malware (Signature match)"
            
            return False, None
        except Exception as e:
            print(f"[ERROR] Signature scan failed for {file_path}: {e}")
            return False, None
        

    def virusTotal(self, file_path: str) -> bool:
        url = "https://www.virustotal.com/api/v3/files/"
        
        headers = {
            "x-apikey": "APIKEY", #Remember to safely add api key here
            "accept": "application/json"
            }

        hashedFile = get_sha256(file_path).upper()

        response = requests.get(url+hashedFile, headers=headers) #Include API key
        if response.status_code != 200:
            print(f"Error: {response.status_code}")
        
        print(response.text)
