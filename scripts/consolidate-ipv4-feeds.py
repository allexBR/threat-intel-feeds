import os
import re
import requests
from concurrent.futures import ThreadPoolExecutor
import threading
import time

# Settings
REPO_OWNER = "allexBR"
REPO_NAME = "threat-intel-feeds"
BRANCH = "main"
BASE_PATH = "sources"
OUTPUT_FILE = "ipv4-addr-consolidated.txt"
THREADS = 10       # Number of threads for parallel processing
REQUEST_DELAY = 1  # Delay between requests to avoid rate limiting

# Regular expression for IPv4
IPV4_PATTERN = r"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"

# Global variables
file_lock = threading.Lock()
unique_ips = set()
processed_files = 0

def get_github_contents(path):
    """Gets contents of a directory on GitHub"""
    api_url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{path}?ref={BRANCH}"
    try:
        time.sleep(REQUEST_DELAY)  # Avoid rate limiting
        response = requests.get(api_url)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Error accessing {path}: {e}")
        return None

def find_all_files():
    """Find all files recursively in subdirectories"""
    all_files = []
    directories = [BASE_PATH]
    
    while directories:
        current_dir = directories.pop()
        contents = get_github_contents(current_dir)
        
        if not contents:
            continue
            
        for item in contents:
            if item['type'] == 'dir':
                directories.append(item['path'])
            elif item['type'] == 'file':
                raw_url = f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/{item['path']}"
                all_files.append(raw_url)
    
    return all_files

def extract_ips_from_url(file_url):
    """Extract IP from a remote file"""
    global processed_files
    
    try:
        time.sleep(REQUEST_DELAY)  # Avoid rate limiting
        response = requests.get(file_url)
        response.raise_for_status()
        content = response.text
        ips = re.findall(IPV4_PATTERN, content)
        
        with file_lock:
            for ip in ips:
                unique_ips.add(ip)
            processed_files += 1
            print(f"Processed {processed_files} files. Current unique IPs: {len(unique_ips)}", end='\r')
                
    except Exception as e:
        print(f"\nError processing {file_url}: {e}")

def save_results():
    """Saves results to output file"""
    with file_lock:
        sorted_ips = sorted(unique_ips, key=lambda ip: [int(part) for part in ip.split('.')])
        
        with open(OUTPUT_FILE, 'w') as f:
            for ip in sorted_ips:
                f.write(f"{ip}\n")
                
        print(f"\n\nTotal unique IPs found: {len(sorted_ips)}")
        print(f"Results saved to {OUTPUT_FILE}")

def main():
    print("Starting IPv4 address consolidation...")
    
    # Get file list
    print("Discovering files in repository...")
    file_urls = find_all_files()
    
    if not file_urls:
        print("No files found in directory structure.")
        return
    
    print(f"Found {len(file_urls)} files to process...\n")
    
    # Process files in parallel
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        executor.map(extract_ips_from_url, file_urls)
    
    # Save results
    save_results()

if __name__ == "__main__":
    main()
