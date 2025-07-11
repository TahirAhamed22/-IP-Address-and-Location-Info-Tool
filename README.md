# -IP-Address-and-Location-Info-Tool
 IP Address and Location Info Tool



code
import sys
import socket
import requests
import json

def get_ip_info(website):
    try:
        ip_address = socket.gethostbyname(website)
        print(f"[+] IP Address of {website}: {ip_address}")

        url = f"https://ipinfo.io/{ip_address}/json"
        response = requests.get(url)

        if response.status_code == 200:
            data = response.json()
            print("[+] Location Info:")
            print(json.dumps(data, indent=4))
        else:
            print("[-] Failed to get information from ipinfo.io")

    except socket.gaierror:
        print("[-] Invalid website or domain not found.")
    except Exception as e:
        print(f"[-] An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python infotool.py <websiteurl>")
    else:
        website = sys.argv[1]
        get_ip_info(website)
