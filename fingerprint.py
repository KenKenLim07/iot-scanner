# fingerprint.py

import requests

def get_vendor_from_mac(mac):
    try:
        oui = mac.upper().replace(':', '').replace('-', '')[:6]
        url = f"https://api.macvendors.com/{oui}"
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            return response.text
    except:
        pass
    return "Unknown Vendor"
