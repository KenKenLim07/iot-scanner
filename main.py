# main.py

from scanner import scan_network
from storage import save_to_json

if __name__ == "__main__":
    network = "192.168.254.0/24"
    devices = scan_network(network)
    
    print("\n[+] Devices Found:\n")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}, Hostname: {device['hostname']}, State: {device['state']}, Ports: {device['ports']}")

    save_to_json(devices)
