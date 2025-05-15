# scanner.py

import nmap
import subprocess
import re

def scan_network(network):
    scanner = nmap.PortScanner()
    print(f"[+] Scanning {network} ...\n")
    scanner.scan(hosts=network, arguments='-sn')  # just ping scan

    devices = []

    for host in scanner.all_hosts():
        try:
            # Check if host exists in results
            host_data = scanner._scan_result["scan"].get(host, {})
            hostname = host_data.get("hostnames", [{}])[0].get("name", "")
            state = host_data.get("status", {}).get("state", "unknown")
            
            # Light port scan for this host
            ports = []
            try:
                port_scan = scanner.scan(hosts=host, arguments='-T4 -F')
                for proto in scanner[host].all_protocols():
                    ports.extend(list(scanner[host][proto].keys()))
            except:
                pass

            mac = get_mac_address(host)

            devices.append({
                'ip': host,
                'hostname': hostname,
                'state': state,
                'ports': ports,
                'mac': mac
            })
        
        except Exception as e:
            print(f"[-] Skipping {host}: {e}")
            continue

    return devices

def get_mac_address(ip):
    try:
        result = subprocess.check_output(["arp", "-n", ip]).decode()
        match = re.search(r'(([a-f\d]{1,2}[-:]){5}[a-f\d]{1,2})', result, re.I)
        if match:
            return match.group(0)
    except Exception as e:
        print(f"[-] Could not get MAC for {ip}: {e}")
    return "N/A"
