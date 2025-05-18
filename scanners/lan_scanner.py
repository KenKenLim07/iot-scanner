# scanner.py

import nmap
import subprocess
import re
import netifaces
from storage.storage import storage
from utils.fingerprint_engine import get_vendor_from_mac
from engines.vuln_engine import assess_risk, check_default_credentials
from typing import List, Dict, Tuple
import ipaddress
from utils.host_discovery import is_host_up
import socket
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor

def get_local_network():
    """Get the local network interface and IP."""
    try:
        # Get all interfaces
        interfaces = netifaces.interfaces()
        active_interface = None
        
        # First try to find the default gateway interface
        gateways = netifaces.gateways()
        if 'default' in gateways and netifaces.AF_INET in gateways['default']:
            active_interface = gateways['default'][netifaces.AF_INET][1]
        
        # If no default gateway, look for the first interface with an IPv4 address
        if not active_interface:
            for iface in interfaces:
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    active_interface = iface
                    break
        
        if not active_interface:
            print("[-] No active network interface found")
            return "192.168.1.0/24"  # Default fallback
        
        # Get IP and netmask
        interface_info = netifaces.ifaddresses(active_interface)[netifaces.AF_INET][0]
        ip = interface_info['addr']
        netmask = interface_info['netmask']
        
        # Convert netmask to CIDR
        cidr = sum([bin(int(x)).count('1') for x in netmask.split('.')])
        
        # Get network address
        ip_parts = ip.split('.')
        netmask_parts = netmask.split('.')
        network = '.'.join([str(int(ip_parts[i]) & int(netmask_parts[i])) for i in range(4)])
        
        return f"{network}/{cidr}"
    except Exception as e:
        print(f"[-] Error getting local network: {str(e)}")
        return "192.168.1.0/24"  # Default fallback

def scan_network(network: str, verbose: bool = False) -> List[Dict]:
    """Scan a network range for IoT devices using concurrent scanning."""
    results = []
    
    try:
        # Parse network range
        if '/' in network:
            network = ipaddress.ip_network(network, strict=False)
            ip_list = [str(ip) for ip in network.hosts()]
        else:
            ip_list = [network]
        
        if verbose:
            print(f"[+] Scanning {network} ...\n")
            print("[*] Performing initial ping scan...")
        
        # First pass: Quick concurrent ping scan to find active hosts
        active_hosts = []
        with ThreadPoolExecutor(max_workers=50) as executor:
            # Submit all ping tasks
            future_to_ip = {executor.submit(is_host_up, ip, timeout=1): ip for ip in ip_list}
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    is_up, _ = future.result()
                    if is_up:
                        active_hosts.append(ip)
                        if verbose:
                            print(f"[+] Found active host: {ip}")
                except Exception as e:
                    if verbose:
                        print(f"[-] Error scanning {ip}: {str(e)}")
        
        if verbose:
            print(f"[+] Found {len(active_hosts)} active hosts\n")
        
        if not active_hosts:
            print("[-] No active hosts found. Try running with sudo for better results.")
            return []
        
        # Second pass: Concurrent detailed scan of active hosts
        with ThreadPoolExecutor(max_workers=10) as executor:
            # Submit all detailed scan tasks
            future_to_ip = {executor.submit(scan_host, ip, verbose): ip for ip in active_hosts}
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    if verbose:
                        print(f"[-] Error scanning {ip}: {str(e)}")
        
        return results
        
    except Exception as e:
        if verbose:
            print(f"[-] Error scanning network: {str(e)}")
        return []

def scan_host(ip: str, verbose: bool = False) -> Dict:
    """Scan a single host for ports, services, and other information."""
    try:
        if verbose:
            print(f"[*] Scanning host: {ip}")
        
        # Get host state
        is_up, mac = is_host_up(ip)
        if verbose:
            print(f"[*] Host state: {'up' if is_up else 'down'}")
        
        # Perform port scan
        if verbose:
            print(f"[*] Performing port scan on {ip}...")
        ports = scan_ports(ip)
        if verbose:
            print(f"[+] Found {len(ports)} open ports")
        
        # Get MAC address and vendor
        if verbose:
            print(f"[*] Getting MAC address for {ip}...")
            print(f"[*] Running ARP lookup for {ip}...")
        mac, vendor = get_mac_vendor(ip)
        if verbose:
            print(f"[+] MAC: {mac}, Vendor: {vendor}")
        
        # Create result entry
        result = {
            'target': ip,
            'ip': ip,
            'status': 'up' if is_up else 'down',
            'ports': ports,
            'services': [{'port': p, 'name': 'unknown'} for p in ports],
            'mac': mac,
            'vendor': vendor,
            'risk_level': 'Unknown'
        }
        
        if verbose:
            print(f"[+] Found device: {ip} ({vendor}) - Risk: {result['risk_level']}\n")
        
        return result
    except Exception as e:
        if verbose:
            print(f"[-] Error scanning {ip}: {str(e)}")
        return None

def scan_ports(ip: str, timeout: int = 1) -> List[int]:
    """Scan common ports on a target IP."""
    common_ports = [
        # Web Services
        80, 443, 8080, 8443, 8888,
        # IoT Protocols
        1883, 8883, 5683, 5684, 7547, 8291,
        # Remote Access
        22, 23, 3389, 5900,
        # Management
        161, 162, 199, 391, 1993,
        # Media
        554, 8554, 8000, 8001,
        # Custom
        7547, 8291, 8888, 8889
    ]
    
    open_ports = []
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except:
            continue
    return open_ports

def get_mac_address(ip):
    try:
        # Try using nmap's MAC address detection first
        scanner = nmap.PortScanner()
        scanner.scan(hosts=ip, arguments='-sn')
        if ip in scanner.all_hosts():
            mac = scanner[ip]['addresses'].get('mac', '')
            if mac:
                return mac
        
        # Fallback to ARP
        print(f"[*] Running ARP lookup for {ip}...")
        result = subprocess.check_output(["arp", "-n", ip], stderr=subprocess.STDOUT).decode()
        match = re.search(r'(([a-f\d]{1,2}[-:]){5}[a-f\d]{1,2})', result, re.I)
        if match:
            return match.group(0)
        else:
            print(f"[-] No MAC address found in ARP result")
    except Exception as e:
        print(f"[-] MAC lookup failed for {ip}: {str(e)}")
    return "N/A"

def get_mac_vendor(ip: str) -> Tuple[str, str]:
    """Get MAC address and vendor for an IP."""
    mac = get_mac_address(ip)
    vendor = get_vendor_from_mac(mac) if mac != "N/A" else "Unknown"
    return mac, vendor
