"""
Enhanced host discovery module with multiple detection methods.
"""

import socket
import subprocess
import platform
from scapy.all import ARP, Ether, srp
from typing import Optional, Tuple

def ping_sweep(ip: str, timeout: int = 1) -> bool:
    """ICMP ping sweep."""
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', '-W', str(timeout), ip]
        return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    except:
        return False

def arp_ping(ip: str, timeout: int = 2) -> Tuple[bool, Optional[str]]:
    """ARP ping with MAC address resolution."""
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
        ans, _ = srp(pkt, timeout=timeout, verbose=0)
        if ans:
            return True, ans[0][1].hwsrc
        return False, None
    except:
        return False, None

def tcp_syn_probe(ip: str, ports: list = [80, 443, 22, 23], timeout: int = 1) -> bool:
    """TCP SYN probe to common ports."""
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                return True
        except:
            continue
    return False

def is_host_up(ip: str, timeout: int = 2) -> Tuple[bool, Optional[str]]:
    """
    Multi-method host discovery.
    Returns (is_up, mac_address)
    """
    try:
        # Try ARP first (most reliable on local network)
        is_up, mac = arp_ping(ip, timeout=timeout)
        if is_up:
            return True, mac
        
        # Try TCP SYN probe with shorter timeout
        if tcp_syn_probe(ip, timeout=timeout//2):
            return True, None
        
        # Try ICMP ping as last resort
        if ping_sweep(ip, timeout=timeout//2):
            return True, None
        
        return False, None
    except Exception as e:
        return False, None

def get_hostname(ip: str) -> Optional[str]:
    """Get hostname via reverse DNS."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None

def get_os_fingerprint(ip: str) -> Optional[str]:
    """Basic OS fingerprinting using TTL and TCP/IP stack quirks."""
    try:
        ttl = subprocess.check_output(['ping', '-c', '1', ip]).decode()
        if 'ttl=64' in ttl.lower():
            return 'Linux/Unix'
        elif 'ttl=128' in ttl.lower():
            return 'Windows'
        elif 'ttl=255' in ttl.lower():
            return 'Network Device'
    except:
        pass
    return None 