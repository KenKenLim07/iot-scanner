"""
Network utility functions for the IoT Scanner.
"""

import socket
import netifaces
import ipaddress

def get_local_ip():
    """Get the local IP address of the machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"

def get_network_interfaces():
    """Get list of available network interfaces."""
    return netifaces.interfaces()

def is_valid_ip(ip):
    """Check if the given string is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_port(port):
    """Check if the given number is a valid port."""
    try:
        port = int(port)
        return 0 < port < 65536
    except ValueError:
        return False 