"""
WAN Scanner module for scanning internet-facing devices.
"""

import socket
import ssl
import json
import logging
import ipaddress
import concurrent.futures
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from engines.vuln_engine import assess_risk, check_default_credentials

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load vendor patterns from JSON
try:
    with open('assets/vendor_patterns.json', 'r') as f:
        VENDOR_PATTERNS = json.load(f)
except FileNotFoundError:
    # Default patterns if file not found
    VENDOR_PATTERNS = {
        'TP-LINK': ['TP-LINK', 'TPLink', 'tp-link'],
        'HUAWEI': ['Huawei', 'HUAWEI', 'huawei'],
        'D-LINK': ['D-Link', 'DLink', 'd-link'],
        'CISCO': ['Cisco', 'CISCO', 'cisco'],
        'ZTE': ['ZTE', 'Zte', 'zte'],
        'NETGEAR': ['NETGEAR', 'Netgear', 'netgear']
    }

class ScannerConfig:
    """Configuration for scanner behavior."""
    def __init__(self, 
                 timeout: float = 1.0,
                 max_workers: int = 10,
                 rate_limit: float = 0.1,  # seconds between requests
                 use_ssl: bool = True,
                 verbose: bool = False):
        self.timeout = timeout
        self.max_workers = max_workers
        self.rate_limit = rate_limit
        self.use_ssl = use_ssl
        self.verbose = verbose

def scan_target(target: str, config: Optional[ScannerConfig] = None, ports: Optional[List[int]] = None) -> Dict:
    """
    Scan a single target (IP or domain) for open ports and services.
    
    Args:
        target: IP address or domain name to scan
        config: Scanner configuration
        ports: Optional list of ports to scan. If None, uses common IoT ports
        
    Returns:
        Dict containing scan results
    """
    if config is None:
        config = ScannerConfig()
    
    if ports is None:
        ports = [
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
        ]  # Common IoT ports
    
    results = {
        'target': target,
        'ip': resolve_target(target),
        'ports': [],
        'services': [],
        'status': 'unknown',
        'vendor': 'Unknown',
        'risk_level': 'Unknown',
        'errors': [],
        'scan_time': datetime.now().isoformat()
    }
    
    for port in ports:
        try:
            service = scan_port(results['ip'], port, config)
            if service:
                results['ports'].append(port)
                results['services'].append(service)
                
                # Try to identify vendor from service banner
                if service.get('banner'):
                    vendor = identify_vendor(service['banner'])
                    if vendor:
                        results['vendor'] = vendor
        except Exception as e:
            error_msg = f"Error scanning port {port}: {str(e)}"
            logger.debug(error_msg)
            results['errors'].append(error_msg)
            continue
    
    results['status'] = 'up' if results['ports'] else 'down'
    
    # Perform vulnerability assessment
    if results['status'] == 'up':
        results['risk_level'] = assess_risk(results)
        results['default_creds'] = check_default_credentials(results['vendor'])
    
    return results

def scan_port(ip: str, port: int, config: ScannerConfig) -> Optional[Dict]:
    """Scan a single port with enhanced protocol detection."""
    try:
        if port in [443, 8443] and config.use_ssl:
            return scan_ssl_port(ip, port, config)
        else:
            return scan_plain_port(ip, port, config)
    except Exception as e:
        logger.debug(f"Error scanning port {port}: {str(e)}")
        return None

def scan_ssl_port(ip: str, port: int, config: ScannerConfig) -> Optional[Dict]:
    """Scan an SSL/TLS port."""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((ip, port), timeout=config.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                if cert:
                    # Extract certificate information
                    cert_info = ssl.get_server_certificate((ip, port))
                    service = {
                        'port': port,
                        'name': 'https',
                        'version': 'unknown',
                        'banner': '',
                        'ssl_info': {
                            'cert': cert_info,
                            'cipher': ssock.cipher()
                        }
                    }
                    
                    # Try to get HTTP response
                    try:
                        ssock.send(b'GET / HTTP/1.1\r\nHost: %s\r\n\r\n' % ip.encode())
                        banner = ssock.recv(1024).decode('utf-8', errors='ignore')
                        service['banner'] = banner
                        if 'Server:' in banner:
                            service['version'] = banner.split('Server:')[1].split('\n')[0].strip()
                    except:
                        pass
                    
                    return service
    except:
        return None

def grab_banner(sock: socket.socket, protocol: str = 'http') -> str:
    """Enhanced banner grabbing with protocol-specific probes."""
    try:
        if protocol == 'http':
            sock.send(b'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n')
        elif protocol == 'ftp':
            sock.send(b'USER anonymous\r\n')
        elif protocol == 'smtp':
            sock.send(b'HELO localhost\r\n')
        elif protocol == 'ssh':
            sock.send(b'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n')
        else:
            sock.send(b'\r\n')
        
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        return banner
    except:
        return ''

def scan_plain_port(ip: str, port: int, config: ScannerConfig) -> Optional[Dict]:
    """Enhanced plain port scanning with better service detection."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(config.timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                service = {
                    'port': port,
                    'name': 'unknown',
                    'version': 'unknown',
                    'banner': '',
                    'product': 'unknown'
                }
                
                # Try different protocol probes
                if port in [80, 8080]:
                    banner = grab_banner(sock, 'http')
                    service['banner'] = banner
                    service['name'] = 'http'
                    if 'Server:' in banner:
                        service['version'] = banner.split('Server:')[1].split('\n')[0].strip()
                        service['product'] = service['version'].split('/')[0] if '/' in service['version'] else service['version']
                elif port in [21, 2121]:
                    banner = grab_banner(sock, 'ftp')
                    service['banner'] = banner
                    service['name'] = 'ftp'
                    if '220' in banner:
                        service['version'] = banner.split('\n')[0].strip()
                elif port in [22, 2222]:
                    banner = grab_banner(sock, 'ssh')
                    service['banner'] = banner
                    service['name'] = 'ssh'
                    if 'SSH-' in banner:
                        service['version'] = banner.split('\n')[0].strip()
                elif port in [25, 587]:
                    banner = grab_banner(sock, 'smtp')
                    service['banner'] = banner
                    service['name'] = 'smtp'
                    if '220' in banner:
                        service['version'] = banner.split('\n')[0].strip()
                elif port in [1883, 8883]:
                    # MQTT probe
                    try:
                        sock.send(b'\x10\x0c\x00\x04MQTT\x04\x02\x00\x3c\x00\x00')
                        response = sock.recv(1024)
                        if response and response[0] == 0x20:
                            service['name'] = 'mqtt'
                            service['version'] = f"MQTT {response[3]}"
                            service['product'] = 'MQTT Broker'
                    except:
                        pass
                elif port in [5683, 5684]:
                    # CoAP probe
                    try:
                        sock.send(b'\x40\x01\x00\x00\x00\x00')
                        response = sock.recv(1024)
                        if response and response[0] & 0xE0 == 0x40:
                            service['name'] = 'coap'
                            service['product'] = 'CoAP Server'
                    except:
                        pass
                else:
                    # Generic banner grab for unknown ports
                    banner = grab_banner(sock)
                    service['banner'] = banner
                
                return service
    except:
        return None

def identify_vendor(banner: str) -> Optional[str]:
    """Identify vendor from service banner using pattern matching."""
    for vendor, patterns in VENDOR_PATTERNS.items():
        if any(pattern.lower() in banner.lower() for pattern in patterns):
            return vendor
    return None

def resolve_target(target: str) -> str:
    """Resolve domain name to IP address."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as e:
        logger.error(f"Failed to resolve {target}: {str(e)}")
        return target

def parse_ip_range(start_ip: str, end_ip: str) -> List[str]:
    """Parse IP range and return list of IP addresses."""
    try:
        start = ipaddress.IPv4Address(start_ip)
        end = ipaddress.IPv4Address(end_ip)
        
        if start > end:
            raise ValueError("Start IP must be less than or equal to end IP")
            
        return [str(ipaddress.IPv4Address(ip)) for ip in range(int(start), int(end) + 1)]
    except ipaddress.AddressValueError as e:
        raise ValueError(f"Invalid IP address: {str(e)}")

def scan_range(start_ip: str, end_ip: str, config: Optional[ScannerConfig] = None) -> List[Dict]:
    """
    Scan a range of IP addresses concurrently.
    
    Args:
        start_ip: Starting IP address
        end_ip: Ending IP address
        config: Scanner configuration
        
    Returns:
        List of scan results for each IP
    """
    if config is None:
        config = ScannerConfig()
    
    try:
        # Parse and validate IP range
        ip_list = parse_ip_range(start_ip, end_ip)
        logger.info(f"Scanning {len(ip_list)} IP addresses...")
        
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=config.max_workers) as executor:
            # Submit all scan tasks
            future_to_ip = {executor.submit(scan_target, ip, config): ip for ip in ip_list}
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    result = future.result()
                    if result['status'] == 'up':
                        logger.info(f"Found active host: {ip} (Risk: {result['risk_level']})")
                    results.append(result)
                except Exception as e:
                    error_msg = f"Error scanning {ip}: {str(e)}"
                    logger.error(error_msg)
                    results.append({
                        'target': ip,
                        'ip': ip,
                        'ports': [],
                        'services': [],
                        'status': 'error',
                        'error': str(e),
                        'risk_level': 'Unknown',
                        'scan_time': datetime.now().isoformat()
                    })
        
        return results
        
    except ValueError as e:
        logger.error(f"Invalid IP range: {str(e)}")
        return []
    except Exception as e:
        logger.error(f"Error during range scan: {str(e)}")
        return []
