"""
Configuration settings for the IoT Scanner application.
"""

# Scanner Configuration
SCAN_TIMEOUT = 5  # seconds
MAX_THREADS = 10
DEFAULT_PORTS = [80, 443, 8080, 8443]

# Network Configuration
DEFAULT_INTERFACE = "eth0"
SUBNET_MASK = "24"

# Output Configuration
REPORT_DIR = "reports"
ASSETS_DIR = "assets"

# API Keys and Credentials
# Add your API keys and credentials here
API_KEYS = {
    "shodan": "",
    "censys": "",
} 