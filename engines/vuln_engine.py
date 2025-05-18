# vuln_engine.py

default_creds = {
    "TP-LINK": [("admin", "admin"), ("admin", "password")],
    "HUAWEI": [("admin", "admin")],
    "D-LINK": [("admin", "admin")],
    "CISCO": [("cisco", "cisco")],
    "ZTE": [("admin", "admin")],
    "NETGEAR": [("admin", "password")]
    # Add more based on your scan results
}

def check_default_credentials(vendor):
    creds = default_creds.get(vendor.upper(), [])
    return creds
def assess_risk(device):
    risk_score = 0

    # Open ports = exposure
    if device["ports"]:
        risk_score += len(device["ports"])

    # If MAC is from known vendor with default creds
    vendor = device.get("vendor", "")
    if check_default_credentials(vendor):
        risk_score += 3

    # If hostname is empty
    if not device.get("hostname"):
        risk_score += 1

    # Score to level
    if risk_score >= 5:
        return "High"
    elif risk_score >= 3:
        return "Medium"
    else:
        return "Low"
