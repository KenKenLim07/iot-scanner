# storage.py

import json
import os

def save_to_json(data, filename="reports/devices.json"):
    os.makedirs("reports", exist_ok=True)
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
