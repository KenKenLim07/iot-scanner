"""
Input/Output utility functions for the IoT Scanner.
"""

import os
from datetime import datetime
from storage import storage

def save_json_report(data, filename=None):
    """Save scan results to a JSON file using the storage module."""
    return storage.save_json(data, filename)

def load_json_report(filename):
    """Load scan results from a JSON file using the storage module."""
    return storage.load_json(filename)

def ensure_directory(directory):
    """Ensure a directory exists, create if it doesn't."""
    os.makedirs(directory, exist_ok=True) 