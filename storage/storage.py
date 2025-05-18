# storage.py

"""
Storage module for handling data persistence in the IoT Scanner.
"""

import json
import os
from datetime import datetime
from typing import Any, Dict, Optional

class Storage:
    def __init__(self, base_dir: str = "reports"):
        self.base_dir = base_dir
        self._ensure_base_dir()
    
    def _ensure_base_dir(self) -> None:
        """Ensure the base directory exists."""
        os.makedirs(self.base_dir, exist_ok=True)
    
    def save_json(self, data: Dict[str, Any], filename: Optional[str] = None) -> str:
        """
        Save data to a JSON file.
        
        Args:
            data: The data to save
            filename: Optional filename. If not provided, generates one with timestamp
            
        Returns:
            str: Path to the saved file
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_report_{timestamp}.json"
        
        filepath = os.path.join(self.base_dir, filename)
        
        try:
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=4)
            return filepath
        except Exception as e:
            raise IOError(f"Failed to save data to {filepath}: {str(e)}")
    
    def load_json(self, filename: str) -> Dict[str, Any]:
        """
        Load data from a JSON file.
        
        Args:
            filename: Name of the file to load
            
        Returns:
            Dict[str, Any]: The loaded data
        """
        filepath = os.path.join(self.base_dir, filename)
        
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            raise FileNotFoundError(f"File not found: {filepath}")
        except json.JSONDecodeError:
            raise ValueError(f"Invalid JSON in file: {filepath}")
        except Exception as e:
            raise IOError(f"Failed to load data from {filepath}: {str(e)}")

# Create a default storage instance
storage = Storage()
