# IoT Vulnerability Scanner 🔍💥

A Python-based LAN IoT device scanner that identifies all connected devices, fingerprints them, and checks for potential vulnerabilities using CVE data and known weak configurations.

---

## 🚀 Project Goals

- 🔎 Discover all devices connected to a local network (e.g., home Wi-Fi, internal LAN)
- 🧠 Fingerprint devices using MAC address + open ports
- 🛡️ Check for default credentials and known CVEs
- 📊 Generate detailed reports (JSON, plaintext, PDF)
- 🖥️ (Optional) Visual dashboard using Flask or Tkinter

---

## 🧩 Tech Stack

- Python 3
- `nmap`, `scapy`, `socket`, `requests`
- CIRCL CVE API / NVD API (for live CVE queries)
- SQLite or JSON for storage
- Flask / Chart.js / Tkinter for optional dashboard

---

## 🧱 Folder Structure

