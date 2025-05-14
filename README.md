# 🔐 IP Checker OSINT - v1.5

**IP Checker** is a professional application designed for cybersecurity IP analysis.  
It allows you to quickly assess the reputation of IP addresses using multiple specialized services, through a clean, modern, and interactive user interface.

---

## ⚠️ Disclaimer

**This project is intended for educational or professional/legal use only.**  
The author is not responsible for any illegal or malicious use.  
Users are solely responsible for complying with applicable laws in their country or organization.

---

## 🆕 What's New in v1.5

- 📊 Integrated IP statistics (blocked, safe, pending) shown inside the GUI  
- 🎛️ Modified UI: Check IP, Block IP, and Safe IP

---

## 🚀 Features

- Sleek GUI with multiple themes available (including dark mode) using Tkinter + ttkbootstrap
- Load a `.txt` file containing one IP address per line
- Manual inspection of each IP through:
  - AbuseIPDB
  - AlienVault OTX
  - VirusTotal
  - IBM X-Force Exchange
  - ThreatBook
- Block and flag IPs directly in the file:
  - `xxx.xxx.xxx.xxx blocked (reason)`
  - `xxx.xxx.xxx.xxx safed (reason)`
- Real-time console log inside the interface
- Interactive buttons: Check / Block / Safe
- Navigation buttons: Back / Next to move between IPs already viewed
- Progress indicator: IP checking: ...
- Statistics counter: total, blocked, safe, pending IPs  

---

## 📦 Installation

### 💻 Windows
1. Download the `IP Checker.exe` file from the releases section
2. Double-click the executable to launch the application (no installation required)

### 🐧 Linux
The Linux executable is under development. For now, use the script version:
1. Install dependencies:
   ```
   sudo apt install python3-tk
   pip install ttkbootstrap
   ```
2. Run `python3 checker.py`

---

## 📋 How to Use IP Checker

1. Launch the application (double-click the executable or run the script)

2. Select which services you want to use via the checkboxes

3. Click "Choose a file" and select a `.txt` file with IP addresses (one per line)

4. Click "Start IP Checker"

5. For each IP, choose:
   - ✅ Check this IP → Opens all selected scanning websites in your browser
   - ⛔ Block it → Add `blocked (reason)` in file
   - ✅ Safe it → Add `safed (reason)` in file
   - ↔️ Use **Back** or **Next** to revisit or move between IPs  

6. Refer to the **statistics bar** for:
    - Total number of IPs
    - How many have been marked "blocked"
    - How many are considered "safe"
    - How many remain unprocessed  

---

## 📄 Expected File Format

Example `ip_list.txt`:

    192.168.1.1
    8.8.8.8
    1.1.1.1

---

## 🛡️ Legal Notices

- Software developed by illeska
- Current version: 1.5
- Uses the following external services:
  - ttkbootstrap
  - AbuseIPDB
  - AlienVault OTX
  - VirusTotal
  - IBM X-Force Exchange
  - ThreatBook

## 🧭 Roadmap

### Planned big features for future versions:

- 🔄 Software name change to reflect expanded functionality *(v2.0)*
- 🌐 Multi-language Support *(v2.x)*
- 🎯 Possible integration of WHOIS auto-lookup to enrich IP data with ASN, domain, geolocation, etc. *(v3.x)*
- 📊 Display IP analysis results directly in the interface, powered by API integration *(v4.x)*

### Planned tiny features for the v1 :

- ➕ Integration of additional threat intelligence platforms *(v1.6)*
- 🔍 Support for verifying domain names, in addition to IP addresses *(v1.6)*
- 📝 Customizable file import/export settings *(v1.7)*
- ❌ Auto-close previously opened scan tabs when a new IP is checked *(v1.8)*
- 🔍 Support for verifying hashes, in addition to IP addresses and domains *(v1.9)*

## 📬 Contact

For suggestions or questions:  
DM ME.  
# ipchecker_osint
