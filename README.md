# 🔐 IP Checker OSINT - v1.1

**IP Checker** is a professional application designed for cybersecurity IP analysis.  
It allows you to quickly assess the reputation of IP addresses using multiple specialized services, through a clean, modern, and interactive user interface.

---

## ⚠️ Disclaimer

**This project is intended for educational or professional/legal use only.**  
The author is not responsible for any illegal or malicious use.  
Users are solely responsible for complying with applicable laws in their country or organization.

---


## 🆕 What's New in v1.1

- ✅ New "Safe it" button added for marking IPs as safe
- 📝 Popup for entering a reason after blocking or safing an IP
- 💾 The chosen reason is automatically saved next to the IP in the original `.txt` file:
  - Example: `192.168.1.1 blocked (malicious activity)`
- ⌨️ You can now submit the reason by pressing Enter
- 🎨 Visual improvements:
  - "IP Checker v1.1" label added in top-left corner
  - Proper layout integration without resizing the window

---


## 🚀 Features

- Sleek dark-themed GUI (Tkinter + ttkbootstrap)
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
- Interactive buttons: Check / Skip / Block / Safe
- Progress indicator: IP checking: ...

---

## ⚙️ Dependencies

Install the required Python packages with:

    pip install ttkbootstrap

### 🖥️ If you're on Linux:

    sudo apt install python3-tk

---

## 📦 How to Use

1. Run the script:

    python checker.py

2. Click "Choose a file" and select a `.txt` file with IP addresses (one per line).

3. Click "Start IP Checker".

4. For each IP, choose:
   - ✅ Check this IP → Opens all 5 scanning websites
   - ⛔ Block it → Add `blocked (reason)` in file
   - ✅ Safe it → Add `safed (reason)` in file
   - ⏭️ Skip this IP → Moves to the next address

---

## 📄 Expected File Format

Example `ip_list.txt`:

    192.168.1.1
    8.8.8.8
    1.1.1.1

---

## 🛡️ Legal Notices

- Software developed by illeska
- Current version: 1.1
- Uses the following external services:
  - ttkbootstrap
  - AbuseIPDB
  - AlienVault OTX
  - VirusTotal
  - IBM X-Force Exchange
  - ThreatBook

## 🧭 Roadmap

### Planned big features for future versions:

- 🌐 Multi-language Support *(v2.x)*
- 🎯 Possible integration of WHOIS auto-lookup to enrich IP data with ASN, domain, geolocation, etc. *(v3.x)*
- 📊 Display IP analysis results directly in the interface, powered by API integration *(v4.x)*

### Planned tiny features for future releases:

- ✅ Checkbox filter to select which services to use *(v1.2)*
- ↔️ Navigation through previously scanned IPs (back/next) *(v1.2)*
- 📄 Option to customize the display theme (dark/light modes) *(v1.3)*
- 📝 Customizable file import/export settings *(v1.x)*
- ➕ Integration of additional threat intelligence platforms *(v1.x)*
- 📊 Basic statistics and visualization of results for the scanned IPs (total blocked, skipped, etc.) directly within the interface *(v1.x)*
- ⚙️ Executable file for easy installation and use *(v1.9)*
## 📬 Contact

For suggestions or questions:  
DM ME.  
# ipchecker
# ipchecker_osint
