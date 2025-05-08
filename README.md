# 🔐 IP Checker OSINT - v1.0

**IP Checker** is a professional application designed for cybersecurity IP analysis.  
It allows you to quickly assess the reputation of IP addresses using multiple specialized services, through a clean, modern, and interactive user interface.

---

## ⚠️ Disclaimer

**This project is intended for educational or professional/legal use only.**  
The author is not responsible for any illegal or malicious use.  
Users are solely responsible for complying with applicable laws in their country or organization.

---
## 🚀 Features

- Sleek dark-themed GUI (Tkinter + ttkbootstrap)
- Load a `.txt` file containing one IP address per line
- Manual inspection of each IP through:
  - [AbuseIPDB](https://www.abuseipdb.com)
  - [AlienVault OTX](https://otx.alienvault.com)
  - [VirusTotal](https://www.virustotal.com)
  - [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com)
  - [ThreatBook](https://threatbook.io)
- Block and flag IPs directly in the file (`xxx.xxx.xxx.xxx blocked`)
- Real-time console log inside the interface
- Interactive buttons: *Check / Skip / Block*
- Progress indicator: `IP checking: ...`

---

## ⚙️ Dependencies

Install the required Python packages with:

```bash
pip install ttkbootstrap
```

### 🖥️ If you're on Linux:

```bash
# tkinter may not be installed by default, so install it manually if needed:
sudo apt install python3-tk
```

---

## 📦 How to Use

1. Run the script:
```bash
python checker.py
```

2. Click **"Choose a file"** and select a `.txt` file with IP addresses (one per line).

3. Click **"Start IP Checker"**.

4. For each IP, choose:
   - ✅ Check this IP → Opens all 5 scanning websites
   - ⛔ Block it → Rewrites the line as `IP blocked`
   - ⏭️ Skip this IP → Moves to the next address

---

## 📄 Expected File Format

Example `ip_list.txt`:

```
192.168.1.1
8.8.8.8
1.1.1.1
```

---

## 🛡️ Legal Notices

- Software developed by illeska
- Current version: **1.0**
- Uses the following external services:
  - [ttkbootstrap](https://ttkbootstrap.readthedocs.io) (GUI framework)
  - [AbuseIPDB](https://www.abuseipdb.com)
  - [AlienVault OTX](https://otx.alienvault.com)
  - [VirusTotal](https://www.virustotal.com)
  - [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com)
  - [ThreatBook](https://threatbook.io)

---

## 🧭 Roadmap (Coming Soon)

Planned features for future releases:

- 📂 Export `.log` files with analyzed, blocked, and skipped IPs
- ✅ Checkbox filter to select which services to use
- ➕ Integration of additional threat intelligence platforms
- ↔️ Navigation through previously scanned IPs (back/next)
- 🔄 Optional **automated mode** for batch processing all IPs
- 🎯 Possible integration of **WHOIS auto-lookup** to enrich IP data with ASN, domain, geolocation, etc.
- g

---

## 📬 Contact

For suggestions or questions:  
DM ME.
# ipchecker
