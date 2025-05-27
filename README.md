<h1 align="center">IDH Checker v2.2.5 (Fixes Bugs)</h1>
<p align="center">
IP Addresses, Domain Names and Hashes Checker - via OSint 
</p>


---

> **⚠️ Disclaimer**  
> This tool is intended for **ethical** and **legal** usage only. The author is not responsible for any illegal or malicious activities conducted with this tool. Always ensure compliance with local laws and regulations regarding cybersecurity and data privacy

## 💡 What is IDH Checker?
**IDH Checker** is a professional tool for cybersecurity experts, network administrators, and threat analysts to quickly assess the **reputation** and **integrity** of **IP addresses**, **domain names**, and **file hashes**. The tool leverages multiple **OSINT (Open Source Intelligence)** services to gather comprehensive information about these elements, helping users identify potential risks and malicious entities.

- **IP addresses**: Check the reputation and security risks associated with an IP.
- **Domain names**: Analyze the reputation, age, and other factors of a domain.
- **Hashes**: Validate the integrity of files and identify known malicious files using hash values (MD5, SHA-1, SHA-256).


## 🔄 What's fixed in v2.2.5 *(Bug fixes release)*

- 🐞 Fixed an issue where entries marked as **safe** were incorrectly shown as `"no results yet"` in the Excel output.

## 🆕 What's New in v2.2.5

- 📊 Improve the stats box (UI)
- 🔄 Make the "Statistics" scrollable like "Services to Use"


## 🛠 Features

- Sleek GUI with multiple themes available (including dark mode) using Tkinter + ttkbootstrap  
- Load a `.txt` file containing one IP address or domain name or hash per line  
- Manual inspection of each IP or domain or hash
- Block and flag IPs or domains or hash directly in the file:
  - `xxx.xxx.xxx.xxx blocked (reason)``
  - `example.com safed (reason)`
- Real-time console log inside the interface  
- Interactive buttons: Check / Block / Safe  
- Navigation buttons: Back / Next to move between already viewed entries  
- Progress indicator: Checking...  
- Statistics counter: total, blocked, safe, pending entries  
- Ability to export your results into a `.csv` file  

---

## 📦 Installation

### 💻 Windows
1. Download the `IDH Checker.exe` file from the releases section  
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

## 📋 How to Use IDH Checker

1. Launch the application (double-click the executable or run the script)  

2. Select which services you want to use via the checkboxes  

3. Click "Choose a file" and select a `.txt` file with **IP addresses or Domain names or Hashes** (one per line)  

4. Click "Start IDH Checker"  

5. For each entry (IP or domain), choose:  
   - ✅ Check this IP/Domain → Opens all selected scanning websites in your browser  
   - ⛔ Block it → Add `blocked (reason)` in file  
   - ✅ Safe it → Add `safed (reason)` in file  
   - ↔️ Use **Back** or **Next** to revisit or move between entries  

6. Refer to the **statistics bar** for:  
    - Total number of entries  
    - How many have been marked "blocked"  
    - How many are considered "safe"  
    - How many remain unprocessed  



## 📄 Expected File Format

Example `idh_list.txt`:

```
192.168.1.1  
example.com
c0202cf6...

```

---

## 🧭 Roadmap

### Planned big features for future versions:

- 🔀 Transition from one service interface to another *(v3.0)*
- 🎯 Possible integration of WHOIS auto-lookup to enrich IP data with ASN, domain, geolocation, etc. *(v3.x)*  
- 📊 Display IP analysis results directly in the interface, powered by API integration *(v4.x)*  

### Planned tiny features for the v2:
- ⏳ Add all-time stats in the options *(v2.3)*
- 🌐 French language Support *(v2.4)*
- ⚙️ Have a preset for "services to use" when the user modifies it *(v2.5)*
- 🖋️ Sign the file by adding date, time, and author during export *(v2.6)*
- 📁 Excel input in "choose a file" *(v2.7)*
- 🌐 Arabic language Support *(v2.8)*
- ❌ Auto-close previously opened scan tabs when a new IP is checked *(v2.9)*  

  

---

## 🛡️ Legal Notices

- Software developed by illeska  
- Current version: 2.2.5
- Uses the following external services:
  - ttkbootstrap  
  - AbuseIPDB  
  - AlienVault OTX  
  - VirusTotal  
  - IBM X-Force Exchange  
  - ThreatBook  
  - Cleantalk Blacklists  



## 🎨 Contributing
We welcome contributions! If you want to improve this project or fix any bugs, feel free to fork the repository and submit a pull request.

## 📞 Contact


For suggestions or questions:  
DM ME.  
# idhchecker_osint