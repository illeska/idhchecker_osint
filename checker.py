CURRENT_VERSION = "2.0"
VERSION_URL = "https://raw.githubusercontent.com/illeska/ipchecker_osint/main/version.txt"


def check_for_update():
    try:
        with urllib.request.urlopen(VERSION_URL) as response:
            latest_version = response.read().decode().strip()
            if latest_version != CURRENT_VERSION:
                answer = messagebox.askyesno(
                    "Update available",
                    f"Current version: {CURRENT_VERSION}\nAvailable version: {latest_version}\n\nDo you want to download the new version?"
                )
                if answer:
                    download_update(latest_version)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to check for updates: {e}")

def download_update(latest_version):
    exe_name = f"IP Checker v{latest_version}.exe"
    exe_url = f"https://github.com/illeska/ipchecker_osint/raw/main/dist/{exe_name.replace(' ', '%20')}"
    new_path = os.path.join(os.path.dirname(sys.executable), exe_name)
    try:
        urllib.request.urlretrieve(exe_url, new_path)
        messagebox.showinfo(
            "Download successful",
            f"New version downloaded successfully.\n\nPath: {new_path}\n\nPlease close this app and run the new version. You can delete this one."
        )
    except Exception as e:
        messagebox.showerror("Error", f"Failed to download the update: {e}")


import ctypes
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
except:
    pass

import urllib.request
import os
import sys
import webbrowser
import time
import ttkbootstrap as ttk
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
from ttkbootstrap.style import Style
import re
from datetime import datetime

selected_file_path = None

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def is_valid_ip(address):
    pattern = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
    if not pattern.match(address):
        return False
    return all(0 <= int(octet) <= 255 for octet in address.split('.'))

def is_valid_domain(address):
    return '.' in address and ' ' not in address and not is_valid_ip(address)

def is_valid_hash(address):
    if re.match(r'^[a-fA-F0-9]{32}$', address):
        return True
    if re.match(r'^[a-fA-F0-9]{40}$', address):
        return True
    if re.match(r'^[a-fA-F0-9]{64}$', address):
        return True
    return False

def detect_address_type(address):
    if is_valid_ip(address):
        return "ip"
    elif is_valid_domain(address):
        return "dns"
    elif is_valid_hash(address):
        return "hash"
    else:
        return "unknown"

class IPCheckerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("IDH Checker v2.0")

        
        self.fonts = {
            "title": ("Poppins", 20, "bold"),
            "subtitle": ("Poppins", 12, "bold"),
            "normal": ("Poppins", 10),
            "console": ("Consolas", 9)
        }

        try:
            icon_path = resource_path("icon.ico")
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
        except Exception as e:
            print(f"Note: Could not load icon: {e}")

        style = Style(theme="cyborg")
        self.root.after(0, self.center_window)
        self.center_window()

        self.services = {
            "AbuseIPDB": {"url": "https://www.abuseipdb.com/check/{ip}", "enabled": tk.BooleanVar(value=True)},
            "AlienVault OTX": {"url": "https://otx.alienvault.com/indicator/ip/{ip}", "enabled": tk.BooleanVar(value=True)},
            "VirusTotal": {"url": "https://www.virustotal.com/gui/search/{ip}", "enabled": tk.BooleanVar(value=True)},
            "IBM X-Force": {"url": "https://exchange.xforce.ibmcloud.com/ip/{ip}", "enabled": tk.BooleanVar(value=True)},
            "ThreatBook": {"url": "https://threatbook.io/ip/{ip}", "enabled": tk.BooleanVar(value=True)},
            "CleanTalk": {"url": "https://cleantalk.org/blacklists/{ip}", "enabled": tk.BooleanVar(value=True)}
        }

        self.services_dns = {
            "AbuseIPDB": {"url": "https://www.abuseipdb.com/check/{dns}", "enabled": tk.BooleanVar(value=True)},
            "AlienVault OTX": {"url": "https://otx.alienvault.com/indicator/domain/{dns}", "enabled": tk.BooleanVar(value=True)},
            "VirusTotal": {"url": "https://www.virustotal.com/gui/domain/{dns}", "enabled": tk.BooleanVar(value=True)},
            "IBM X-Force": {"url": "https://exchange.xforce.ibmcloud.com/url/{dns}", "enabled": tk.BooleanVar(value=True)},
            "ThreatBook": {"url": "https://threatbook.io/domain/{dns}", "enabled": tk.BooleanVar(value=True)},
            "CleanTalk": {"url": "https://cleantalk.org/blacklists/{dns}", "enabled": tk.BooleanVar(value=True)}
        }
        
        self.services_hash = {
            "VirusTotal": {"url": "https://www.virustotal.com/gui/file/{hash}", "enabled": tk.BooleanVar(value=True)},
            "IBM X-Force": {"url": "https://exchange.xforce.ibmcloud.com/malware/{hash}", "enabled": tk.BooleanVar(value=True)},
            "AlienVault OTX": {"url": "https://otx.alienvault.com/indicator/file/{hash}", "enabled": tk.BooleanVar(value=True)}
        }

        self.header_frame = tk.Frame(self.root, height=60)
        self.header_frame.pack(fill="x", pady=(0, 15))
        
        self.title_label = tk.Label(
            self.header_frame, 
            text="IP, DNS & HASH CHECKER", 
            font=self.fonts["title"],
            pady=10
        )
        self.title_label.pack(side="left", padx=20)

        self.main_frame = tk.Frame(self.root, padx=15, pady=15)
        self.main_frame.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        self.top_actions_frame = tk.Frame(self.main_frame)
        self.top_actions_frame.pack(fill="x", pady=(0, 10))
        
        self.select_button = ttk.Button(
            self.top_actions_frame, 
            text="📁 Choose a file", 
            command=self.select_file, 
            bootstyle="primary-outline",
            width=15
        )
        self.select_button.pack(side="left", padx=(0, 10), ipady=5)
        
        self.start_button = ttk.Button(
            self.top_actions_frame, 
            text="▶️ Start Checker", 
            command=self.start_script, 
            state="disabled", 
            bootstyle="success",
            width=20
        )
        self.start_button.pack(side="left", ipady=5)


        menu_bar = tk.Menu(self.root)
        options_menu = tk.Menu(menu_bar, tearoff=0)
        
        theme_menu = tk.Menu(options_menu, tearoff=0)
        self.theme_var = tk.StringVar(value="superhero")  
        for theme in ["superhero", "cosmo", "cyborg", "darkly", "minty", "solar", "united"]:
            theme_menu.add_radiobutton(
                label=theme,
                variable=self.theme_var,
                value=theme,
                command=lambda: self.change_theme(self.theme_var.get())
            )
        options_menu.add_cascade(label="Theme", menu=theme_menu)
        
        export_menu = tk.Menu(options_menu, tearoff=0)
        export_menu.add_command(label="CSV", command=self.export_to_csv)
        options_menu.add_cascade(label="Export", menu=export_menu)
        
        menu_bar.add_cascade(label="Options", menu=options_menu)
        self.root.config(menu=menu_bar)

        self.services_frame = ttk.LabelFrame(
            self.main_frame, 
            text="Services", 
            bootstyle="primary",
            padding=10
        )
        self.services_frame.pack(fill="x", pady=10)

        services_grid = ttk.Frame(self.services_frame)
        services_grid.pack(fill="x")
        
        for i, (service_name, service_data) in enumerate(self.services.items()):
            cb = ttk.Checkbutton(
                services_grid,
                text=service_name,
                variable=service_data["enabled"],
                bootstyle="round-toggle-primary"
            )
            cb.grid(row=i // 3, column=i % 3, padx=10, pady=5, sticky="w")

        self.select_buttons_frame = ttk.Frame(self.services_frame)
        self.select_buttons_frame.pack(pady=(5, 0), anchor="e")

        self.select_all_btn = ttk.Button(
            self.select_buttons_frame,
            text="Select All",
            command=self.select_all_services,
            bootstyle="info-outline",
            width=12
        )
        self.select_all_btn.pack(side="left", padx=5, ipady=3)

        self.deselect_all_btn = ttk.Button(
            self.select_buttons_frame,
            text="Deselect All",
            command=self.deselect_all_services,
            bootstyle="info-outline",
            width=12
        )
        self.deselect_all_btn.pack(side="left", padx=5, ipady=3)


        self.address_container = tk.Frame(self.main_frame, pady=10)
        self.address_container.pack(fill="x")
        
        self.address_label = tk.Label(
            self.address_container, 
            text="Current Entry:", 
            font=self.fonts["subtitle"],
        )
        self.address_label.pack(anchor="w")
        
        self.address_display = tk.Text(
            self.address_container, 
            height=1, 
            width=50, 
            bd=0, 
            highlightthickness=1,
            font=self.fonts["normal"],
            relief="flat",
            padx=10,
            pady=5
        )
        self.address_display.tag_configure("bold", font=(self.fonts["normal"][0], self.fonts["normal"][1], "bold"))
        self.address_display.tag_configure("normal", font=self.fonts["normal"])
        self.address_display.config(state="disabled")
        self.address_display.pack(fill="x", pady=(5, 0))


        self.action_nav_frame = tk.Frame(self.main_frame)
        self.action_nav_frame.pack(fill="x", pady=10)
        
        self.nav_frame = ttk.Frame(self.action_nav_frame)
        self.nav_frame.pack(side="left")

        self.back_button = ttk.Button(
            self.nav_frame, 
            text="⏪", 
            command=self.previous_address, 
            width=5,
            bootstyle="primary-outline"
        )
        self.back_button.pack(side="left", padx=(0, 10), ipady=5)

        self.next_button = ttk.Button(
            self.nav_frame, 
            text="⏭️", 
            command=self.go_next_address, 
            width=5,
            bootstyle="primary-outline"
        )
        self.next_button.pack(side="left", ipady=5)

        self.button_frame = ttk.Frame(self.action_nav_frame)
        self.button_frame.pack(side="right")


        self.check_button = ttk.Button(
            self.button_frame, 
            text="🔍 Check", 
            command=self.check_current_address, 
            bootstyle="primary", 
            width=12
        )
        self.check_button.pack(side="left", padx=5, ipady=5)

        self.safe_button = ttk.Button(
            self.button_frame, 
            text="✅ Safe", 
            command=self.safe_current_address, 
            bootstyle="success", 
            width=12
        )
        self.safe_button.pack(side="left", padx=5, ipady=5)
        
        self.block_button = ttk.Button(
            self.button_frame, 
            text="❌ Block", 
            command=self.block_current_address, 
            bootstyle="danger", 
            width=12
        )
        self.block_button.pack(side="left", padx=5, ipady=5)


        self.stats_label = tk.Label(
            self.main_frame, 
            text="",  
            font=("Poppins", 8, "italic")
        )
        self.stats_label.pack(anchor="w", pady=(0, 5))


        self.console_frame = tk.Frame(
            self.main_frame, 
            padx=1, 
            pady=1
        )
        self.console_frame.pack(fill="both", expand=True)
        
        self.console = scrolledtext.ScrolledText(
            self.console_frame, 
            width=80, 
            height=18,  
            state='disabled',  
            insertbackground="white",
            font=self.fonts["console"],
            padx=10,
            pady=10,
            relief="flat"
        )
        self.console.pack(fill="both", expand=True)

        self.status_bar = tk.Label(
            self.root, 
            text="Ready", 
            bd=1, 
            relief=tk.SUNKEN, 
            anchor=tk.W,
            font=("Poppins", 8),
            padx=10
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        self.disable_action_buttons()
        self.disable_navigation_buttons()

        self.file_path = None
        self.address_history = []
        self.address_list = []
        self.address_types = {}  
        self.current_index = -1
        self.current_address = None

    def export_to_csv(self):
        """Export the data from the current file to a CSV file"""
        if not self.file_path:
            messagebox.showwarning("No File Selected", "Please select a file first before exporting data.")
            return     
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            default_name = f"ipchecker_export_{timestamp}.csv"
            csv_path = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv")],
                initialfile=default_name
            )
            if not csv_path:  
                return
            with open(self.file_path, 'r') as file:
                lines = file.readlines()
            rows_to_export = []
            rows_to_export.append(["Address", "Type", "Status", "Reason"])
            
            for line in lines:
                parts = line.strip().split(None, 1) 
                address = parts[0]
                address_type = self.address_types.get(address, "unknown")
                
                if len(parts) > 1:
                    status_info = parts[1]
                    status_match = re.search(r'(blocked|safed)', status_info, re.IGNORECASE)
                    status = status_match.group(1) if status_match else ""
                    
                    reason_match = re.search(r'\((.*?)\)', status_info)
                    reason = reason_match.group(1) if reason_match else ""
                    
                    rows_to_export.append([address, address_type, status if status else "No result yet", reason])
                else:
                    rows_to_export.append([address, address_type, "No result yet", ""])
            
            with open(csv_path, 'w', newline='', encoding='utf-8') as csv_file:
                for row in rows_to_export:
                    csv_file.write(f'"{row[0]}";"{row[1]}";"{row[2]}";"{row[3]}"\n')
                    
            self.console_log(f"Successfully exported data to {csv_path}")
            messagebox.showinfo("Export Complete", f"Successfully exported data to CSV file:\n{csv_path}")
            
        except Exception as e:
            self.console_log(f"Error exporting to CSV: {e}")
            messagebox.showerror("Export Error", f"Failed to export data: {e}")

    def change_theme(self, selected_theme):
        style = Style()
        try:
            style.theme_use(selected_theme)
            self.console_log(f"Theme changed to: {selected_theme}")
        except Exception as e:
            self.console_log(f"Error changing theme: {e}")

    def select_all_services(self):
        for service in self.services.values():
            service["enabled"].set(True)

    def deselect_all_services(self):
        for service in self.services.values():
            service["enabled"].set(False)

    def center_window(self, width=650, height=750):
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width // 2) - (width // 2)
        y = (screen_height // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def select_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            self.file_path = file_path
            self.console_log(f"Selected File : {file_path}")
            self.start_button.config(state="normal")

    def start_script(self):
        if not any(service["enabled"].get() for service in self.services.values()):
            messagebox.showwarning("No Services Selected", "Please select at least one service to use for checking.")
            return
        globals()['selected_file_path'] = self.file_path
        self.check_addresses()

    def console_log(self, message):
        self.console.config(state='normal')
        self.console.insert("end", message + "\n")
        self.console.see("end")
        self.console.config(state='disabled')

    def update_address_label(self, address, address_type, index, total, status="⏳"):
        self.address_display.config(state="normal")
        self.address_display.delete("1.0", "end")
        
        if address_type == "ip":
            type_display = "IP"
        elif address_type == "dns":
            type_display = "Domain"
        elif address_type == "hash":
            type_display = "Hash"
        else:
            type_display = "Unknown"
        
        self.address_display.insert("end", f"{status} {type_display} checking: ", "normal")
        self.address_display.insert("end", f"{address}", "bold")
        self.address_display.insert("end", f" ({index + 1} of {total})", "normal")
        self.address_display.config(state="disabled")
        self.enable_action_buttons()
        self.update_navigation_buttons()

    def enable_action_buttons(self):
        self.check_button.config(state="normal")
        self.block_button.config(state="normal")
        self.safe_button.config(state="normal")

    def disable_action_buttons(self):
        self.check_button.config(state="disabled")
        self.block_button.config(state="disabled")
        self.safe_button.config(state="disabled")

    def update_navigation_buttons(self):
        self.back_button.config(state="normal" if self.current_index > 0 else "disabled")
        self.next_button.config(state="normal")

    def disable_navigation_buttons(self):
        self.back_button.config(state="disabled")
        self.next_button.config(state="disabled")

    def previous_address(self):
        if self.current_index > 0:
            self.current_index -= 1
            self.current_address = self.address_list[self.current_index]
            address_type = self.address_types[self.current_address]
            self.update_address_label(self.current_address, address_type, self.current_index, len(self.address_list))
            
            if address_type == "ip":
                type_display = "IP"
            elif address_type == "dns":
                type_display = "Domain"
            elif address_type == "hash":
                type_display = "Hash"
            else:
                type_display = "Unknown"
                
            self.console_log(f"Navigated back to {type_display}: {self.current_address}")

    def go_next_address(self):
        if self.current_index < len(self.address_list) - 1:
            self.current_index += 1
            self.current_address = self.address_list[self.current_index]
            address_type = self.address_types[self.current_address]
            self.update_address_label(self.current_address, address_type, self.current_index, len(self.address_list))
            
            if address_type == "ip":
                type_display = "IP"
            elif address_type == "dns":
                type_display = "Domain"
            elif address_type == "hash":
                type_display = "Hash"
            else:
                type_display = "Unknown"
                
            self.console_log(f"Navigated forward to {type_display}: {self.current_address}")
        elif self.current_index == len(self.address_list) - 1:
            if messagebox.askyesno("Confirmation", "This is the last entry, are you sure to end it?"):
                self.address_display.config(state="normal")
                self.address_display.delete("1.0", "end")
                self.address_display.insert("end", "✅ All entries checked.", "bold")
                self.address_display.config(state="disabled")
                self.disable_action_buttons()
                self.disable_navigation_buttons()
                self.console_log("Checking Done - All the entries have been treated.")

    def check_current_address(self):
        address_type = self.address_types[self.current_address]
        
        if address_type == "ip":
            enabled_services = {name: data for name, data in self.services.items() if data["enabled"].get()}
        elif address_type == "dns":  
            enabled_services = {name: data for name, data in self.services_dns.items() if data["enabled"].get()}
        elif address_type == "hash":
            messagebox.showinfo(
                "Hash Checker",
                "Les services suivants sont disponibles pour la vérification des hashes:\n\n" +
                "- VirusTotal: https://www.virustotal.com/gui/file/{hash}\n" +
                "- IBM X-Force: https://exchange.xforce.ibmcloud.com/malware/{hash}\n" +
                "- AlienVault OTX: https://otx.alienvault.com/indicator/file/{hash}"
            )
            enabled_services = {name: data for name, data in self.services_hash.items() if data["enabled"].get()}
        else:
            enabled_services = {}
            
        if not enabled_services:
            messagebox.showwarning("No Services Selected", "Please select at least one service for checking.")
            return
            
        open_web(self.current_address, address_type, enabled_services)
        self.update_address_label(self.current_address, address_type, self.current_index, len(self.address_list), status="✅")

    def block_current_address(self):
        address_type = self.address_types[self.current_address]
        
        if address_type == "ip":
            type_display = "IP"
        elif address_type == "dns":
            type_display = "Domain"
        elif address_type == "hash":
            type_display = "Hash"
        else:
            type_display = "Unknown"
        
        if messagebox.askyesno("Confirmation", f"Are you sure you want to block this {type_display}?"):
            self.disable_action_buttons()
            self.ask_reason("block", self.current_address)

    def safe_current_address(self):
        address_type = self.address_types[self.current_address]
        
        if address_type == "ip":
            type_display = "IP"
        elif address_type == "dns":
            type_display = "Domain"
        elif address_type == "hash":
            type_display = "Hash"
        else:
            type_display = "Unknown"
        
        if messagebox.askyesno("Confirmation", f"Are you sure you want to mark this {type_display} as safe?"):
            self.disable_action_buttons()
            self.ask_reason("safe", self.current_address)

    def ask_reason(self, action_type, address):
        reason_window = tk.Toplevel(self.root)
        address_type = self.address_types[address]
        
        if address_type == "ip":
            type_display = "IP"
        elif address_type == "dns":
            type_display = "Domain"
        elif address_type == "hash":
            type_display = "Hash"
        else:
            type_display = "Unknown"
        
        reason_window.title(f"{action_type.capitalize()} Reason")
        reason_window.geometry("400x150")
        reason_window.transient(self.root)
        reason_window.grab_set()

        self.root.update_idletasks()
        x = self.root.winfo_rootx() + 200
        y = self.root.winfo_rooty() + 200
        reason_window.geometry(f"+{x}+{y}")

        label = ttk.Label(reason_window, text=f"Enter reason to {action_type} {type_display}: {address}")
        label.pack(pady=10)

        reason_var = tk.StringVar()
        entry = ttk.Entry(reason_window, textvariable=reason_var, width=50)
        entry.pack(pady=5)
        entry.focus()

        def submit(event=None):
            reason = reason_var.get().strip()
            if reason:
                reason_window.destroy()
                self.write_address_status(address, f"{action_type}ed", reason)
                self.console_log(f"{address} has been {action_type}ed. Reason: {reason}")
                self.next_address()
                self.update_stats()

        submit_btn = ttk.Button(reason_window, text="Submit", command=submit, bootstyle="success")
        submit_btn.pack(pady=10)
        reason_window.bind("<Return>", submit)

    def write_address_status(self, address, status, reason):
        with open(selected_file_path, 'r') as file:
            lines = file.readlines()
        with open(selected_file_path, 'w') as file:
            for line in lines:
                if line.strip() == address:
                    file.write(f"{address} {status} ({reason})\n")
                else:
                    file.write(line)

    def next_address(self):
        self.current_index += 1
        if self.current_index < len(self.address_list):
            self.current_address = self.address_list[self.current_index]
            address_type = self.address_types[self.current_address]
            self.update_address_label(self.current_address, address_type, self.current_index, len(self.address_list))
        else:
            self.address_display.config(state="normal")
            self.address_display.delete("1.0", "end")
            self.address_display.insert("end", "✅ All entries checked.", "bold")
            self.address_display.config(state="disabled")
            self.disable_action_buttons()
            self.disable_navigation_buttons()

    def check_addresses(self):
        try:
            with open(selected_file_path, 'r') as file:
                addresses = file.readlines()
                if not addresses:
                    raise ValueError("The file is empty")
            
                addresses = [addr.strip().split()[0] for addr in addresses]
                self.address_list = addresses
                
                for addr in addresses:
                    addr_type = detect_address_type(addr)
                    if addr_type == "unknown":
                        self.console_log(f"Warning: '{addr}' is neither a valid IP, domain name, nor hash. Treating as domain.")
                        addr_type = "dns"  
                    self.address_types[addr] = addr_type
                
                self.current_index = 0
                self.current_address = addresses[0]
                address_type = self.address_types[self.current_address]
                self.update_address_label(self.current_address, address_type, self.current_index, len(addresses))
                

                ip_count = sum(1 for addr_type in self.address_types.values() if addr_type == "ip")
                dns_count = sum(1 for addr_type in self.address_types.values() if addr_type == "dns")
                hash_count = sum(1 for addr_type in self.address_types.values() if addr_type == "hash")
                
                self.console_log(f"Detected {ip_count} IP addresses, {dns_count} domain names, and {hash_count} hashes.")
                
                self.update_stats()

        except Exception as e:
            self.console_log(f"Error loading file: {e}")
            messagebox.showerror("Error", str(e))

    def update_stats(self):
        try:
            with open(selected_file_path, 'r') as f:
                lines = f.readlines()
            total = len(lines)
            blocked = sum(1 for l in lines if "blocked" in l)
            safe = sum(1 for l in lines if "safe" in l)
            remaining = total - blocked - safe
            self.stats_label.config(
                text=f"Total: {total}, Blocked: {blocked}, Safe: {safe}, Remaining: {remaining}"
            )
        except Exception as e:
            self.console_log(f"Error updating stats: {e}")

class PrintRedirector:
    def __init__(self, gui):
        self.gui = gui

    def write(self, message):
        if message.strip():
            self.gui.console_log(message.strip())

    def flush(self):
        pass

def open_web(address, address_type, enabled_services):
    if address_type == "ip":
        print("Opening IP Checker...")
        time.sleep(1)
        for i, (name, data) in enumerate(enabled_services.items(), 1):
            print(f"Opening {name} ({i}/{len(enabled_services)})...")
            webbrowser.open(data["url"].format(ip=address))
            time.sleep(0.2)
        print(f"All services opened for IP: {address}.")
    elif address_type == "dns": 
        print("Opening Domain Checker...")
        time.sleep(1)
        for i, (name, data) in enumerate(enabled_services.items(), 1):
            print(f"Opening {name} ({i}/{len(enabled_services)})...")
            webbrowser.open(data["url"].format(dns=address))
            time.sleep(0.2)
        print(f"All services opened for Domain: {address}.")
    elif address_type == "hash":
        print("Opening Hash Checker...")
        time.sleep(1)
        for i, (name, data) in enumerate(enabled_services.items(), 1):
            print(f"Opening {name} ({i}/{len(enabled_services)})...")
            webbrowser.open(data["url"].format(hash=address))
            time.sleep(0.2)
        print(f"All services opened for Hash: {address}.")

if __name__ == "__main__":
    root = ttk.Window(themename="superhero")
    gui = IPCheckerGUI(root)
    sys.stdout = PrintRedirector(gui)
    check_for_update()
    root.mainloop()