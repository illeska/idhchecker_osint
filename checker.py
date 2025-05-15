import ctypes
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
except:
    pass

import os
import sys
import webbrowser
import time
import ttkbootstrap as ttk
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
from ttkbootstrap.style import Style
import re
import socket

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

def detect_address_type(address):
    if is_valid_ip(address):
        return "ip"
    elif is_valid_domain(address):
        return "dns"
    else:
        return "unknown"

class IPCheckerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("IP Checker v1.6")

        try:
            icon_path = resource_path("icon.ico")
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
        except Exception as e:
            print(f"Note: Could not load icon: {e}")

        self.root.configure(bg="#212121")
        self.root.geometry("700x850")

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

        self.title_label = tk.Label(self.root, text="IP & DNS CHECKER", font=("Courier New", 24, "bold"))
        self.title_label.pack(anchor="w", padx=10, pady=(2, 0))

        self.top_right_frame = ttk.Frame(root)
        self.top_right_frame.pack(anchor="ne", padx=10, pady=(10, 0))

        self.select_button = ttk.Button(self.top_right_frame, text="Choose a file", command=self.select_file, bootstyle="primary")
        self.select_button.pack(padx=5)

        self.start_button = ttk.Button(self.top_right_frame, text="Start Checker", command=self.start_script, state="disabled", bootstyle="success", width=30)
        self.start_button.pack(padx=5, pady=(0, 0), ipady=10)

        menu_bar = tk.Menu(self.root)
        options_menu = tk.Menu(menu_bar, tearoff=0)
        theme_menu = tk.Menu(options_menu, tearoff=0)
        self.theme_var = tk.StringVar(value="darkly")
        for theme in ["darkly", "flatly", "cyborg", "superhero"]:
            theme_menu.add_radiobutton(
                label=theme,
                variable=self.theme_var,
                value=theme,
                command=lambda: self.change_theme(self.theme_var.get())
            )
        options_menu.add_cascade(label="Theme", menu=theme_menu)
        menu_bar.add_cascade(label="Options", menu=options_menu)
        self.root.config(menu=menu_bar)

        self.services_frame = ttk.LabelFrame(root, text="Select Services to Use", bootstyle="info")
        self.services_frame.pack(padx=10, pady=5, fill="x")

        for i, (service_name, service_data) in enumerate(self.services.items()):
            cb = ttk.Checkbutton(
                self.services_frame,
                text=service_name,
                variable=service_data["enabled"],
                bootstyle="round-toggle"
            )
            cb.grid(row=i // 3, column=i % 3, padx=10, pady=5, sticky="w")

        self.select_buttons_frame = ttk.Frame(self.services_frame)
        self.select_buttons_frame.grid(row=(len(self.services) - 1) // 3 + 1, column=0, columnspan=3, pady=5)

        self.select_all_btn = ttk.Button(
            self.select_buttons_frame,
            text="Select All",
            command=self.select_all_services,
            bootstyle="info-outline",
            width=12
        )
        self.select_all_btn.pack(side="left", padx=5)

        self.deselect_all_btn = ttk.Button(
            self.select_buttons_frame,
            text="Deselect All",
            command=self.deselect_all_services,
            bootstyle="info-outline",
            width=12
        )
        self.deselect_all_btn.pack(side="left", padx=5)

        self.address_display = tk.Text(root, height=2, width=50, bg="#1e1e1e", fg="#f0f0f0", bd=0, highlightthickness=0)
        self.address_display.tag_configure("bold", font=("Segoe UI", 10, "bold"))
        self.address_display.tag_configure("normal", font=("Segoe UI", 10))
        self.address_display.config(state="disabled", padx=3, pady=3)
        self.address_display.pack(padx=10, pady=(10, 0), anchor="w")

        self.nav_frame = ttk.Frame(root)
        self.nav_frame.pack(padx=10, pady=3, anchor="w")

        self.back_button = ttk.Button(self.nav_frame, text="⬅️", command=self.previous_address, width=3, bootstyle="info")
        self.back_button.pack(side="left", padx=5)

        self.next_button = ttk.Button(self.nav_frame, text="➡️", command=self.go_next_address, width=3, bootstyle="info")
        self.next_button.pack(side="left", padx=5)

        self.button_frame = ttk.Frame(root)
        self.button_frame.pack(padx=10, pady=5, anchor="w")

        self.check_button = ttk.Button(self.button_frame, text="Check Entry", command=self.check_current_address, bootstyle="primary", width=15)
        self.check_button.pack(side="left", padx=5)

        self.block_button = ttk.Button(self.button_frame, text="Block Entry", command=self.block_current_address, bootstyle="danger")
        self.block_button.pack(side="left", padx=5)

        self.safe_button = ttk.Button(self.button_frame, text="Safe Entry", command=self.safe_current_address, bootstyle="success")
        self.safe_button.pack(side="left", padx=5)

        self.stats_label = tk.Label(root, text="", fg="white", bg="#212121", font=("Segoe UI", 8, "italic"))
        self.stats_label.pack(anchor="w", padx=10, pady=(0, 5))

        self.disable_action_buttons()
        self.disable_navigation_buttons()

        self.console = scrolledtext.ScrolledText(root, width=100, height=25, state='disabled', bg="#1e1e1e", fg="#f0f0f0", insertbackground="white")
        self.console.pack(padx=10, pady=10, fill="both", expand=True)

        self.file_path = None
        self.address_history = []
        self.address_list = []
        self.address_types = {}  
        self.current_index = -1
        self.current_address = None
        self.center_window()

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

    def center_window(self):
        self.root.update_idletasks()
        w = self.root.winfo_width()
        h = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (w // 2)
        y = (self.root.winfo_screenheight() // 2) - (h // 2)
        self.root.geometry(f"+{x}+{y}")

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
        
        type_display = "IP" if address_type == "ip" else "Domain"
        
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
            type_display = "IP" if address_type == "ip" else "Domain"
            self.console_log(f"Navigated back to {type_display}: {self.current_address}")

    def go_next_address(self):
        if self.current_index < len(self.address_list) - 1:
            self.current_index += 1
            self.current_address = self.address_list[self.current_index]
            address_type = self.address_types[self.current_address]
            self.update_address_label(self.current_address, address_type, self.current_index, len(self.address_list))
            type_display = "IP" if address_type == "ip" else "Domain"
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
        else:  
            enabled_services = {name: data for name, data in self.services_dns.items() if data["enabled"].get()}
            
        if not enabled_services:
            messagebox.showwarning("No Services Selected", "Please select at least one service for checking.")
            return
            
        open_web(self.current_address, address_type, enabled_services)
        self.update_address_label(self.current_address, address_type, self.current_index, len(self.address_list), status="✅")

    def block_current_address(self):
        address_type = self.address_types[self.current_address]
        type_display = "IP" if address_type == "ip" else "Domain"
        
        if messagebox.askyesno("Confirmation", f"Are you sure you want to block this {type_display}?"):
            self.disable_action_buttons()
            self.ask_reason("block", self.current_address)

    def safe_current_address(self):
        address_type = self.address_types[self.current_address]
        type_display = "IP" if address_type == "ip" else "Domain"
        
        if messagebox.askyesno("Confirmation", f"Are you sure you want to mark this {type_display} as safe?"):
            self.disable_action_buttons()
            self.ask_reason("safe", self.current_address)

    def ask_reason(self, action_type, address):
        reason_window = tk.Toplevel(self.root)
        address_type = self.address_types[address]
        type_display = "IP" if address_type == "ip" else "Domain"
        
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
                        self.console_log(f"Warning: '{addr}' is neither a valid IP nor a domain name. Treating as domain.")
                        addr_type = "dns"  
                    self.address_types[addr] = addr_type
                
                self.current_index = 0
                self.current_address = addresses[0]
                address_type = self.address_types[self.current_address]
                self.update_address_label(self.current_address, address_type, self.current_index, len(addresses))
                

                ip_count = sum(1 for addr_type in self.address_types.values() if addr_type == "ip")
                dns_count = len(self.address_types) - ip_count
                self.console_log(f"Detected {ip_count} IP addresses and {dns_count} domain names.")
                
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
    else: 
        print("Opening Domain Checker...")
        time.sleep(1)
        for i, (name, data) in enumerate(enabled_services.items(), 1):
            print(f"Opening {name} ({i}/{len(enabled_services)})...")
            webbrowser.open(data["url"].format(dns=address))
            time.sleep(0.2)
        print(f"All services opened for domain: {address}.")

if __name__ == "__main__":
    root = ttk.Window(themename="darkly")
    gui = IPCheckerGUI(root)
    sys.stdout = PrintRedirector(gui)
    root.mainloop()