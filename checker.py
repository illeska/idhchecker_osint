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

selected_file_path = None

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

class IPCheckerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("IP Checker v1.3")
        try:
            icon_path = resource_path("icon.ico")
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
        except Exception as e:
            print(f"Note: Could not load icon: {e}")
        self.root.configure(bg="#212121")
        self.root.geometry("800x600")

        self.services = {
            "AbuseIPDB": {"url": "https://www.abuseipdb.com/check/{ip}", "enabled": tk.BooleanVar(value=True)},
            "AlienVault OTX": {"url": "https://otx.alienvault.com/indicator/ip/{ip}", "enabled": tk.BooleanVar(value=True)},
            "VirusTotal": {"url": "https://www.virustotal.com/gui/search/{ip}", "enabled": tk.BooleanVar(value=True)},
            "IBM X-Force": {"url": "https://exchange.xforce.ibmcloud.com/ip/{ip}", "enabled": tk.BooleanVar(value=True)},
            "ThreatBook": {"url": "https://threatbook.io/ip/{ip}", "enabled": tk.BooleanVar(value=True)}
        }

        self.title_label = tk.Label(
            self.root,
            text="IP CHECKER",
            font=("Courier New", 24, "bold"),
        )
        self.title_label.pack(anchor="w", padx=10, pady=(2, 0))

        self.top_right_frame = ttk.Frame(root)
        self.top_right_frame.pack(anchor="ne", padx=10, pady=(10, 0))

        self.select_button = ttk.Button(self.top_right_frame, text="Choose a file", command=self.select_file, bootstyle="primary")
        self.select_button.pack(side="top", pady=2)

        self.start_button = ttk.Button(self.top_right_frame, text="Start IP Checker", command=self.start_script, state="disabled", bootstyle="success", width=20)
        self.start_button.pack(side="top", pady=2)

        self.services_frame = ttk.LabelFrame(root, text="Select Services to Use", bootstyle="info")
        self.services_frame.pack(padx=10, pady=5, fill="x")

        for i, (service_name, service_data) in enumerate(self.services.items()):
            cb = ttk.Checkbutton(
                self.services_frame, 
                text=service_name, 
                variable=service_data["enabled"],
                bootstyle="round-toggle"
            )
            cb.grid(row=i//3, column=i%3, padx=10, pady=5, sticky="w")
        
        self.select_buttons_frame = ttk.Frame(self.services_frame)
        self.select_buttons_frame.grid(row=(len(self.services)-1)//3 + 1, column=0, columnspan=3, pady=5)
        
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

        self.ip_display = tk.Text(root, height=2, width=50, bg="#1e1e1e", fg="#f0f0f0", bd=0, highlightthickness=0)
        self.ip_display.tag_configure("bold", font=("Segoe UI", 10, "bold"))
        self.ip_display.tag_configure("normal", font=("Segoe UI", 10))
        self.ip_display.config(state="disabled", padx=3, pady=3)
        self.ip_display.pack(padx=10, pady=(10, 0), anchor="w")

        # Navigation buttons frame
        self.nav_frame = ttk.Frame(root)
        self.nav_frame.pack(padx=10, pady=3, anchor="w")

        # Navigation buttons (back/next)
        self.back_button = ttk.Button(self.nav_frame, text="⬅️", command=self.previous_ip, width=3, bootstyle="info")
        self.back_button.pack(side="left", padx=5)
        
        self.next_button = ttk.Button(self.nav_frame, text="➡️", command=self.go_next_ip, width=3, bootstyle="info")
        self.next_button.pack(side="left", padx=5)

        self.button_frame = ttk.Frame(root)
        self.button_frame.pack(padx=10, pady=5, anchor="w")

        self.check_button = ttk.Button(self.button_frame, text="Check this IP", command=self.check_current_ip, bootstyle="primary")
        self.check_button.pack(side="left", padx=5)

        self.block_button = ttk.Button(self.button_frame, text="Block it", command=self.block_current_ip, bootstyle="danger")
        self.block_button.pack(side="left", padx=5)

        self.safe_button = ttk.Button(self.button_frame, text="Safe it", command=self.safe_current_ip, bootstyle="success")
        self.safe_button.pack(side="left", padx=5)

        self.disable_action_buttons()
        self.disable_navigation_buttons()

        self.console = scrolledtext.ScrolledText(root, width=100, height=25, state='disabled', bg="#1e1e1e", fg="#f0f0f0", insertbackground="white")
        self.console.pack(padx=10, pady=10, fill="both", expand=True)

        self.file_path = None
        self.ip_history = []  # Track navigation history
        self.ip_list = []
        self.current_index = -1
        self.current_ip = None
        self.center_window()

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
            self.console_log(f"Fichier sélectionné : {file_path}")
            self.start_button.config(state="normal")

    def start_script(self):
        # Verify at least one service is selected
        if not any(service["enabled"].get() for service in self.services.values()):
            messagebox.showwarning(
                "No Services Selected", 
                "Please select at least one service to use for IP checking."
            )
            return

        globals()['selected_file_path'] = self.file_path
        self.check_ip()

    def console_log(self, message):
        self.console.config(state='normal')
        self.console.insert("end", message + "\n")
        self.console.see("end")
        self.console.config(state='disabled')

    def update_ip_label(self, ip, index, total, status="⏳"):
        self.ip_display.config(state="normal")
        self.ip_display.delete("1.0", "end")
        self.ip_display.insert("end", f"{status} IP checking: ", "normal")
        self.ip_display.insert("end", f"{ip}", "bold")
        self.ip_display.insert("end", f" ({index + 1} of {total})", "normal")
        self.ip_display.config(state="disabled")
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
        if self.current_index > 0:
            self.back_button.config(state="normal")
        else:
            self.back_button.config(state="disabled")
        self.next_button.config(state="normal")

    def disable_navigation_buttons(self):
        self.back_button.config(state="disabled")
        self.next_button.config(state="disabled")

    def previous_ip(self):
        if self.current_index > 0:
            self.current_index -= 1
            self.current_ip = self.ip_list[self.current_index]
            self.update_ip_label(self.current_ip, self.current_index, len(self.ip_list))
            self.console_log(f"Navigated back to IP: {self.current_ip}")

    def go_next_ip(self):
        if self.current_index < len(self.ip_list) - 1:
            self.current_index += 1
            self.current_ip = self.ip_list[self.current_index]
            self.update_ip_label(self.current_ip, self.current_index, len(self.ip_list))
            self.console_log(f"Navigated forward to IP: {self.current_ip}")
        elif self.current_index == len(self.ip_list) - 1:
            confirm = messagebox.askyesno("Confirmation", "This is the last IP, are you sure to end it ?")
            if confirm:
                self.ip_display.config(state="normal")
                self.ip_display.delete("1.0", "end")
                self.ip_display.insert("end", "✅ All IPs checked.", "bold")
                self.ip_display.config(state="disabled")
                self.disable_action_buttons()
                self.disable_navigation_buttons()
                self.console_log("Checking Done - All the IPs have been treated.")

    def check_current_ip(self):
        enabled_services = {name: data for name, data in self.services.items() if data["enabled"].get()}
        if not enabled_services:
            messagebox.showwarning(
                "No Services Selected", 
                "Please select at least one service to use for IP checking."
            )
            return
            
        open_web(self.current_ip, enabled_services)
        self.update_ip_label(self.current_ip, self.current_index, len(self.ip_list), status="✅")


    def block_current_ip(self):
        confirm = messagebox.askyesno("Confirmation", f"Are you sure you want to block this IP?")
        if confirm:
            self.disable_action_buttons()
            self.ask_reason("block", self.current_ip)

    def safe_current_ip(self):
        confirm = messagebox.askyesno("Confirmation", f"Are you sure you want to mark this IP as safe?")
        if confirm:
            self.disable_action_buttons()
            self.ask_reason("safe", self.current_ip)

    def ask_reason(self, action_type, ip):
        reason_window = tk.Toplevel(self.root)
        reason_window.title(f"{action_type.capitalize()} Reason")
        reason_window.geometry("400x150")
        reason_window.transient(self.root)
        reason_window.grab_set()

        self.root.update_idletasks()
        x = self.root.winfo_rootx() + 200
        y = self.root.winfo_rooty() + 200
        reason_window.geometry(f"+{x}+{y}")

        label = ttk.Label(reason_window, text=f"Enter reason to {action_type} IP: {ip}")
        label.pack(pady=10)

        reason_var = tk.StringVar()
        entry = ttk.Entry(reason_window, textvariable=reason_var, width=50)
        entry.pack(pady=5)
        entry.focus()

        def submit(event=None):
            reason = reason_var.get().strip()
            if reason:
                reason_window.destroy()
                self.write_ip_status(ip, f"{action_type}ed", reason)
                self.console_log(f"{ip} has been {action_type}ed. Reason: {reason}")
                self.next_ip()

        submit_btn = ttk.Button(reason_window, text="Submit", command=submit, bootstyle="success")
        submit_btn.pack(pady=10)

        reason_window.bind("<Return>", submit)

    def write_ip_status(self, ip, status, reason):
        with open(selected_file_path, 'r') as file:
            lines = file.readlines()
        with open(selected_file_path, 'w') as file:
            for line in lines:
                if line.strip() == ip:
                    file.write(f"{ip} {status} ({reason})\n")
                else:
                    file.write(line)

    def next_ip(self):
        self.current_index += 1
        if self.current_index < len(self.ip_list):
            self.current_ip = self.ip_list[self.current_index]
            self.update_ip_label(self.current_ip, self.current_index, len(self.ip_list))
        else:
            self.ip_display.config(state="normal")
            self.ip_display.delete("1.0", "end")
            self.ip_display.insert("end", "✅ All IPs checked.", "bold")
            self.ip_display.config(state="disabled")
            self.disable_action_buttons()
            self.disable_navigation_buttons()

    def check_ip(self):
        try:
            with open(selected_file_path, 'r') as file:
                ip_addresses = file.readlines()
                if not ip_addresses:
                    raise ValueError("The file is empty")
                ip_addresses = [ip.strip() for ip in ip_addresses]

            self.ip_list = ip_addresses
            self.current_index = 0
            self.current_ip = ip_addresses[0]
            self.update_ip_label(self.current_ip, self.current_index, len(ip_addresses))

        except FileNotFoundError:
            self.console_log("Error: ip_txt.txt file not found in the current directory")
            messagebox.showerror("File Error", "The selected file was not found.")
            return
        except ValueError as e:
            self.console_log(f"Error reading IP addresses: {str(e)}")
            self.console_log("Please ensure each line contains a valid IP address in format: xxx.xxx.xxx.xxx")
            messagebox.showerror("Format Error", f"Error reading IP addresses: {str(e)}\nPlease ensure each line contains a valid IP address.")
            return
        except Exception as e:
            self.console_log(f"Unexpected error occurred while reading the file: {str(e)}")
            messagebox.showerror("Error", f"Unexpected error occurred: {str(e)}")
            return

class PrintRedirector:
    def __init__(self, gui):
        self.gui = gui

    def write(self, message):
        if message.strip():
            self.gui.console_log(message.strip())

    def flush(self):
        pass

def open_web(ip, enabled_services):
    print("Opening IP Checker...")
    time.sleep(1)
    
    service_count = len(enabled_services)
    current = 1
    
    for service_name, service_data in enabled_services.items():
        print(f"Opening {service_name} ({current}/{service_count})...")
        url = service_data["url"].format(ip=ip)
        webbrowser.open(url)
        current += 1
        time.sleep(0.2)
    
    print(f"All selected services ({service_count}) opened for IP: {ip}")

if __name__ == "__main__":
    root = ttk.Window(themename="darkly")
    gui = IPCheckerGUI(root)
    sys.stdout = PrintRedirector(gui)
    root.mainloop()