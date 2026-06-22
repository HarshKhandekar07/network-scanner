import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import queue
import os
from scanner import get_local_ip, get_default_subnet, scan_network
from utils import export_to_csv

class NetworkScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Scanner Utility")
        self.root.geometry("850x600")
        self.root.configure(bg="#1E1E24")  # Dark Slate Background
        self.root.minsize(750, 500)
        
        self.devices = []
        self.scan_queue = queue.Queue()
        self.is_scanning = False
        
        # Detect host network configurations
        self.local_ip = get_local_ip()
        self.default_subnet = get_default_subnet()
        
        # Configure overall ttk styling
        self.setup_styles()
        
        # Build UI layout components
        self.create_widgets()
        
        # Start queue polling loop
        self.root.after(100, self.process_queue)

    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")
        
        # Treeview styling for dark theme
        self.style.configure("Treeview",
            background="#2A2A35",
            foreground="#FFFFFF",
            rowheight=32,
            fieldbackground="#2A2A35",
            bordercolor="#3A3A4A",
            borderwidth=0,
            font=("Helvetica", 10)
        )
        self.style.map("Treeview",
            background=[("selected", "#5865F2")],  # Discord-like Accent Blue
            foreground=[("selected", "#FFFFFF")]
        )
        self.style.configure("Treeview.Heading",
            background="#18181F",
            foreground="#FFFFFF",
            font=("Helvetica", 10, "bold"),
            borderwidth=1,
            relief="flat"
        )
        self.style.map("Treeview.Heading",
            background=[("active", "#252530")]
        )
        
        # Styled Progressbar
        self.style.configure("Custom.Horizontal.TProgressbar",
            troughcolor="#18181F",
            background="#00C897",  # Emerald Green
            thickness=15
        )

    def create_widgets(self):
        # --- Top Header & Control Panel ---
        self.control_frame = tk.Frame(self.root, bg="#2A2A35", bd=0)
        self.control_frame.pack(fill=tk.X, padx=15, pady=15)
        
        # Label & Entry for Subnet Target
        self.subnet_label = tk.Label(self.control_frame, text="Scan Target (Subnet or Range):", 
                                     bg="#2A2A35", fg="#FFFFFF", font=("Helvetica", 11, "bold"))
        self.subnet_label.grid(row=0, column=0, padx=15, pady=15, sticky="w")
        
        self.subnet_entry = tk.Entry(self.control_frame, bg="#1E1E24", fg="#FFFFFF", 
                                     insertbackground="#FFFFFF", font=("Helvetica", 11),
                                     bd=0, highlightthickness=1, highlightbackground="#3A3A4A",
                                     highlightcolor="#5865F2")
        self.subnet_entry.insert(0, self.default_subnet)
        self.subnet_entry.grid(row=0, column=1, padx=5, pady=15, ipady=6, ipadx=10, sticky="ew")
        
        # Scan trigger button
        self.scan_button = tk.Button(self.control_frame, text="Start Scan", command=self.trigger_scan,
                                     bg="#5865F2", fg="#FFFFFF", activebackground="#4752C4",
                                     activeforeground="#FFFFFF", font=("Helvetica", 10, "bold"),
                                     bd=0, cursor="hand2", padx=20, pady=6)
        self.scan_button.grid(row=0, column=2, padx=15, pady=15)
        
        # Bind hover effects
        self.scan_button.bind("<Enter>", lambda e: self.scan_button.configure(bg="#4752C4"))
        self.scan_button.bind("<Leave>", lambda e: self.scan_button.configure(bg="#5865F2"))
        
        self.control_frame.columnconfigure(1, weight=1)

        # --- Statistics Cards Frame ---
        self.stats_frame = tk.Frame(self.root, bg="#1E1E24")
        self.stats_frame.pack(fill=tk.X, padx=15, pady=(0, 10))
        
        self.card_local_ip = self.create_stat_card(self.stats_frame, "YOUR LOCAL IP", self.local_ip, 0)
        self.card_device_count = self.create_stat_card(self.stats_frame, "DEVICES DETECTED", "0", 1)
        self.card_progress_pct = self.create_stat_card(self.stats_frame, "SCAN PROGRESS", "Idle", 2)
        
        self.stats_frame.columnconfigure(0, weight=1)
        self.stats_frame.columnconfigure(1, weight=1)
        self.stats_frame.columnconfigure(2, weight=1)

        # --- Progress Bar Area ---
        self.progress_frame = tk.Frame(self.root, bg="#1E1E24")
        self.progress_frame.pack(fill=tk.X, padx=15, pady=(0, 15))
        
        self.progress_bar = ttk.Progressbar(self.progress_frame, style="Custom.Horizontal.TProgressbar",
                                            mode="determinate", value=0)
        self.progress_bar.pack(fill=tk.X, ipady=2)

        # --- Main Results Table (Treeview) ---
        self.table_frame = tk.Frame(self.root, bg="#1E1E24")
        self.table_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))
        
        columns = ("ip", "mac", "hostname", "vendor")
        self.tree = ttk.Treeview(self.table_frame, columns=columns, show="headings", style="Treeview")
        
        self.tree.heading("ip", text="IP Address")
        self.tree.heading("mac", text="MAC Address")
        self.tree.heading("hostname", text="Hostname")
        self.tree.heading("vendor", text="Device Vendor")
        
        self.tree.column("ip", width=140, anchor="center")
        self.tree.column("mac", width=160, anchor="center")
        self.tree.column("hostname", width=180, anchor="w")
        self.tree.column("vendor", width=200, anchor="w")
        
        # Add a dark-styled scrollbar
        self.scrollbar = ttk.Scrollbar(self.table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=self.scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # --- Footer Operations Panel ---
        self.footer_frame = tk.Frame(self.root, bg="#1E1E24")
        self.footer_frame.pack(fill=tk.X, padx=15, pady=(0, 15))
        
        self.status_label = tk.Label(self.footer_frame, text="Ready to scan network.", 
                                     bg="#1E1E24", fg="#8E9297", font=("Helvetica", 9, "italic"))
        self.status_label.pack(side=tk.LEFT, pady=5)
        
        self.export_button = tk.Button(self.footer_frame, text="Export CSV", command=self.trigger_export,
                                       bg="#2A2A35", fg="#FFFFFF", activebackground="#3A3A4A",
                                       activeforeground="#FFFFFF", font=("Helvetica", 9, "bold"),
                                       bd=0, cursor="hand2", padx=15, pady=5, state=tk.DISABLED)
        self.export_button.pack(side=tk.RIGHT)
        
        self.export_button.bind("<Enter>", lambda e: self.export_hover_effect(True))
        self.export_button.bind("<Leave>", lambda e: self.export_hover_effect(False))

    def create_stat_card(self, parent, title, value, col):
        card = tk.Frame(parent, bg="#2A2A35", bd=0)
        card.grid(row=0, column=col, padx=5 if col == 1 else (0 if col == 0 else 10), sticky="ew")
        
        title_lbl = tk.Label(card, text=title, bg="#2A2A35", fg="#8E9297", font=("Helvetica", 8, "bold"))
        title_lbl.pack(anchor="w", padx=15, pady=(12, 2))
        
        value_lbl = tk.Label(card, text=value, bg="#2A2A35", fg="#FFFFFF", font=("Helvetica", 14, "bold"))
        value_lbl.pack(anchor="w", padx=15, pady=(0, 12))
        
        return value_lbl

    def export_hover_effect(self, enter):
        if self.export_button["state"] != tk.DISABLED:
            self.export_button.configure(bg="#3A3A4A" if enter else "#2A2A35")

    def trigger_scan(self):
        if self.is_scanning:
            return
            
        target = self.subnet_entry.get().strip()
        if not target:
            messagebox.showwarning("Input Error", "Please provide a valid subnet target (e.g. 192.168.1.0/24).")
            return
            
        self.is_scanning = True
        self.scan_button.configure(state=tk.DISABLED, bg="#3A3A4A", text="Scanning...")
        self.export_button.configure(state=tk.DISABLED, bg="#1E1E24")
        self.status_label.configure(text="Resolving target and starting active scan threads...", fg="#00C897")
        
        # Clear Treeview and local cache
        self.devices.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        self.card_device_count.configure(text="0")
        self.card_progress_pct.configure(text="0%")
        self.progress_bar.configure(value=0)
        
        # Spin scan off to a background thread to prevent UI freezing
        scan_thread = threading.Thread(target=self.run_background_scan, args=(target,), daemon=True)
        scan_thread.start()

    def run_background_scan(self, target):
        try:
            results = scan_network(target, progress_callback=self.on_scan_progress)
            self.scan_queue.put(("complete", results))
        except Exception as e:
            self.scan_queue.put(("error", str(e)))

    def on_scan_progress(self, progress_dict):
        # Thread-safe queue submission for real-time status updates
        self.scan_queue.put(("progress", progress_dict))

    def process_queue(self):
        """
        Polls the queue at regular intervals for async worker updates.
        Runs safely on the main GUI thread.
        """
        try:
            while True:
                msg_type, payload = self.scan_queue.get_nowait()
                
                if msg_type == "progress":
                    scanned = payload["scanned"]
                    total = payload["total"]
                    percentage = payload["percentage"]
                    device = payload["current_device"]
                    
                    self.progress_bar.configure(value=percentage)
                    self.card_progress_pct.configure(text=f"{percentage}%")
                    self.status_label.configure(text=f"Scanning network: {scanned}/{total} IPs analyzed...")
                    
                    # If an active device is found, insert it into the list immediately
                    if device:
                        self.devices.append(device)
                        self.tree.insert("", tk.END, values=(
                            device["ip"], 
                            device["mac"], 
                            device["hostname"], 
                            device["vendor"]
                        ))
                        self.card_device_count.configure(text=str(len(self.devices)))
                        
                elif msg_type == "complete":
                    self.is_scanning = False
                    self.scan_button.configure(state=tk.NORMAL, bg="#5865F2", text="Start Scan")
                    self.status_label.configure(text=f"Scan complete. Found {len(self.devices)} active device(s).", fg="#00C897")
                    
                    if len(self.devices) > 0:
                        self.export_button.configure(state=tk.NORMAL, bg="#2A2A35")
                    
                    self.progress_bar.configure(value=100)
                    self.card_progress_pct.configure(text="Finished")
                    
                elif msg_type == "error":
                    self.is_scanning = False
                    self.scan_button.configure(state=tk.NORMAL, bg="#5865F2", text="Start Scan")
                    self.status_label.configure(text="Scan failed due to an error.", fg="#FF3333")
                    self.card_progress_pct.configure(text="Failed")
                    messagebox.showerror("Scan Error", f"An error occurred during scanning:\n{payload}")
                    
        except queue.Empty:
            pass
            
        # Reschedule queue polling
        self.root.after(100, self.process_queue)

    def trigger_export(self):
        if not self.devices:
            return
            
        # Request destination file path from user
        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
            initialfile="devices.csv",
            title="Export Scan Results"
        )
        
        if filepath:
            success, msg = export_to_csv(filepath, self.devices)
            if success:
                messagebox.showinfo("Export Success", msg)
                self.status_label.configure(text="Scan results successfully written to file.", fg="#00C897")
            else:
                messagebox.showerror("Export Error", msg)
                self.status_label.configure(text="Failed to export results.", fg="#FF3333")

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScannerApp(root)
    root.mainloop()
