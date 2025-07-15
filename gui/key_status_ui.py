import tkinter as tk
from datetime import datetime
import json
from pathlib import Path
from zoneinfo import ZoneInfo
from PIL import Image, ImageTk
from modules.rsa_keys import update_public_key_store
from modules.key_status import update_key_status
from modules.qr_utils import generate_qr_for_public_key

class KeyStorageWindow:
    def __init__(self, root, dashboard_window, safe_email):
        self.root = root
        self.dashboard_window = dashboard_window
        self.email = dashboard_window.email
        self.safe_email = safe_email
        self.root.title("Quản lý khóa")
        self.root.transient(dashboard_window.root)
        self.root.grab_set()

        # Minimum window size
        self.min_width = 600
        self.min_height = 500  # Increased for entries and QR code


        # Modern style setup
        from modules.key_status import get_key_status_color
        from tkinter import ttk
        self.root.configure(bg="#f6faff", padx=20, pady=20)
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("TLabel", font=("Segoe UI", 11), background="#f6faff", foreground="#1976d2")
        self.style.configure("TFrame", background="#f6faff")
        self.style.configure("TEntry", font=("Segoe UI", 11), padding=6)
        self.style.configure("TButton", font=("Segoe UI", 11, "bold"), foreground="#fff", background="#1976d2", borderwidth=0, padding=8)
        self.style.map("TButton", background=[("active", "#1565c0"), ("!active", "#1976d2")], foreground=[("active", "#fff")])

        # Frame for key details
        self.key_frame = ttk.Frame(self.root, style="TFrame")
        self.key_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        labels = [
            "Khóa công khai (Rút gọn):",
            "Ngày tạo:",
            "Ngày hết hạn:",
            "Trạng thái:",
            "Số ngày còn lại:"
        ]
        self.entries = []
        for i, label_text in enumerate(labels):
            ttk.Label(self.key_frame, text=label_text, style="TLabel").grid(row=i, column=0, sticky="w", pady=2)
            entry = ttk.Entry(self.key_frame, width=50, state="readonly", style="TEntry")
            entry.grid(row=i, column=1, sticky="nsew", padx=5, pady=2)
            self.entries.append(entry)

        self.public_key_entry = self.entries[0]
        self.created_entry = self.entries[1]
        self.expires_entry = self.entries[2]
        self.status_entry = self.entries[3]
        self.valid_days_entry = self.entries[4]

        # QR code display
        ttk.Label(self.key_frame, text="QR Code Khóa công khai:", style="TLabel").grid(row=5, column=0, sticky="w", pady=5)
        self.qr_label = tk.Label(self.key_frame, bg="#f6faff")
        self.qr_label.grid(row=5, column=1, sticky="nsew", pady=5)

        # Make columns and rows expandable
        self.key_frame.columnconfigure(0, weight=0)
        self.key_frame.columnconfigure(1, weight=1)
        for i in range(6):
            self.key_frame.rowconfigure(i, weight=1)

        # Make root window expandable
        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)

        # Button frame for Create, Extend, and Close buttons (use grid for consistent layout)
        button_frame = ttk.Frame(self.root, style="TFrame")
        button_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 10))
        self.root.rowconfigure(1, weight=0)  # Button row does not expand vertically
        self.root.columnconfigure(0, weight=1)
        # Place buttons in button_frame using grid for horizontal layout
        btn_opts = {"sticky": "ew", "padx": 5, "ipady": 2}
        btn_new = ttk.Button(button_frame, text="Tạo khóa RSA mới", command=self.create_new_keys, style="TButton")
        btn_new.grid(row=0, column=0, **btn_opts)
        btn_extend = ttk.Button(button_frame, text="Gia hạn khóa RSA", command=self.extend_keys, style="TButton")
        btn_extend.grid(row=0, column=1, **btn_opts)
        btn_close = ttk.Button(button_frame, text="Đóng", command=self.close_window, style="TButton")
        btn_close.grid(row=0, column=2, **btn_opts)
        button_frame.columnconfigure(0, weight=1)
        button_frame.columnconfigure(1, weight=1)
        button_frame.columnconfigure(2, weight=1)

        # Load and display keys with automatic status update
        self.load_keys()

        # Start periodic status update (every 60 seconds)
        self.update_interval = 60000  # 60 seconds in milliseconds
        self.schedule_status_update()

        # Adjust window size
        self.adjust_window_size()

    def adjust_window_size(self):
        """Adjust window size to fit all elements with minimum size constraints."""
        self.root.update_idletasks()
        req_width = max(self.key_frame.winfo_reqwidth() + 60, self.min_width)
        req_height = max(self.key_frame.winfo_reqheight() + 100, self.min_height)
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - req_width) // 2
        y = (screen_height - req_height) // 2
        self.root.geometry(f"{req_width}x{req_height}+{x}+{y}")
        self.root.minsize(700, 500)

    def schedule_status_update(self):
        """Schedule periodic status updates for keys."""
        self.load_keys()  # Update keys and refresh entries
        self.update_job = self.root.after(self.update_interval, self.schedule_status_update)

    def load_keys(self):
        """Load current key, update status, and display in entry widgets."""
        current_key_path = Path(f"./data/{self.safe_email}/rsa_keypair.json")
        qr_path = Path(f"./data/{self.safe_email}/public_key_qr.png")
        now = datetime.now(ZoneInfo("Asia/Ho_Chi_Minh"))

        # Clear existing entry values
        for entry in [self.public_key_entry, self.created_entry, self.expires_entry,
                      self.status_entry, self.valid_days_entry]:
            entry.config(state="normal")
            entry.delete(0, tk.END)

        # Clear QR code
        self.qr_label.config(image="")
        self.qr_image = None  # Prevent garbage collection

        # Update public key store
        update_public_key_store(self.email)

        # Load and update current key
        try:
            with open(current_key_path, "r") as f:
                key_data = json.load(f)
                key_data = update_key_status(key_data, now)
                with open(current_key_path, "w") as f:
                    json.dump(key_data, f, indent=4)
                self.update_key_display(key_data, now)
        except (FileNotFoundError, json.JSONDecodeError):
            pass

        # Load QR code if it exists
        try:
            if(qr_path).exists():
                qr_path, message = generate_qr_for_public_key(self.email, self.safe_email)
                img = Image.open(qr_path)
                img = img.resize((150, 150), Image.Resampling.LANCZOS)
                self.qr_image = ImageTk.PhotoImage(img)
                self.qr_label.config(image=self.qr_image)
        except FileNotFoundError:
            pass  # No QR code, leave label empty

    def update_key_display(self, key_data, now):
        """Update entry widgets with key data, apply color for status."""
        from modules.key_status import get_key_status_color
        public_key = key_data["public_key"]
        created = datetime.fromisoformat(key_data["created"]).strftime("%Y-%m-%d %H:%M:%S")
        expires = datetime.fromisoformat(key_data["expires"]).strftime("%Y-%m-%d %H:%M:%S")
        status = key_data["status"]

        # Calculate valid days left
        expires_dt = datetime.fromisoformat(key_data["expires"])
        valid_days = (expires_dt - now).days
        valid_days_left = str(valid_days) if status != "revoked" else "Revoked"

        # Truncate public key for display
        truncated_key = public_key[:60] + "..." if len(public_key) > 60 else public_key

        # Update entries
        entry_values = [
            (self.public_key_entry, truncated_key),
            (self.created_entry, created),
            (self.expires_entry, expires),
            (self.status_entry, status),
            (self.valid_days_entry, valid_days_left)
        ]
        for entry, value in entry_values:
            entry.config(state="normal")
            entry.delete(0, tk.END)
            entry.insert(0, value)
            entry.config(state="readonly")

        # Apply color for status entry
        color = get_key_status_color(status)
        self.style.configure("Status.TEntry", fieldbackground=color, foreground="#fff")
        self.status_entry.config(style="Status.TEntry")

    def create_new_keys(self):
        self.dashboard_window.create_new_keys(callback=self.load_keys)

    def extend_keys(self):
        self.dashboard_window.extend_keys(callback=self.load_keys)

    def close_window(self):
        if hasattr(self, 'update_job'):
            self.root.after_cancel(self.update_job)  # Stop periodic updates
        self.root.destroy()