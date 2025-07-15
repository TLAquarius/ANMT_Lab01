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

        # Add padding
        self.root.configure(padx=20, pady=20)

        # Frame for key details
        self.key_frame = tk.Frame(self.root)
        self.key_frame.pack(fill="both", pady=10)

        # Entry widgets for key details
        tk.Label(self.key_frame, text="Khóa công khai (Rút gọn):").pack(anchor="w")
        self.public_key_entry = tk.Entry(self.key_frame, width=50, state="readonly")
        self.public_key_entry.pack(fill="x", pady=2)

        tk.Label(self.key_frame, text="Ngày tạo:").pack(anchor="w")
        self.created_entry = tk.Entry(self.key_frame, width=50, state="readonly")
        self.created_entry.pack(fill="x", pady=2)

        tk.Label(self.key_frame, text="Ngày hết hạn:").pack(anchor="w")
        self.expires_entry = tk.Entry(self.key_frame, width=50, state="readonly")
        self.expires_entry.pack(fill="x", pady=2)

        tk.Label(self.key_frame, text="Trạng thái:").pack(anchor="w")
        self.status_entry = tk.Entry(self.key_frame, width=50, state="readonly")
        self.status_entry.pack(fill="x", pady=2)

        tk.Label(self.key_frame, text="Số ngày còn lại:").pack(anchor="w")
        self.valid_days_entry = tk.Entry(self.key_frame, width=50, state="readonly")
        self.valid_days_entry.pack(fill="x", pady=2)

        # QR code display
        tk.Label(self.key_frame, text="QR Code Khóa công khai:").pack(anchor="w", pady=5)
        self.qr_label = tk.Label(self.key_frame)
        self.qr_label.pack(pady=5)

        # Button frame for Create, Extend, and Close buttons
        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=10)
        tk.Button(button_frame, text="Tạo khóa RSA mới", command=self.create_new_keys).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Gia hạn khóa RSA", command=self.extend_keys).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Đóng", command=self.close_window).pack(side=tk.LEFT, padx=5)

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
        self.root.minsize(self.min_width, self.min_height)

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
        """Update entry widgets with key data."""
        public_key = key_data["public_key"]
        created = datetime.fromisoformat(key_data["created"]).strftime("%Y-%m-%d %H:%M:%S")
        expires = datetime.fromisoformat(key_data["expires"]).strftime("%Y-%m-%d %H:%M:%S")
        status = key_data["status"]

        # Calculate valid days left
        expires_dt = datetime.fromisoformat(key_data["expires"])
        valid_days = (expires_dt - now).days
        valid_days_left = str(valid_days) if status != "revoked" else "Revoked"

        # Truncate public key for display
        truncated_key = public_key[60] + "..." if len(public_key) > 60 else public_key

        # Update entries
        for entry, value in [
            (self.public_key_entry, truncated_key),
            (self.created_entry, created),
            (self.expires_entry, expires),
            (self.status_entry, status),
            (self.valid_days_entry, valid_days_left)
        ]:
            entry.config(state="normal")
            entry.delete(0, tk.END)
            entry.insert(0, value)
            entry.config(state="readonly")

    def create_new_keys(self):
        """Call DashboardWindow's create_new_keys with callback to refresh keys."""
        self.dashboard_window.create_new_keys(callback=self.load_keys)

    def extend_keys(self):
        """Call DashboardWindow's extend_keys with callback to refresh keys."""
        self.dashboard_window.extend_keys(callback=self.load_keys)

    def close_window(self):
        """Cancel scheduled updates and close the window."""
        if hasattr(self, 'update_job'):
            self.root.after_cancel(self.update_job)  # Stop periodic updates
        self.root.destroy()