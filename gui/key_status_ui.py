import tkinter as tk
from tkinter import ttk
from datetime import datetime
import json
from pathlib import Path
from zoneinfo import ZoneInfo
from modules.rsa_keys import update_public_key_store

class KeyStorageWindow:
    def __init__(self, root, dashboard_window, email):
        self.root = root
        self.dashboard_window = dashboard_window
        self.email = email
        self.safe_email = email.replace("@", "_at_").replace(".", "_dot_")
        self.root.title("Key Storage")
        self.root.transient(dashboard_window.root)
        self.root.grab_set()

        # Minimum window size
        self.min_width = 600
        self.min_height = 400

        # Add padding
        self.root.configure(padx=20, pady=20)

        # Create Treeview for key display
        columns = ("Public Key", "Created", "Expires", "Status", "Valid Days Left")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings")
        self.tree.heading("Public Key", text="Public Key (Truncated)")
        self.tree.heading("Created", text="Created")
        self.tree.heading("Expires", text="Expires")
        self.tree.heading("Status", text="Status")
        self.tree.heading("Valid Days Left", text="Valid Days Left")
        self.tree.column("Public Key", width=150)
        self.tree.column("Created", width=100)
        self.tree.column("Expires", width=100)
        self.tree.column("Status", width=100)
        self.tree.column("Valid Days Left", width=100)
        self.tree.pack(fill="both", expand=True, pady=10)

        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=scrollbar.set)

        # Load and display keys
        self.load_keys()

        # Close button
        tk.Button(self.root, text="Close", command=self.root.destroy).pack(pady=10)

        # Adjust window size
        self.adjust_window_size()

    def adjust_window_size(self):
        """Adjust window size to fit all elements with minimum size constraints."""
        self.root.update_idletasks()
        req_width = max(self.tree.winfo_reqwidth() + 60, self.min_width)
        req_height = max(self.tree.winfo_reqheight() + 100, self.min_height)
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - req_width) // 2
        y = (screen_height - req_height) // 2
        self.root.geometry(f"{req_width}x{req_height}+{x}+{y}")
        self.root.minsize(self.min_width, self.min_height)

    def load_keys(self):
        """Load current and archived keys and display in the Treeview."""
        current_key_path = Path(f"./data/{self.safe_email}/rsa_keypair.json")
        archived_keys_path = Path(f"./data/{self.safe_email}/archived_keys.json")
        now = datetime.now(ZoneInfo("Asia/Ho_Chi_Minh"))
        update_public_key_store(self.email)
        # Load current key
        try:
            with open(current_key_path, "r") as f:
                key_data = json.load(f)
                self.add_key_to_tree(key_data, now)
        except (FileNotFoundError, json.JSONDecodeError):
            pass

        # Load archived keys
        try:
            with open(archived_keys_path, "r") as f:
                archived_keys = json.load(f)
                for key_data in archived_keys:
                    self.add_key_to_tree(key_data, now)
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    def add_key_to_tree(self, key_data, now):
        """Add a key to the Treeview with calculated valid days left."""
        public_key = key_data["public_key"]
        created = datetime.fromisoformat(key_data["created"]).strftime("%Y-%m-%d %H:%M:%S")
        expires = datetime.fromisoformat(key_data["expires"]).strftime("%Y-%m-%d %H:%M:%S")
        status = key_data["status"]

        # Calculate valid days left
        expires_dt = datetime.fromisoformat(key_data["expires"])
        valid_days = (expires_dt - now).days
        if status != "revoked":
            valid_days_left = str(valid_days)
        else:
            valid_days_left = "Revoked"
        # Truncate public key for display
        truncated_key = public_key

        self.tree.insert("", "end", values=(truncated_key, created, expires, status, valid_days_left))