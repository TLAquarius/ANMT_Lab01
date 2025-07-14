import tkinter as tk
from tkinter import messagebox
from modules.auth import reset_passphrase, validate_passphrase, derive_key
from modules.rsa_keys import generate_rsa_keypair, update_public_key_store
from modules.logger import log_action
from pathlib import Path
import json
import base64

class RecoveryWindow:
    def __init__(self, root, main_window):
        self.root = root  # Toplevel window
        self.main_window = main_window  # MainWindow instance
        self.root.title("Reset Passphrase")
        self.root.transient(main_window.root)  # Use main_window.root for transient
        self.root.grab_set()

        # Minimum window size
        self.min_width = 400
        self.min_height = 500

        # Add padding
        self.root.configure(padx=20, pady=20)

        # Labels and entries
        tk.Label(root, text="Email").pack(pady=5)
        self.email_entry = tk.Entry(root)
        self.email_entry.pack(pady=5)

        tk.Label(root, text="Recovery code").pack(pady=5)
        self.recovery_code_entry = tk.Entry(root, show="*")
        self.recovery_code_entry.pack(pady=5)

        tk.Label(root, text="Passphrase mới").pack(pady=5)
        self.passphrase_entry = tk.Entry(root, show="*")
        self.passphrase_entry.pack(pady=5)

        self.error_label = tk.Label(root, text="", fg="red")
        self.error_label.pack(pady=5)

        button_frame = tk.Frame(root)
        button_frame.pack(pady=20)
        tk.Button(button_frame, text="Đặt lại", command=self.submit).pack(side=tk.LEFT, padx=10)
        tk.Button(button_frame, text="Hủy", command=self.cancel).pack(side=tk.LEFT, padx=10)

        self.adjust_window_size()

    def adjust_window_size(self):
        self.root.update_idletasks()
        req_width = self.root.winfo_reqwidth() + 40
        req_height = self.root.winfo_reqheight() + 40
        final_width = max(req_width, self.min_width)
        final_height = max(req_height, self.min_height)
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - final_width) // 2
        y = (screen_height - final_height) // 2
        self.root.geometry(f"{final_width}x{final_height}+{x}+{y}")
        self.root.minsize(self.min_width, self.min_height)

    def cancel(self):
        """Handle cancellation by re-enabling main window buttons and closing the window."""
        self.main_window.enable_buttons()
        self.root.destroy()

    def submit(self):
        email = self.email_entry.get().strip()
        recovery_code = self.recovery_code_entry.get().strip()
        new_passphrase = self.passphrase_entry.get().strip()

        if not all([email, recovery_code, new_passphrase]):
            self.error_label.config(text="Vui lòng điền đầy đủ thông tin")
            return

        if len(recovery_code) != 16:
            self.error_label.config(text="Recovery code phải dài 16 ký tự")
            return

        # Validate new passphrase
        valid, error = validate_passphrase(new_passphrase)
        if not valid:
            self.error_label.config(text=error)
            return

        try:
            with open(Path("./data/users.json"), "r") as f:
                users = json.load(f)
            user = next((u for u in users if u["email"] == email), None)
            if not user:
                self.error_label.config(text="Email không tồn tại")
                log_action(email, "reset_passphrase", "failed: Email not found")
                return

            recovery_code_hash = base64.b64decode(user["recovery_code_hash"])
            recovery_salt = base64.b64decode(user["recovery_code_salt"])
            input_hash = derive_key(recovery_code, recovery_salt)
            if recovery_code_hash != input_hash:
                self.error_label.config(text="Recovery code không hợp lệ")
                log_action(email, "reset_passphrase", "failed: Invalid recovery code")
                return

            success, message = reset_passphrase(email, recovery_code, new_passphrase)
            if success:
                messagebox.showinfo("Thành công", message)
                self.main_window.enable_buttons()  # Re-enable main window buttons
                self.root.destroy()
            else:
                self.error_label.config(text=message)
                # Optionally re-enable buttons here if you want to allow retry after failure
                self.main_window.enable_buttons()
        except Exception as e:
            log_action(email, "reset_passphrase", f"failed: {str(e)}")
            self.error_label.config(text=f"Lỗi: {str(e)}")
            # Optionally re-enable buttons here if you want to allow retry after exception
            self.main_window.enable_buttons()