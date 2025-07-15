import tkinter as tk
from tkinter import messagebox
from modules.auth import validate_passphrase, derive_key
from modules.recovery import recovery_passphrase
from modules.logger import log_action
from pathlib import Path
import json
import base64

class RecoveryWindow:
    def __init__(self, root, main_window):
        self.root = root  # Toplevel window
        self.main_window = main_window  # MainWindow instance
        self.root.title("Khôi phục tài khoản")
        self.root.transient(main_window.root)  # Use main_window.root for transient
        self.root.grab_set()

        # Minimum window size
        self.min_width = 400
        self.min_height = 500

        # Add padding
        self.root.configure(padx=20, pady=20, bg="#F5F7FA")
        style = tk.ttk.Style()
        style.theme_use("clam")
        style.configure("TButton",
                        background="#1976D2",
                        foreground="white",
                        font=("Segoe UI", 12, "bold"),
                        borderwidth=0,
                        focusthickness=3,
                        focuscolor="#2196F3",
                        padding=10)
        style.map("TButton",
                  background=[('active', '#2196F3'), ('pressed', '#1565C0')])
        style.configure("TLabel",
                        background="#F5F7FA",
                        foreground="#222",
                        font=("Segoe UI", 13, "bold"))
        style.configure("Error.TLabel",
                        foreground="#E53935",
                        font=("Segoe UI", 12, "bold"))
        style.configure("TEntry",
                        font=("Segoe UI", 12),
                        padding=8)

        main_frame = tk.Frame(self.root, bg="#FFFFFF", bd=0, highlightthickness=0)
        main_frame.pack(padx=20, pady=20, fill="both", expand=True)
        main_frame.configure(bg="#FFFFFF")
        main_frame.pack_propagate(True)

        title_label = tk.ttk.Label(main_frame, text="KHÔI PHỤC TÀI KHOẢN", style="TLabel")
        title_label.pack(pady=(10, 20))

        tk.ttk.Label(main_frame, text="Email:", style="TLabel").pack(anchor="w", pady=(6,2))
        self.email_entry = tk.ttk.Entry(main_frame, font=("Segoe UI", 12))
        self.email_entry.pack(fill="x", pady=(0,6))

        tk.ttk.Label(main_frame, text="Mã phục hồi:", style="TLabel").pack(anchor="w", pady=(6,2))
        self.recovery_code_entry = tk.ttk.Entry(main_frame, show="*", font=("Segoe UI", 12))
        self.recovery_code_entry.pack(fill="x", pady=(0,6))

        tk.ttk.Label(main_frame, text="Passphrase mới:", style="TLabel").pack(anchor="w", pady=(6,2))
        self.passphrase_entry = tk.ttk.Entry(main_frame, show="*", font=("Segoe UI", 12))
        self.passphrase_entry.pack(fill="x", pady=(0,6))

        self.error_label = tk.ttk.Label(main_frame, text="", style="Error.TLabel")
        self.error_label.pack(anchor="w", pady=(0,6))

        button_frame = tk.Frame(main_frame, bg="#FFFFFF")
        button_frame.pack(pady=(0,6))
        self.submit_btn = tk.ttk.Button(button_frame, text="Đặt lại", command=self.submit, style="TButton")
        self.submit_btn.pack(side=tk.LEFT, padx=8)
        self.cancel_btn = tk.ttk.Button(button_frame, text="Hủy", command=self.cancel, style="TButton")
        self.cancel_btn.pack(side=tk.LEFT, padx=8)

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
                log_action(email, "Khôi phục tài khoản", "Failed: Email không tồn tại")
                return

            recovery_code_hash = base64.b64decode(user["recovery_code_hash"])
            recovery_salt = base64.b64decode(user["recovery_code_salt"])
            input_hash = derive_key(recovery_code, recovery_salt)
            if recovery_code_hash != input_hash:
                self.error_label.config(text="Recovery code không hợp lệ")
                log_action(email, "Khôi phục tài khoản", "failed: Mã phục hồi không hợp lệ")
                return

            success, message = recovery_passphrase(email, recovery_code, new_passphrase)
            if success:
                messagebox.showinfo("Thành công", message)
                self.main_window.enable_buttons()  # Re-enable main window buttons
                self.root.destroy()
            else:
                self.error_label.config(text=message)
                # Optionally re-enable buttons here if you want to allow retry after failure
                self.main_window.enable_buttons()
        except Exception as e:
            log_action(email, "Khôi phục tài khoản", f"Failed: {str(e)}")
            self.error_label.config(text=f"Lỗi: {str(e)}")
            # Optionally re-enable buttons here if you want to allow retry after exception
            self.main_window.enable_buttons()