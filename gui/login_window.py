import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
from modules.auth import verify_login
from modules.mfa import generate_otp, generate_totp_qr, verify_totp
from modules.logger import log_action
from datetime import datetime
from zoneinfo import ZoneInfo
from gui.dashboard_window import DashboardWindow

class LoginWindow:
    def __init__(self, root, main_window):
        self.root = root
        self.main_window = main_window
        self.root.title("Đăng nhập")
        self.root.transient(main_window.root)
        self.root.grab_set()

        # Minimum window size
        self.min_width = 400
        self.min_height = 540

        self.root.configure(bg="#F5F7FA")
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

        main_frame = tk.Frame(root, bg="#FFFFFF", bd=0, highlightthickness=0)
        main_frame.pack(padx=20, pady=20, fill="both", expand=True)
        main_frame.configure(bg="#FFFFFF")
        main_frame.pack_propagate(True)

        title_label = tk.ttk.Label(main_frame, text="ĐĂNG NHẬP", style="TLabel")
        title_label.pack(pady=(10, 20))

        email_label = tk.ttk.Label(main_frame, text="Email:", style="TLabel")
        email_label.pack(anchor="w", pady=(0, 5))
        self.email_entry = tk.ttk.Entry(main_frame, font=("Segoe UI", 12))
        self.email_entry.pack(fill="x", pady=(0, 10))

        pass_label = tk.ttk.Label(main_frame, text="Passphrase:", style="TLabel")
        pass_label.pack(anchor="w", pady=(0, 5))
        self.passphrase_entry = tk.ttk.Entry(main_frame, show="*", font=("Segoe UI", 12))
        self.passphrase_entry.pack(fill="x", pady=(0, 10))

        button_frame = tk.Frame(main_frame, bg="#FFFFFF")
        button_frame.pack(pady=4)
        self.login_btn = tk.ttk.Button(button_frame, text="Đăng nhập", command=self.submit_login, style="TButton")
        self.login_btn.pack(side=tk.LEFT, padx=8)
        self.back_btn = tk.ttk.Button(button_frame, text="Quay lại", command=self.go_back, style="TButton")
        self.back_btn.pack(side=tk.LEFT, padx=8)

        self.lockout_label = tk.ttk.Label(main_frame, text="", style="Error.TLabel")
        self.lockout_label.pack(pady=3)

        # MFA frame (hidden initially)
        self.mfa_frame = tk.Frame(main_frame, bg="#FFFFFF")
        tk.ttk.Label(self.mfa_frame, text="Chọn phương thức MFA", style="TLabel").pack(pady=0)
        self.mfa_method = tk.StringVar(value="otp")
        tk.ttk.Radiobutton(self.mfa_frame, text="OTP (Email) (mô phỏng bằng in code trong terminal)", variable=self.mfa_method, value="otp", style="TRadiobutton").pack(anchor="w")
        tk.ttk.Radiobutton(self.mfa_frame, text="TOTP (QR Code)", variable=self.mfa_method, value="totp", style="TRadiobutton").pack(anchor="w")
        tk.ttk.Button(self.mfa_frame, text="Tạo mã MFA", command=self.generate_mfa, style="TButton").pack(pady=6)

        self.code_label = tk.ttk.Label(self.mfa_frame, text="Nhập mã 6 số", style="TLabel")
        self.code_entry = tk.ttk.Entry(self.mfa_frame, font=("Segoe UI", 12))
        self.confirm_btn = tk.ttk.Button(self.mfa_frame, text="Xác nhận", command=self.verify_mfa, style="TButton")
        self.back_mfa_btn = tk.ttk.Button(self.mfa_frame, text="Quay lại", command=self.go_back, style="TButton")

        self.qr_label = tk.Label(self.mfa_frame, bg="#FFFFFF")

        self.user = None
        self.otp_data = None

        # Adjust window size
        self.adjust_window_size()

    def adjust_window_size(self):
        """Adjust window size to fit all elements with minimum size constraints."""
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

    def submit_login(self):
        email = self.email_entry.get()
        passphrase = self.passphrase_entry.get()

        if not email or not passphrase:
            messagebox.showerror("Lỗi", "Email và passphrase không được để trống")
            return

        success, user, message = verify_login(email, passphrase)
        self.lockout_label.config(text=message if "locked" in message.lower() else "")
        if success:
            self.user = user
            self.email_entry.config(state="disabled")
            self.passphrase_entry.config(state="disabled")
            self.lockout_label.config(text="")
            self.mfa_frame.pack(pady=10)
        else:
            messagebox.showerror("Lỗi", message)

    def generate_mfa(self):
        if self.mfa_method.get() == "otp":
            self.qr_label.pack_forget()
            otp, created, expires = generate_otp()
            self.otp_data = {"code": otp, "created": created, "expires": expires}
            print(f"OTP sent to {self.user['email']}: {otp} (expires at {expires})")
            log_action(self.user['email'], "Tạo mã OTP (email)", f"Success: OTP {otp}, hạn sử dụng {expires}")
            self.code_label.pack()
            self.code_entry.pack()
            self.confirm_btn.pack(pady=6)
            self.back_mfa_btn.pack(pady=6)
        else:
            self.qr_label.pack_forget()
            img = generate_totp_qr(self.user["email"], self.user["totp_secret"])
            img = img.resize((150, 150), Image.Resampling.LANCZOS)
            self.qr_image = ImageTk.PhotoImage(img)
            self.qr_label.config(image=self.qr_image)
            self.qr_label.pack()
            self.code_label.pack()
            self.code_entry.pack()
            self.confirm_btn.pack(pady=6)
            self.back_mfa_btn.pack(pady=6)
            log_action(self.user['email'], "Tạo mã QR cho TOTP", f"Success")
        self.adjust_window_size()

    def verify_mfa(self):
        code = self.code_entry.get()
        if not code:
            messagebox.showerror("Lỗi", "Phải nhập mã MFA")
            return

        if self.mfa_method.get() == "otp":
            if code == self.otp_data["code"]:
                expires = datetime.fromisoformat(self.otp_data["expires"])
                now = datetime.now(ZoneInfo("Asia/Ho_Chi_Minh"))
                if now <= expires:
                    log_action(self.user['email'], "Xác minh OTP", "Success")
                    self.open_dashboard()
                else:
                    messagebox.showerror("Lỗi", "OTP hết hạn")
                    log_action(self.user['email'], "Xác minh OTP", "Failed: OTP hết hạn")
            else:
                messagebox.showerror("Lỗi", "OTP không hợp lệ")
                log_action(self.user['email'], "Xác minh OTP", "Failed: OTP không hợp lệ")
        else:
            if verify_totp(self.user["totp_secret"], code):
                log_action(self.user['email'], "Xác minh TOTP", "Success")
                self.open_dashboard()
            else:
                messagebox.showerror("Lỗi", "TOTP không hợp lệ")
                log_action(self.user['email'], "Xác minh TOTP", "Failed: TOTP không hợp lệ")

    def open_dashboard(self):
        """Open the dashboard window and close the login window."""
        self.main_window.enable_buttons()
        dashboard_window = tk.Toplevel(self.main_window.root)
        DashboardWindow(dashboard_window, self.main_window, self.user['email'])
        self.root.destroy()

    def go_back(self):
        """Close the login window and re-enable main window buttons."""
        self.main_window.enable_buttons()
        self.root.destroy()