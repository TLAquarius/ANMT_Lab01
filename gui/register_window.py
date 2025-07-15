import tkinter as tk
from tkinter import messagebox, ttk
import re
from datetime import datetime
from modules.auth import sign_up

class SignupWindow:
    def __init__(self, root, main_window):
        self.root = root  # Toplevel window
        self.main_window = main_window  # MainWindow instance
        self.root.title("Đăng ký")
        self.root.transient(main_window.root)
        self.root.grab_set()

        # Minimum window size
        self.min_width = 400
        self.min_height = 650

        self.root.configure(bg="#F5F7FA")
        style = ttk.Style()
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

        title_label = ttk.Label(main_frame, text="ĐĂNG KÝ TÀI KHOẢN", style="TLabel")
        title_label.pack(pady=(10, 20))

        self.email_entry = ttk.Entry(main_frame, font=("Segoe UI", 12))
        ttk.Label(main_frame, text="Email:", style="TLabel").pack(anchor="w", pady=(0, 2))
        self.email_entry.pack(fill="x", pady=(0, 2))
        self.email_error = ttk.Label(main_frame, text="", style="Error.TLabel")
        self.email_error.pack(anchor="w", pady=(0, 2))

        self.name_entry = ttk.Entry(main_frame, font=("Segoe UI", 12))
        ttk.Label(main_frame, text="Họ tên:", style="TLabel").pack(anchor="w", pady=(4, 2))
        self.name_entry.pack(fill="x", pady=(0, 2))

        self.dob_entry = ttk.Entry(main_frame, font=("Segoe UI", 12))
        ttk.Label(main_frame, text="Ngày sinh (DD/MM/YYYY):", style="TLabel").pack(anchor="w", pady=(4, 2))
        self.dob_entry.pack(fill="x", pady=(0, 2))
        self.dob_error = ttk.Label(main_frame, text="", style="Error.TLabel")
        self.dob_error.pack(anchor="w", pady=(0, 2))

        self.phone_entry = ttk.Entry(main_frame, font=("Segoe UI", 12))
        ttk.Label(main_frame, text="Điện thoại:", style="TLabel").pack(anchor="w", pady=(4, 2))
        self.phone_entry.pack(fill="x", pady=(0, 2))
        self.phone_error = ttk.Label(main_frame, text="", style="Error.TLabel")
        self.phone_error.pack(anchor="w", pady=(0, 2))

        self.address_entry = ttk.Entry(main_frame, font=("Segoe UI", 12))
        ttk.Label(main_frame, text="Địa chỉ:", style="TLabel").pack(anchor="w", pady=(4, 2))
        self.address_entry.pack(fill="x", pady=(0, 2))

        self.passphrase_entry = ttk.Entry(main_frame, show="*", font=("Segoe UI", 12))
        ttk.Label(main_frame, text="Passphrase:", style="TLabel").pack(anchor="w", pady=(4, 2))
        self.passphrase_entry.pack(fill="x", pady=(0, 2))
        self.passphrase_error = ttk.Label(main_frame, text="", style="Error.TLabel")
        self.passphrase_error.pack(anchor="w", pady=(0, 2))

        self.confirm_passphrase_entry = ttk.Entry(main_frame, show="*", font=("Segoe UI", 12))
        ttk.Label(main_frame, text="Xác nhận Passphrase:", style="TLabel").pack(anchor="w", pady=(4, 2))
        self.confirm_passphrase_entry.pack(fill="x", pady=(0, 2))
        self.confirm_passphrase_error = ttk.Label(main_frame, text="", style="Error.TLabel")
        self.confirm_passphrase_error.pack(anchor="w", pady=(0, 2))

        self.show_passphrase_var = tk.BooleanVar()
        ttk.Checkbutton(
            main_frame,
            text="Hiện Passphrases",
            variable=self.show_passphrase_var,
            command=self.toggle_passphrase,
            style="TCheckbutton"
        ).pack(pady=4, anchor="w")
        style.configure("TCheckbutton", font=("Segoe UI", 13))

        button_frame = tk.Frame(main_frame, bg="#FFFFFF")
        button_frame.pack(pady=8)
        self.submit_btn = ttk.Button(button_frame, text="Đăng ký", command=self.submit, style="TButton")
        self.submit_btn.pack(side=tk.LEFT, padx=6)
        self.back_btn = ttk.Button(button_frame, text="Quay lại", command=self.go_back, style="TButton")
        self.back_btn.pack(side=tk.LEFT, padx=6)

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

    def toggle_passphrase(self):
        """Toggle the visibility of both passphrase entry boxes."""
        if self.show_passphrase_var.get():
            self.passphrase_entry.config(show="")
            self.confirm_passphrase_entry.config(show="")
        else:
            self.passphrase_entry.config(show="*")
            self.confirm_passphrase_entry.config(show="*")

    def validate_email(self, email):
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))

    def validate_dob(self, dob):
        try:
            datetime.strptime(dob, '%d/%m/%Y')
            if datetime.strptime(dob, '%d/%m/%Y') > datetime.now():
                return False
            return True
        except ValueError:
            return False

    def validate_phone(self, phone):
        pattern = r'^\+?\d+([-.\s]?\d+)*$'
        return bool(re.match(pattern, phone))

    def show_copyable_info(self, title, message, recovery_code):
        window = tk.Toplevel()
        window.title(title)
        window.resizable(False, False)
        window.grab_set()  # Modal

        ttk.Label(window, text=message).pack(padx=10, pady=(10, 0))

        entry = tk.Entry(window, width=40)
        entry.insert(0, recovery_code)
        entry.configure(state='readonly')  # Allow copy but not edit
        entry.pack(padx=10, pady=5)
        entry.focus()
        entry.selection_range(0, tk.END)  # Auto-select

        ttk.Button(window, text="OK", command=window.destroy).pack(pady=(0, 10))

        # Optional: Center window
        window.update_idletasks()
        w, h = window.winfo_width(), window.winfo_height()
        x = (window.winfo_screenwidth() // 2) - (w // 2)
        y = (window.winfo_screenheight() // 2) - (h // 2)
        window.geometry(f'{w}x{h}+{x}+{y}')

    def submit(self):
        email = self.email_entry.get()
        full_name = self.name_entry.get()
        dob = self.dob_entry.get()
        phone = self.phone_entry.get()
        address = self.address_entry.get()
        passphrase = self.passphrase_entry.get()
        confirm_passphrase = self.confirm_passphrase_entry.get()

        self.email_error.config(text="")
        self.dob_error.config(text="")
        self.phone_error.config(text="")
        self.passphrase_error.config(text="")
        self.confirm_passphrase_error.config(text="")

        # Check if all fields are filled
        if not all([email, full_name, dob, phone, address, passphrase, confirm_passphrase]):
            messagebox.showerror("Lỗi", "Vui lòng điền đầy đủ thông tin")
            return

        # Validate email
        if not self.validate_email(email):
            self.email_error.config(text="Format email không hợp lệ")
            return

        # Validate date of birth
        if not self.validate_dob(dob):
            self.dob_error.config(text="Ngày sinh không hợp lệ (định dạng: DD/MM/YYYY)")
            return

        if not self.validate_phone(phone):
            self.phone_error.config(text="Số điện thoại không hợp lệ")
            return

        # Validate passphrase match
        if passphrase != confirm_passphrase:
            self.confirm_passphrase_error.config(text="Mật khẩu không khớp")
            return

        success, message, recovery_code = sign_up(email, full_name, dob, phone, address, passphrase)
        if success:
            self.show_copyable_info("Success", f"{message}\nMã khôi phục (Vui lòng ghi nhớ mã này): ",recovery_code)
            self.go_back()
        else:
            messagebox.showerror("Error", message)

    def go_back(self):
        """Close the signup window and re-enable main window buttons."""
        self.main_window.enable_buttons()
        self.root.destroy()