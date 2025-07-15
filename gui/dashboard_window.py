import tkinter as tk
from tkinter import messagebox, ttk, filedialog
from datetime import datetime
import re, base64
import json
from pathlib import Path
from zoneinfo import ZoneInfo
from PIL import Image, ImageTk
from modules.recovery import change_passphrase
from modules.rsa_keys import generate_rsa_keypair, update_public_key_store, derive_key
from modules.qr_utils import generate_qr_for_public_key, read_qr
from modules.logger import log_action
from modules.pubkey_search import search_public_key
from modules.file_crypto import encrypt_file_with_metadata, decrypt_file
from modules.file_sign import sign_file, verify_signature
from modules.auth import verify_passphrase, validate_passphrase
from gui.key_status_ui import KeyStorageWindow
from modules.admin import is_admin
from gui.admin_panel import AdminWindow

class DashboardWindow:
    def __init__(self, root, main_window, email):
        self.root = root
        self.main_window = main_window
        self.email = email
        self.root.title(f"Người dùng - {email}")
        self.root.transient(main_window.root)
        self.root.grab_set()

        self.min_width = 400
        self.min_height = 800


        # Modern style setup
        self.root.configure(bg="#f6faff", padx=20, pady=20)
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("TButton", font=("Segoe UI", 11, "bold"), foreground="#fff", background="#1976d2", borderwidth=0, padding=8)
        self.style.map("TButton",
            background=[("active", "#1565c0"), ("!active", "#1976d2")],
            foreground=[("active", "#fff")]
        )
        self.style.configure("TLabel", font=("Segoe UI", 11), background="#f6faff", foreground="#222")
        self.style.configure("Error.TLabel", font=("Segoe UI", 10, "italic"), foreground="#d32f2f", background="#f6faff")
        self.style.configure("TEntry", font=("Segoe UI", 11), padding=6)
        self.style.configure("TFrame", background="#f6faff")
        self.style.configure("TRadiobutton", font=("Segoe UI", 11), background="#f6faff", foreground="#1976d2")
        self.style.map("TRadiobutton", background=[("active", "#e3f2fd")])

        # Load user data from users.json
        self.user = self.load_user_data()
        if not self.user:
            temp_error = "Không tìm thấy dữ liệu người dùng này"
            log_action(self.email, "Load dữ liệu người dùng", f"failed: {temp_error}")
            messagebox.showerror("Lỗi", f"{temp_error}")
            self.logout()
            return


        # Info frame
        info_frame = ttk.Frame(root, style="TFrame")
        info_frame.pack(fill="x", pady=(0, 10))
        ttk.Label(info_frame, text=f"Họ tên: {self.user['full_name']}", anchor="w", style="TLabel").pack(fill="x", pady=2)
        ttk.Label(info_frame, text=f"Email: {self.user['email']}", anchor="w", style="TLabel").pack(fill="x", pady=2)
        ttk.Label(info_frame, text=f"Điện thoại: {self.user['phone']}", anchor="w", style="TLabel").pack(fill="x", pady=2)
        ttk.Label(info_frame, text=f"Ngày sinh: {self.user['dob']}", anchor="w", style="TLabel").pack(fill="x", pady=2)
        ttk.Label(info_frame, text=f"Địa chỉ: {self.user['address']}", anchor="w", style="TLabel").pack(fill="x", pady=2)

        sep = ttk.Separator(root, orient="horizontal")
        sep.pack(fill="x", pady=10)

        # Button frame
        btn_frame = ttk.Frame(root, style="TFrame")
        btn_frame.pack(fill="x", pady=0)
        btn_pad = {"padx": 0, "pady": 6, "fill": "x"}

        if is_admin(self.email):
            ttk.Button(btn_frame, text="Màn Hình Quản Trị", command=self.open_admin, style="TButton").pack(**btn_pad)
        ttk.Button(btn_frame, text="Cập nhật thông tin", command=self.open_update_info, style="TButton").pack(**btn_pad)
        ttk.Button(btn_frame, text="Đổi passphrase", command=self.open_change_passphrase, style="TButton").pack(**btn_pad)
        ttk.Button(btn_frame, text="Quản lý key", command=self.view_keys, style="TButton").pack(**btn_pad)
        ttk.Button(btn_frame, text="Tạo mã QR public key", command=self.generate_qr_code, style="TButton").pack(**btn_pad)
        ttk.Button(btn_frame, text="Đọc mã QR public key và lưu", command=self.read_qr_code, style="TButton").pack(**btn_pad)
        ttk.Button(btn_frame, text="Tìm public key", command=self.search_public_key_ui, style="TButton").pack(**btn_pad)
        ttk.Button(btn_frame, text="Mã hóa File", command=self.encrypt_file, style="TButton").pack(**btn_pad)
        ttk.Button(btn_frame, text="Giải mã File", command=self.decrypt_file, style="TButton").pack(**btn_pad)
        ttk.Button(btn_frame, text="Ký số File", command=self.sign_file, style="TButton").pack(**btn_pad)
        ttk.Button(btn_frame, text="Xác minh chữ ký", command=self.verify_signature, style="TButton").pack(**btn_pad)
        ttk.Button(btn_frame, text="Đăng xuất", command=self.logout, style="TButton").pack(**btn_pad)

        self.adjust_window_size()
        self.root.update()

    def load_user_data(self):
        """Load user data from users.json based on email."""
        try:
            with open(Path("./data/users.json"), "r") as f:
                users = json.load(f)
            return next((user for user in users if user["email"] == self.email), None)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            log_action(self.email, "Load dữ liệu người dùng", f"Failed: không tìm thấy file users.json")
            return None

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

    def open_admin(self):
        """Open the admin window."""
        admin_window = tk.Toplevel(self.main_window.root)
        admin_window.transient(self.root)
        admin_window.grab_set()
        AdminWindow(admin_window, self.main_window, self.email)
        log_action(self.email, "Mở cửa sổ admin", "Success")

    def open_update_info(self):

        update_window = tk.Toplevel(self.root)
        update_window.title("Cập nhật thông tin người dùng")
        update_window.transient(self.root)
        update_window.grab_set()
        update_window.configure(bg="#f6faff", padx=30, pady=30)

        def style_label(widget):
            widget.configure(bg="#f6faff", fg="#1976d2", font=("Segoe UI", 12, "bold"))
        def style_entry(widget):
            widget.configure(bg="#fff", fg="#222", font=("Segoe UI", 12), relief="groove", bd=2, highlightbackground="#1976d2", highlightcolor="#1976d2", highlightthickness=1, insertbackground="#1976d2")
        def style_error(widget):
            widget.configure(bg="#f6faff", fg="#d32f2f", font=("Segoe UI", 10, "italic"))

        form_frame = tk.Frame(update_window, bg="#f6faff")
        form_frame.pack(fill="both", expand=True)

        name_label = tk.Label(form_frame, text="Họ tên")
        style_label(name_label)
        name_label.pack(pady=(0,5), anchor="w")
        name_entry = tk.Entry(form_frame)
        style_entry(name_entry)
        name_entry.insert(0, self.user['full_name'])
        name_entry.pack(pady=5, fill="x")

        dob_label = tk.Label(form_frame, text="Ngày sinh (DD/MM/YYYY)")
        style_label(dob_label)
        dob_label.pack(pady=(10,5), anchor="w")
        dob_entry = tk.Entry(form_frame)
        style_entry(dob_entry)
        dob_entry.insert(0, self.user['dob'])
        dob_entry.pack(pady=5, fill="x")
        dob_error = tk.Label(form_frame, text="")
        style_error(dob_error)
        dob_error.pack(anchor="w")

        phone_label = tk.Label(form_frame, text="Điện thoại")
        style_label(phone_label)
        phone_label.pack(pady=(10,5), anchor="w")
        phone_entry = tk.Entry(form_frame)
        style_entry(phone_entry)
        phone_entry.insert(0, self.user['phone'])
        phone_entry.pack(pady=5, fill="x")
        phone_error = tk.Label(form_frame, text="")
        style_error(phone_error)
        phone_error.pack(anchor="w")

        address_label = tk.Label(form_frame, text="Địa chỉ")
        style_label(address_label)
        address_label.pack(pady=(10,5), anchor="w")
        address_entry = tk.Entry(form_frame)
        style_entry(address_entry)
        address_entry.insert(0, self.user['address'])
        address_entry.pack(pady=5, fill="x")

        def save_changes():
            new_name = name_entry.get()
            new_dob = dob_entry.get()
            new_phone = phone_entry.get()
            new_address = address_entry.get()

            dob_error.config(text="")
            phone_error.config(text="")

            if not all([new_name, new_dob, new_phone, new_address]):
                messagebox.showerror("Lỗi", "Không được để trống các trường")
                return

            if not self.validate_dob(new_dob):
                dob_error.config(text="Định dạng bị sai (DD/MM/YYYY)")
                return

            if not self.validate_phone(new_phone):
                phone_error.config(text="Định dạng bị sai")
                return

            users_file = Path("./data/users.json")
            try:
                with open(users_file, "r") as f:
                    users = json.load(f)
                for user in users:
                    if user["email"] == self.email:
                        user["full_name"] = new_name
                        user["dob"] = new_dob
                        user["phone"] = new_phone
                        user["address"] = new_address
                        break
                with open(users_file, "w") as f:
                    json.dump(users, f, indent=4)
                self.user.update({
                    "full_name": new_name,
                    "dob": new_dob,
                    "phone": new_phone,
                    "address": new_address
                })
                log_action(self.email, "Cập nhật thông tin tài khoản", "Success")
                messagebox.showinfo("Thành công", "Cập nhật thông tin thành công")
                update_window.destroy()
                self.root.destroy()
                new_dashboard = tk.Toplevel(self.main_window.root)
                DashboardWindow(new_dashboard, self.main_window, self.email)
            except Exception as e:
                log_action(self.email, "Cập nhật thông tin tài khoản", f"Failed: Lỗi quá trình đọc/ghi dữ liệu")
                messagebox.showerror("Lỗi", f"Cập nhật thất bại do lỗi quá trình đọc/ghi dữ liệu")


        button_frame = tk.Frame(update_window, bg="#f6faff")
        button_frame.pack(pady=20)
        def style_button(widget):
            widget.configure(bg="#1976d2", fg="#fff", font=("Segoe UI", 12, "bold"), activebackground="#2196f3", activeforeground="#fff", relief="flat", bd=0, padx=16, pady=8, cursor="hand2")
        save_btn = tk.Button(button_frame, text="Lưu thay đổi", command=save_changes)
        style_button(save_btn)
        save_btn.pack(side=tk.LEFT, padx=10)
        cancel_btn = tk.Button(button_frame, text="Hủy thay đổi", command=update_window.destroy)
        style_button(cancel_btn)
        cancel_btn.pack(side=tk.LEFT, padx=10)

        update_window.update_idletasks()
        req_width = update_window.winfo_reqwidth() + 40
        req_height = update_window.winfo_reqheight() + 40
        x = (update_window.winfo_screenwidth() - req_width) // 2
        y = (update_window.winfo_screenheight() - req_height) // 2
        update_window.geometry(f"{req_width}x{req_height}+{x}+{y}")

    def open_change_passphrase(self):
        """Open a window to change the user's passphrase."""

        change_window = tk.Toplevel(self.root)
        change_window.title("Đổi passphrase")
        change_window.transient(self.root)
        change_window.grab_set()
        change_window.configure(bg="#f6faff", padx=30, pady=30)

        def style_label(widget):
            widget.configure(bg="#f6faff", fg="#1976d2", font=("Segoe UI", 12, "bold"))
        def style_entry(widget):
            widget.configure(bg="#fff", fg="#222", font=("Segoe UI", 12), relief="groove", bd=2, highlightbackground="#1976d2", highlightcolor="#1976d2", highlightthickness=1, insertbackground="#1976d2")
        def style_error(widget):
            widget.configure(bg="#f6faff", fg="#d32f2f", font=("Segoe UI", 10, "italic"))

        pass_label = tk.Label(change_window, text="Passphrase cũ")
        style_label(pass_label)
        pass_label.pack(pady=(0,5), anchor="w")
        old_passphrase_entry = tk.Entry(change_window, show="*")
        style_entry(old_passphrase_entry)
        old_passphrase_entry.pack(pady=5, fill="x")

        new_label = tk.Label(change_window, text="Passphrase mới")
        style_label(new_label)
        new_label.pack(pady=(10,5), anchor="w")
        new_passphrase_entry = tk.Entry(change_window, show="*")
        style_entry(new_passphrase_entry)
        new_passphrase_entry.pack(pady=5, fill="x")

        error_label = tk.Label(change_window, text="")
        style_error(error_label)
        error_label.pack(anchor="w", pady=5)

        def perform_change():
            old_passphrase = old_passphrase_entry.get().strip()
            new_passphrase = new_passphrase_entry.get().strip()

            if not old_passphrase:
                error_label.config(text="Không được để trống passphrase cũ")
                return

            valid, error = validate_passphrase(old_passphrase)
            if not valid:
                error_label.config(text=error)
                return

            success, message = verify_passphrase(self.email, old_passphrase)
            if not success:
                error_label.config(text="Passphrase cũ bị sai")
                log_action(self.email, "Đổi passphrase mới", f"Failed: {message}")
                return

            if not new_passphrase:
                error_label.config(text="Không được để trống passphrase mới")
                return

            valid, error = validate_passphrase(new_passphrase)
            if not valid:
                error_label.config(text=error)
                return

            # Call backend function to change passphrase
            try:
                success, message = change_passphrase(self.email, old_passphrase, new_passphrase)
                if success:
                    messagebox.showinfo("Thành công", message, parent=change_window)
                    change_window.destroy()
                else:
                    error_label.config(text=message)
            except Exception as e:
                error_label.config(text=f"Lỗi: {str(e)}")
                log_action(self.email, "Đổi passphrase mới", f"Failed: {str(e)}")


        button_frame = tk.Frame(change_window, bg="#f6faff")
        button_frame.pack(pady=20)
        def style_button(widget):
            widget.configure(bg="#1976d2", fg="#fff", font=("Segoe UI", 12, "bold"), activebackground="#2196f3", activeforeground="#fff", relief="flat", bd=0, padx=16, pady=8, cursor="hand2")
        change_btn = tk.Button(button_frame, text="Đổi mật khẩu", command=perform_change)
        style_button(change_btn)
        change_btn.pack(side=tk.LEFT, padx=10)
        cancel_btn = tk.Button(button_frame, text="Hủy thay đổi", command=change_window.destroy)
        style_button(cancel_btn)
        cancel_btn.pack(side=tk.LEFT, padx=10)

        change_window.update_idletasks()
        req_width = max(change_window.winfo_reqwidth() + 40, 300)
        req_height = max(change_window.winfo_reqheight() + 40, 200)
        x = (change_window.winfo_screenwidth() - req_width) // 2
        y = (change_window.winfo_screenheight() - req_height) // 2
        change_window.geometry(f"{req_width}x{req_height}+{x}+{y}")

    def create_new_keys(self, callback=None):

        passphrase_window = tk.Toplevel(self.root)
        passphrase_window.title("Tạo cập Key RSA mới")
        passphrase_window.transient(self.root)
        passphrase_window.grab_set()
        passphrase_window.configure(bg="#f6faff", padx=30, pady=30)

        def style_label(widget):
            widget.configure(bg="#f6faff", fg="#1976d2", font=("Segoe UI", 12, "bold"))
        def style_entry(widget):
            widget.configure(bg="#fff", fg="#222", font=("Segoe UI", 12), relief="groove", bd=2, highlightbackground="#1976d2", highlightcolor="#1976d2", highlightthickness=1, insertbackground="#1976d2")
        def style_error(widget):
            widget.configure(bg="#f6faff", fg="#d32f2f", font=("Segoe UI", 10, "italic"))

        pass_label = tk.Label(passphrase_window, text="Nhập passphrase")
        style_label(pass_label)
        pass_label.pack(pady=(0,5), anchor="w")
        passphrase_entry = tk.Entry(passphrase_window, show="*")
        style_entry(passphrase_entry)
        passphrase_entry.pack(pady=5, fill="x")

        recovery_label = tk.Label(passphrase_window, text="Nhập mã khôi phục (không bắt buộc, cần thiết để khôi phục private key)")
        style_label(recovery_label)
        recovery_label.pack(pady=(10,5), anchor="w")
        recovery_entry = tk.Entry(passphrase_window, show="*")
        style_entry(recovery_entry)
        recovery_entry.pack(pady=5, fill="x")

        error_label = tk.Label(passphrase_window, text="")
        style_error(error_label)
        error_label.pack(anchor="w")

        def submit_passphrase():
            passphrase = passphrase_entry.get().strip()
            recovery_code = recovery_entry.get().strip() or None
            if not passphrase:
                error_label.config(text="Passphrase không được để trống")
                return

            valid, error = validate_passphrase(passphrase)
            if not valid:
                error_label.config(text=error)
                return

            success, message = verify_passphrase(self.email, passphrase)
            if not success:
                error_label.config(text="Passphrase bị sai")
                log_action(self.email, "Tạo khóa RSA", f"Failed: Passphrase bị sai")
                return

            if recovery_code:
                try:
                    with open(Path("./data/users.json"), "r") as f:
                        users = json.load(f)
                    user = next((u for u in users if u["email"] == self.email), None)
                    if not user:
                        error_label.config(text="Không tìm thấy người dùng")
                        return
                    recovery_code_hash = base64.b64decode(user["recovery_code_hash"])
                    recovery_salt = base64.b64decode(user["recovery_code_salt"])
                    input_hash = derive_key(recovery_code, recovery_salt)
                    if recovery_code_hash != input_hash:
                        error_label.config(text="Mã phục hồi bị sai")
                        log_action(self.email, "Tạo khóa RSA", "Failed: Mã phục hồi bị sai")
                        return
                except Exception as e:
                    error_label.config(text=f"Lỗi: {str(e)}")
                    log_action(self.email, "Tạo khóa RSA", f"Failed: {str(e)}")
                    return

            try:
                key_data = generate_rsa_keypair(self.email, passphrase, recovery_code, mode="renew")
                update_public_key_store(self.email)
                log_action(self.email, "Tạo khóa RSA", "Success")
                messagebox.showinfo("Success", "New RSA keys created successfully")
                passphrase_window.destroy()
                if callback:
                    callback()
            except Exception as e:
                log_action(self.email, "Tạo khóa RSA", f"Failed: {str(e)}")
                error_label.config(text=f"Lỗi: {str(e)}")


        button_frame = tk.Frame(passphrase_window, bg="#f6faff")
        button_frame.pack(pady=20)
        def style_button(widget):
            widget.configure(bg="#1976d2", fg="#fff", font=("Segoe UI", 12, "bold"), activebackground="#2196f3", activeforeground="#fff", relief="flat", bd=0, padx=16, pady=8, cursor="hand2")
        confirm_btn = tk.Button(button_frame, text="Xác nhận", command=submit_passphrase)
        style_button(confirm_btn)
        confirm_btn.pack(side=tk.LEFT, padx=10)
        cancel_btn = tk.Button(button_frame, text="Hủy", command=passphrase_window.destroy)
        style_button(cancel_btn)
        cancel_btn.pack(side=tk.LEFT, padx=10)

        passphrase_window.update_idletasks()
        req_width = passphrase_window.winfo_reqwidth() + 40
        req_height = passphrase_window.winfo_reqheight() + 40
        x = (passphrase_window.winfo_screenwidth() - req_width) // 2
        y = (passphrase_window.winfo_screenheight() - req_height) // 2
        passphrase_window.geometry(f"{req_width}x{req_height}+{x}+{y}")

    def extend_keys(self, callback=None):

        passphrase_window = tk.Toplevel(self.root)
        passphrase_window.title("Gia hạn khóa")
        passphrase_window.transient(self.root)
        passphrase_window.grab_set()
        passphrase_window.configure(bg="#f6faff", padx=30, pady=30)

        def style_label(widget):
            widget.configure(bg="#f6faff", fg="#1976d2", font=("Segoe UI", 12, "bold"))
        def style_entry(widget):
            widget.configure(bg="#fff", fg="#222", font=("Segoe UI", 12), relief="groove", bd=2, highlightbackground="#1976d2", highlightcolor="#1976d2", highlightthickness=1, insertbackground="#1976d2")
        def style_error(widget):
            widget.configure(bg="#f6faff", fg="#d32f2f", font=("Segoe UI", 10, "italic"))

        pass_label = tk.Label(passphrase_window, text="Nhập passphrase")
        style_label(pass_label)
        pass_label.pack(pady=(0,5), anchor="w")
        passphrase_entry = tk.Entry(passphrase_window, show="*")
        style_entry(passphrase_entry)
        passphrase_entry.pack(pady=5, fill="x")

        recovery_label = tk.Label(passphrase_window, text="Nhập mã khôi phục (không bắt buộc, cần thiết để khôi phục private key)")
        style_label(recovery_label)
        recovery_label.pack(pady=(10,5), anchor="w")
        recovery_entry = tk.Entry(passphrase_window, show="*")
        style_entry(recovery_entry)
        recovery_entry.pack(pady=5, fill="x")

        error_label = tk.Label(passphrase_window, text="")
        style_error(error_label)
        error_label.pack(anchor="w")

        def submit_passphrase():
            passphrase = passphrase_entry.get().strip()
            recovery_code = recovery_entry.get().strip() or None
            if not passphrase:
                error_label.config(text="Passphrase không được để trống")
                return

            valid, error = validate_passphrase(passphrase)
            if not valid:
                error_label.config(text=error)
                return

            success, message = verify_passphrase(self.email, passphrase)
            if not success:
                error_label.config(text="Passphrase bị sai")
                log_action(self.email, "Gia hạn khóa", f"Failed: Passphrase bị sai")
                return

            if recovery_code:
                try:
                    with open(Path("./data/users.json"), "r") as f:
                        users = json.load(f)
                    user = next((u for u in users if u["email"] == self.email), None)
                    if not user:
                        error_label.config(text="Không tìm thấy người dùng")
                        return
                    recovery_code_hash = base64.b64decode(user["recovery_code_hash"])
                    recovery_salt = base64.b64decode(user["recovery_code_salt"])
                    input_hash = derive_key(recovery_code, recovery_salt)
                    if recovery_code_hash != input_hash:
                        error_label.config(text="Mã phục hồi không hợp lệ")
                        log_action(self.email, "Gia hạn khóa", "Failed: Mã phục hồi bị sai")
                        return
                except Exception as e:
                    error_label.config(text=f"Lỗi: {str(e)}")
                    log_action(self.email, "Gia hạn khóa", f"Failed: {str(e)}")
                    return

            try:
                key_data = generate_rsa_keypair(self.email, passphrase, recovery_code, mode="extend")
                update_public_key_store(self.email)
                log_action(self.email, "Gia hạn khóa", "Success")
                messagebox.showinfo("Success", "Gia hạn khóa thành công")
                passphrase_window.destroy()
                if callback:
                    callback()
            except Exception as e:
                log_action(self.email, "Gia hạn khóa", f"Failed: {str(e)}")
                error_label.config(text=f"Lỗi: {str(e)}")


        button_frame = tk.Frame(passphrase_window, bg="#f6faff")
        button_frame.pack(pady=20)
        def style_button(widget):
            widget.configure(bg="#1976d2", fg="#fff", font=("Segoe UI", 12, "bold"), activebackground="#2196f3", activeforeground="#fff", relief="flat", bd=0, padx=16, pady=8, cursor="hand2")
        confirm_btn = tk.Button(button_frame, text="Xác nhận", command=submit_passphrase)
        style_button(confirm_btn)
        confirm_btn.pack(side=tk.LEFT, padx=10)
        cancel_btn = tk.Button(button_frame, text="Hủy", command=passphrase_window.destroy)
        style_button(cancel_btn)
        cancel_btn.pack(side=tk.LEFT, padx=10)

        passphrase_window.update_idletasks()
        req_width = passphrase_window.winfo_reqwidth() + 40
        req_height = passphrase_window.winfo_reqheight() + 40
        x = (passphrase_window.winfo_screenwidth() - req_width) // 2
        y = (passphrase_window.winfo_screenheight() - req_height) // 2
        passphrase_window.geometry(f"{req_width}x{req_height}+{x}+{y}")

    def view_keys(self):
        safe_email = self.email.replace("@", "_at_").replace(".", "_dot_")
        key_window = tk.Toplevel(self.root)
        KeyStorageWindow(key_window, self, safe_email)

    def generate_qr_code(self):
        safe_email = self.email.replace("@", "_at_").replace(".", "_dot_")
        try:
            qr_path, message = generate_qr_for_public_key(self.email, safe_email)
            qr_window = tk.Toplevel(self.root)
            qr_window.title("Tạo QR code cho public key")
            qr_window.transient(self.root)
            qr_window.grab_set()

            img = Image.open(qr_path)
            img = img.resize((200, 200), Image.Resampling.LANCZOS)
            qr_image = ImageTk.PhotoImage(img)
            tk.Label(qr_window, image=qr_image).pack(pady=10)
            tk.Label(qr_window, text=message).pack(pady=5)
            tk.Button(qr_window, text="Đóng", command=qr_window.destroy).pack(pady=10)
            qr_window.qr_image = qr_image

            qr_window.update_idletasks()
            req_width = max(qr_window.winfo_reqwidth() + 40, 300)
            req_height = max(qr_window.winfo_reqheight() + 40, 300)
            x = (qr_window.winfo_screenwidth() - req_width) // 2
            y = (qr_window.winfo_screenheight() - req_height) // 2
            qr_window.geometry(f"{req_width}x{req_height}+{x}+{y}")

        except ValueError as e:
            messagebox.showerror("Lỗi", str(e))
        except Exception as e:
            messagebox.showerror("Lỗi", f"{str(e)}")
            log_action(self.email, "Tạo QR code public key", f"Failed: {str(e)}")

    def read_qr_code(self):
        file_path = filedialog.askopenfilename(filetypes=[("PNG Images", "*.png"), ("All Files", "*.*")])
        if not file_path:
            return

        try:
            qr_data, status_msg = read_qr(self.email, file_path)
            qr_info_window = tk.Toplevel(self.root)
            qr_info_window.title("Đọc QR code")
            qr_info_window.transient(self.root)
            qr_info_window.grab_set()

            tk.Label(qr_info_window, text=f"Email: {qr_data['email']}", anchor="w").pack(fill="x", pady=5)
            tk.Label(qr_info_window, text=f"Tạo lúc: {datetime.fromisoformat(qr_data['created']).strftime('%Y-%m-%d')}", anchor="w").pack(fill="x", pady=5)
            tk.Label(qr_info_window, text=f"Hêt hạn lúc: {datetime.fromisoformat(qr_data['expires']).strftime('%Y-%m-%d')}", anchor="w").pack(fill="x", pady=5)
            tk.Label(qr_info_window, text=f"Public Key: {qr_data['public_key']}", anchor="w").pack(fill="x", pady=5)
            tk.Label(qr_info_window, text=f"Trạng thái: {status_msg}", anchor="w").pack(fill="x", pady=5)
            tk.Button(qr_info_window, text="Đóng", command=qr_info_window.destroy).pack(pady=10)

            qr_info_window.update_idletasks()
            req_width = max(qr_info_window.winfo_reqwidth() + 40, 400)
            req_height = max(qr_info_window.winfo_reqheight() + 40, 300)
            x = (qr_info_window.winfo_screenwidth() - req_width) // 2
            y = (qr_info_window.winfo_screenheight() - req_height) // 2
            qr_info_window.geometry(f"{req_width}x{req_height}+{x}+{y}")

        except ValueError as e:
            messagebox.showerror("Lỗi", str(e))
        except Exception as e:
            messagebox.showerror("Lỗi", f"{str(e)}")

    def search_public_key_ui(self):
        search_window = tk.Toplevel(self.root)
        search_window.title("Tìm kiếm Public Key")
        search_window.transient(self.root)
        search_window.grab_set()
        search_window.configure(bg="#f6faff", padx=30, pady=30)

        def style_label(widget):
            widget.configure(bg="#f6faff", fg="#1976d2", font=("Segoe UI", 12, "bold"))
        def style_entry(widget):
            widget.configure(bg="#fff", fg="#222", font=("Segoe UI", 12), relief="groove", bd=2, highlightbackground="#1976d2", highlightcolor="#1976d2", highlightthickness=1, insertbackground="#1976d2")
        def style_error(widget):
            widget.configure(bg="#f6faff", fg="#d32f2f", font=("Segoe UI", 10, "italic"))

        email_label = tk.Label(search_window, text="Nhập Email để tìm kiếm")
        style_label(email_label)
        email_label.pack(pady=(0,5), anchor="w")
        search_entry = tk.Entry(search_window)
        style_entry(search_entry)
        search_entry.pack(pady=5, fill="x")
        error_label = tk.Label(search_window, text="")
        style_error(error_label)
        error_label.pack(anchor="w", pady=5)

        def perform_search():
            search_email = search_entry.get().strip()
            if not search_email:
                error_label.config(text="Email là bắt buộc")
                return

            try:
                result, message, similar_emails = search_public_key(self.email, search_email)

                if result is None:
                    if similar_emails:
                        similar_emails_str = "\n".join(similar_emails)
                        messagebox.showinfo("Không tìm thấy", f"{message}\nEmail tương tự:\n{similar_emails_str}")
                    else:
                        messagebox.showinfo("Không tìm thấy", message)
                    log_action(self.email, f"Tìm kiếm public key", f"Failed: không tìm thấy '{search_email}'")
                    return

                result_window = tk.Toplevel(self.root)
                result_window.title(f"Public Key - {search_email}")
                result_window.transient(self.root)
                result_window.grab_set()
                result_window.configure(padx=20, pady=20)

                # Frame for key details
                key_frame = tk.Frame(result_window)
                key_frame.pack(fill="both", expand=True, pady=10)

                # Error label for invalid data
                error_label_result = tk.Label(key_frame, text="", fg="red")
                error_label_result.pack(anchor="w", pady=5)

                # Entry widgets for key details
                tk.Label(key_frame, text="Email:").pack(anchor="w")
                email_entry = tk.Entry(key_frame, width=50)
                email_entry.insert(0, search_email)
                email_entry.config(state="readonly")
                email_entry.pack(fill="both", expand=True, pady=2)

                tk.Label(key_frame, text="Khóa công khai (Rút gọn):").pack(anchor="w")
                public_key_entry = tk.Entry(key_frame, width=50)
                truncated_key = result["public_key"][:60] + "..." if len(result["public_key"]) > 60 else result["public_key"]
                public_key_entry.insert(0, truncated_key)
                public_key_entry.config(state="readonly")
                public_key_entry.pack(fill="both", expand=True, pady=2)

                tk.Label(key_frame, text="Ngày tạo:").pack(anchor="w")
                created_entry = tk.Entry(key_frame, width=50)
                created = datetime.fromisoformat(result["created"]).strftime("%Y-%m-%d %H:%M:%S")
                created_entry.insert(0, created)
                created_entry.config(state="readonly")
                created_entry.pack(fill="both", expand=True, pady=2)

                tk.Label(key_frame, text="Ngày hết hạn:").pack(anchor="w")
                expires_entry = tk.Entry(key_frame, width=50)
                expires = datetime.fromisoformat(result["expires"]).strftime("%Y-%m-%d %H:%M:%S")
                expires_entry.insert(0, expires)
                expires_entry.config(state="readonly")
                expires_entry.pack(fill="both", expand=True, pady=2)

                tk.Label(key_frame, text="Trạng thái:").pack(anchor="w")
                status_entry = tk.Entry(key_frame, width=50)
                status = result["status"]
                status_entry.insert(0, status)
                status_entry.config(state="readonly")
                status_entry.pack(fill="both", expand=True, pady=2)

                tk.Label(key_frame, text="Số ngày còn lại:").pack(anchor="w")
                valid_days_entry = tk.Entry(key_frame, width=50)
                now = datetime.now(ZoneInfo("Asia/Ho_Chi_Minh"))
                expires_dt = datetime.fromisoformat(result["expires"])
                valid_days = (expires_dt - now).days
                valid_days_left = str(valid_days) if result["status"] != "revoked" else "Revoked"
                valid_days_entry.insert(0, valid_days_left)
                valid_days_entry.config(state="readonly")
                valid_days_entry.pack(fill="both", expand=True, pady=2)

                # Force UI update
                key_frame.update()

                # Validate required fields
                required_fields = ["public_key", "created", "expires", "status"]
                if not all(field in result for field in required_fields):
                    error_label_result.config(text="Dữ liệu khóa không đầy đủ.")
                    log_action(self.email, "Tìm kiếm public key", f"Failed: Public key không đủ thông tin")
                    return

                # QR code display
                tk.Label(key_frame, text="QR Code Khóa công khai:").pack(anchor="w", pady=5)
                qr_label = tk.Label(key_frame)
                qr_label.pack(pady=5)
                safe_search_email = search_email.replace("@", "_at_").replace(".", "_dot_")
                qr_path = Path(f"./data/{safe_search_email}/public_key_qr.png")
                try:
                    img = Image.open(qr_path)
                    img = img.resize((150, 150), Image.Resampling.LANCZOS)
                    qr_image = ImageTk.PhotoImage(img)
                    qr_label.config(image=qr_image)
                    qr_label.image = qr_image
                except FileNotFoundError:
                    pass

                # Close button
                button_frame = tk.Frame(result_window)
                button_frame.pack(pady=10)
                tk.Button(button_frame, text="Đóng", command=result_window.destroy).pack(side=tk.LEFT, padx=5)

                # Adjust window size and allow flexible resizing
                result_window.update_idletasks()
                req_width = key_frame.winfo_reqwidth() + 80
                req_height = key_frame.winfo_reqheight() + 120
                x = (result_window.winfo_screenwidth() - req_width) // 2
                y = (result_window.winfo_screenheight() - req_height) // 2
                result_window.geometry(f"{req_width}x{req_height}+{x}+{y}")
                result_window.minsize(700, 500)
                result_window.resizable(True, True)

            except Exception as e:
                log_action(self.email, "Tìm kiếm public key", f"Failed: {str(e)}")
                messagebox.showerror("Lỗi", f"Không thể tìm kiếm public key: {str(e)}")

        button_frame = tk.Frame(search_window, bg="#f6faff")
        button_frame.pack(pady=20)
        def style_button(widget):
            widget.configure(bg="#1976d2", fg="#fff", font=("Segoe UI", 12, "bold"), activebackground="#2196f3", activeforeground="#fff", relief="flat", bd=0, padx=16, pady=8, cursor="hand2")
        search_btn = tk.Button(button_frame, text="Tìm kiếm", command=perform_search)
        style_button(search_btn)
        search_btn.pack(side=tk.LEFT, padx=10)
        cancel_btn = tk.Button(button_frame, text="Hủy", command=search_window.destroy)
        style_button(cancel_btn)
        cancel_btn.pack(side=tk.LEFT, padx=10)

        search_window.update_idletasks()
        req_width = search_window.winfo_reqwidth() + 40
        req_height = search_window.winfo_reqheight() + 40
        x = (search_window.winfo_screenwidth() - req_width) // 2
        y = (search_window.winfo_screenheight() - req_height) // 2
        search_window.geometry(f"{req_width}x{req_height}+{x}+{y}")

    def encrypt_file(self):
        encrypt_window = tk.Toplevel(self.root)
        encrypt_window.title("Mã hóa File")
        encrypt_window.transient(self.root)
        encrypt_window.grab_set()
        encrypt_window.configure(bg="#f6faff", padx=30, pady=30)

        def style_label(widget):
            widget.configure(bg="#f6faff", fg="#1976d2", font=("Segoe UI", 12, "bold"))
        def style_entry(widget):
            widget.configure(bg="#fff", fg="#222", font=("Segoe UI", 12), relief="groove", bd=2, highlightbackground="#1976d2", highlightcolor="#1976d2", highlightthickness=1, insertbackground="#1976d2")
        def style_error(widget):
            widget.configure(bg="#f6faff", fg="#d32f2f", font=("Segoe UI", 10, "italic"))

        file_label = tk.Label(encrypt_window, text="Chọn File cần mã hóa")
        style_label(file_label)
        file_label.pack(pady=(0,5), anchor="w")
        file_entry = tk.Entry(encrypt_window, width=50)
        style_entry(file_entry)
        file_entry.pack(pady=5, fill="x")
        browse_btn = tk.Button(encrypt_window, text="Browse", command=lambda: file_entry.insert(0, filedialog.askopenfilename()))
        browse_btn.pack(pady=5)

        email_label = tk.Label(encrypt_window, text="Email người nhận")
        style_label(email_label)
        email_label.pack(pady=(10,5), anchor="w")
        email_entry = tk.Entry(encrypt_window)
        style_entry(email_entry)
        email_entry.pack(pady=5, fill="x")

        format_label = tk.Label(encrypt_window, text="Chọn định dạng lưu")
        style_label(format_label)
        format_label.pack(pady=(10,5), anchor="w")
        split_key_var = tk.BooleanVar(value=False)
        radio_frame = tk.Frame(encrypt_window, bg="#f6faff")
        radio_frame.pack(pady=5, anchor="w")
        radio1 = tk.Radiobutton(radio_frame, text="Một file .enc", variable=split_key_var, value=False, bg="#f6faff", fg="#1976d2", font=("Segoe UI", 11))
        radio2 = tk.Radiobutton(radio_frame, text="Tách thành 2 file .enc và .key", variable=split_key_var, value=True, bg="#f6faff", fg="#1976d2", font=("Segoe UI", 11))
        radio1.pack(side=tk.LEFT, padx=10)
        radio2.pack(side=tk.LEFT, padx=10)

        error_label = tk.Label(encrypt_window, text="")
        style_error(error_label)
        error_label.pack(anchor="w", pady=5)

        def perform_encryption():
            input_path = file_entry.get().strip()
            recipient_email = email_entry.get().strip()
            split_key = split_key_var.get()

            if not input_path or not recipient_email:
                error_label.config(text="File và email người nhận không được để trống")
                return

            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, recipient_email):
                error_label.config(text="Email sai định dạng")
                return

            try:
                enc_path, key_path = encrypt_file_with_metadata(input_path, recipient_email, self.email, split_key)
                message = f"File enc được mã hóa thành công và lưu tại: {enc_path}"
                if key_path:
                    message += f"\nFile Key lưu tại: {key_path}"
                messagebox.showinfo("Thành công", message)
                encrypt_window.destroy()
            except ValueError as e:
                error_label.config(text=str(e))
            except Exception as e:
                error_label.config(text=f"Mã hóa thất bại: {str(e)}")

        button_frame = tk.Frame(encrypt_window, bg="#f6faff")
        button_frame.pack(pady=20)
        def style_button(widget):
            widget.configure(bg="#1976d2", fg="#fff", font=("Segoe UI", 12, "bold"), activebackground="#2196f3", activeforeground="#fff", relief="flat", bd=0, padx=16, pady=8, cursor="hand2")
        encrypt_btn = tk.Button(button_frame, text="Mã hóa", command=perform_encryption)
        style_button(encrypt_btn)
        encrypt_btn.pack(side=tk.LEFT, padx=10)
        cancel_btn = tk.Button(button_frame, text="Hủy", command=encrypt_window.destroy)
        style_button(cancel_btn)
        cancel_btn.pack(side=tk.LEFT, padx=10)

        encrypt_window.update_idletasks()
        req_width = max(encrypt_window.winfo_reqwidth() + 40, 400)
        req_height = max(encrypt_window.winfo_reqheight() + 40, 300)
        x = (encrypt_window.winfo_screenwidth() - req_width) // 2
        y = (encrypt_window.winfo_screenheight() - req_height) // 2
        encrypt_window.geometry(f"{req_width}x{req_height}+{x}+{y}")

    def decrypt_file(self):
        decrypt_window = tk.Toplevel(self.root)
        decrypt_window.title("Giải mã File")
        decrypt_window.transient(self.root)
        decrypt_window.grab_set()
        decrypt_window.configure(bg="#f6faff", padx=30, pady=30)

        def style_label(widget):
            widget.configure(bg="#f6faff", fg="#1976d2", font=("Segoe UI", 12, "bold"))
        def style_entry(widget):
            widget.configure(bg="#fff", fg="#222", font=("Segoe UI", 12), relief="groove", bd=2, highlightbackground="#1976d2", highlightcolor="#1976d2", highlightthickness=1, insertbackground="#1976d2")
        def style_error(widget):
            widget.configure(bg="#f6faff", fg="#d32f2f", font=("Segoe UI", 10, "italic"))

        safe_email = self.email.replace("@", "_at_").replace(".", "_dot_")
        storage_dir = Path(f"data/{safe_email}/storage")

        file_label = tk.Label(decrypt_window, text="Chọn file .enc đã bị mã hóa (đảm bảo key nằm cùng thư mục)")
        style_label(file_label)
        file_label.pack(pady=(0,5), anchor="w")
        file_entry = tk.Entry(decrypt_window, width=50)
        style_entry(file_entry)
        file_entry.pack(pady=5, fill="x")
        browse_btn = tk.Button(decrypt_window, text="Browse", command=lambda: file_entry.insert(0, filedialog.askopenfilename(initialdir=storage_dir, filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")])) )
        browse_btn.pack(pady=5)

        pass_label = tk.Label(decrypt_window, text="Nhập passphrase")
        style_label(pass_label)
        pass_label.pack(pady=(10,5), anchor="w")
        passphrase_entry = tk.Entry(decrypt_window, show="*")
        style_entry(passphrase_entry)
        passphrase_entry.pack(pady=5, fill="x")

        error_label = tk.Label(decrypt_window, text="")
        style_error(error_label)
        error_label.pack(anchor="w", pady=5)

        def perform_decryption():
            enc_path = file_entry.get().strip()
            passphrase = passphrase_entry.get().strip()

            if not enc_path:
                error_label.config(text="File bị mã không được để trống")
                return

            if not passphrase:
                error_label.config(text="Passphrase không được để trống")
                return

            valid, error = validate_passphrase(passphrase)
            if not valid:
                error_label.config(text=error)
                return

            success, message = verify_passphrase(self.email, passphrase)
            if not success:
                error_label.config(text="Passphrase bị sai")
                log_action(self.email, "Giải mã File", f"Failed: Passphrase bị sai")
                return

            try:
                output_path, metadata = decrypt_file(enc_path, passphrase, self.email)
                result_window = tk.Toplevel(self.root)
                result_window.title("Kết quả giải mã")
                result_window.transient(self.root)
                result_window.grab_set()

                tk.Label(result_window, text=f"File giải mã đã được lưu tại: {output_path}", anchor="w").pack(fill="x", pady=5)
                tk.Label(result_window, text="Metadata:", anchor="w").pack(fill="x", pady=5)
                for key, value in metadata.items():
                    tk.Label(result_window, text=f"{key}: {value}", anchor="w").pack(fill="x", pady=2)
                tk.Button(result_window, text="Close", command=result_window.destroy).pack(pady=10)

                result_window.update_idletasks()
                req_width = max(result_window.winfo_reqwidth() + 40, 400)
                req_height = max(result_window.winfo_reqheight() + 40, 300)
                x = (result_window.winfo_screenwidth() - req_width) // 2
                y = (result_window.winfo_screenheight() - req_height) // 2
                result_window.geometry(f"{req_width}x{req_height}+{x}+{y}")

                messagebox.showinfo("Thành công", f"Giải mã thành công: {output_path}")
                decrypt_window.destroy()
            except ValueError as e:
                error_label.config(text=str(e))
            except Exception as e:
                error_label.config(text=f"Thất bại: {str(e)}")

        button_frame = tk.Frame(decrypt_window, bg="#f6faff")
        button_frame.pack(pady=20)
        def style_button(widget):
            widget.configure(bg="#1976d2", fg="#fff", font=("Segoe UI", 12, "bold"), activebackground="#2196f3", activeforeground="#fff", relief="flat", bd=0, padx=16, pady=8, cursor="hand2")
        decrypt_btn = tk.Button(button_frame, text="Giải mã", command=perform_decryption)
        style_button(decrypt_btn)
        decrypt_btn.pack(side=tk.LEFT, padx=10)
        cancel_btn = tk.Button(button_frame, text="Hủy", command=decrypt_window.destroy)
        style_button(cancel_btn)
        cancel_btn.pack(side=tk.LEFT, padx=10)

        decrypt_window.update_idletasks()
        req_width = max(decrypt_window.winfo_reqwidth() + 40, 400)
        req_height = max(decrypt_window.winfo_reqheight() + 40, 300)
        x = (decrypt_window.winfo_screenwidth() - req_width) // 2
        y = (decrypt_window.winfo_screenheight() - req_height) // 2
        decrypt_window.geometry(f"{req_width}x{req_height}+{x}+{y}")

    def sign_file(self):
        sign_window = tk.Toplevel(self.root)
        sign_window.title("Ký File")
        sign_window.transient(self.root)
        sign_window.grab_set()
        sign_window.configure(bg="#f6faff", padx=30, pady=30)

        def style_label(widget):
            widget.configure(bg="#f6faff", fg="#1976d2", font=("Segoe UI", 12, "bold"))
        def style_entry(widget):
            widget.configure(bg="#fff", fg="#222", font=("Segoe UI", 12), relief="groove", bd=2, highlightbackground="#1976d2", highlightcolor="#1976d2", highlightthickness=1, insertbackground="#1976d2")
        def style_error(widget):
            widget.configure(bg="#f6faff", fg="#d32f2f", font=("Segoe UI", 10, "italic"))

        file_label = tk.Label(sign_window, text="Chọn file để ký")
        style_label(file_label)
        file_label.pack(pady=(0,5), anchor="w")
        file_entry = tk.Entry(sign_window, width=50)
        style_entry(file_entry)
        file_entry.pack(pady=5, fill="x")
        browse_btn = tk.Button(sign_window, text="Browse", command=lambda: file_entry.insert(0, filedialog.askopenfilename()))
        browse_btn.pack(pady=5)

        pass_label = tk.Label(sign_window, text="Nhập Passphrase")
        style_label(pass_label)
        pass_label.pack(pady=(10,5), anchor="w")
        passphrase_entry = tk.Entry(sign_window, show="*")
        style_entry(passphrase_entry)
        passphrase_entry.pack(pady=5, fill="x")

        error_label = tk.Label(sign_window, text="")
        style_error(error_label)
        error_label.pack(anchor="w", pady=5)

        def perform_sign():
            file_path = file_entry.get().strip()
            passphrase = passphrase_entry.get().strip()

            error_label.config(text="")
            if not file_path or not passphrase:
                error_label.config(text="Vui lòng chọn file và nhập passphrase.")
                return

            try:
                success, message, sig_path = sign_file(file_path, self.email, passphrase)
                if success:
                    messagebox.showinfo("Thành công", message, parent=sign_window)
                    sign_window.destroy()
                else:
                    error_label.config(text=message)
            except Exception as e:
                error_label.config(text=f"Đã xảy ra lỗi không mong muốn: {str(e)}")
                log_action(self.email, "Ký số File", f"Failed: {str(e)}")

        button_frame = tk.Frame(sign_window, bg="#f6faff")
        button_frame.pack(pady=20)
        def style_button(widget):
            widget.configure(bg="#1976d2", fg="#fff", font=("Segoe UI", 12, "bold"), activebackground="#2196f3", activeforeground="#fff", relief="flat", bd=0, padx=16, pady=8, cursor="hand2")
        sign_btn = tk.Button(button_frame, text="Ký", command=perform_sign)
        style_button(sign_btn)
        sign_btn.pack(side=tk.LEFT, padx=10)
        cancel_btn = tk.Button(button_frame, text="Hủy", command=sign_window.destroy)
        style_button(cancel_btn)
        cancel_btn.pack(side=tk.LEFT, padx=10)

        sign_window.update_idletasks()
        req_width = max(sign_window.winfo_reqwidth() + 40, 350)
        req_height = max(sign_window.winfo_reqheight() + 40, 220)
        x = (sign_window.winfo_screenwidth() - req_width) // 2
        y = (sign_window.winfo_screenheight() - req_height) // 2
        sign_window.geometry(f"{req_width}x{req_height}+{x}+{y}")

    def verify_signature(self):
        verify_window = tk.Toplevel(self.root)
        verify_window.title("Xác Thực Chữ Ký")
        verify_window.transient(self.root)
        verify_window.grab_set()
        verify_window.configure(bg="#f6faff", padx=30, pady=30)

        def style_label(widget):
            widget.configure(bg="#f6faff", fg="#1976d2", font=("Segoe UI", 12, "bold"))
        def style_entry(widget):
            widget.configure(bg="#fff", fg="#222", font=("Segoe UI", 12), relief="groove", bd=2, highlightbackground="#1976d2", highlightcolor="#1976d2", highlightthickness=1, insertbackground="#1976d2")
        def style_error(widget):
            widget.configure(bg="#f6faff", fg="#d32f2f", font=("Segoe UI", 10, "italic"))

        file_label = tk.Label(verify_window, text="Chọn file gốc")
        style_label(file_label)
        file_label.pack(pady=(0,5), anchor="w")
        file_entry = tk.Entry(verify_window, width=50)
        style_entry(file_entry)
        file_entry.pack(pady=5, fill="x")
        browse_file_btn = tk.Button(verify_window, text="Browse", command=lambda: file_entry.insert(0, filedialog.askopenfilename()))
        browse_file_btn.pack(pady=5)

        sig_label = tk.Label(verify_window, text="Chọn file chữ ký (.sig)")
        style_label(sig_label)
        sig_label.pack(pady=(10,5), anchor="w")
        sig_entry = tk.Entry(verify_window, width=50)
        style_entry(sig_entry)
        sig_entry.pack(pady=5, fill="x")
        browse_sig_btn = tk.Button(verify_window, text="Browse", command=lambda: sig_entry.insert(0, filedialog.askopenfilename(filetypes=[("Signature Files", "*.sig"), ("All Files", "*.*")])) )
        browse_sig_btn.pack(pady=5)

        error_label = tk.Label(verify_window, text="")
        style_error(error_label)
        error_label.pack(anchor="w", pady=5)

        def perform_verify():
            file_path = file_entry.get().strip()
            sig_path = sig_entry.get().strip()

            error_label.config(text="")
            if not file_path or not sig_path:
                error_label.config(text="Vui lòng chọn cả file gốc và file chữ ký.")
                return

            try:
                result = verify_signature(file_path, sig_path, self.email)

                if result.get("valid"):
                    message = (f"Xác thực thành công!\n\n"
                               f"Người ký: {result.get('signer_email', 'N/A')}\n"
                               f"Thời gian ký: {datetime.fromisoformat(result['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}")
                    messagebox.showinfo("Thành công", message, parent=verify_window)
                    verify_window.destroy()
                else:
                    error_message = result.get("message", "Lỗi không xác định.")
                    error_label.config(text=f"Xác thực chữ ký thất bại.\nLý do: {error_message}")
            except Exception as e:
                error_label.config(text=f"Đã xảy ra lỗi trong quá trình xác thực: {str(e)}")
                log_action(self.email, "Xác minh chữ ký", f"Failed: {str(e)}")

        button_frame = tk.Frame(verify_window, bg="#f6faff")
        button_frame.pack(pady=20)
        def style_button(widget):
            widget.configure(bg="#1976d2", fg="#fff", font=("Segoe UI", 12, "bold"), activebackground="#2196f3", activeforeground="#fff", relief="flat", bd=0, padx=16, pady=8, cursor="hand2")
        verify_btn = tk.Button(button_frame, text="Xác thực", command=perform_verify)
        style_button(verify_btn)
        verify_btn.pack(side=tk.LEFT, padx=10)
        cancel_btn = tk.Button(button_frame, text="Hủy", command=verify_window.destroy)
        style_button(cancel_btn)
        cancel_btn.pack(side=tk.LEFT, padx=10)

        verify_window.update_idletasks()
        req_width = max(verify_window.winfo_reqwidth() + 40, 350)
        req_height = max(verify_window.winfo_reqheight() + 40, 220)
        x = (verify_window.winfo_screenwidth() - req_width) // 2
        y = (verify_window.winfo_screenheight() - req_height) // 2
        verify_window.geometry(f"{req_width}x{req_height}+{x}+{y}")

    def logout(self):
        log_action(self.email, "Đăng xuất", "Success")
        self.main_window.enable_buttons()
        self.root.destroy()