import tkinter as tk
from tkinter import messagebox, ttk, filedialog
from datetime import datetime
import re, base64
import json
from pathlib import Path
from zoneinfo import ZoneInfo
from PIL import Image, ImageTk
from modules.rsa_keys import generate_rsa_keypair, update_key_status, update_public_key_store, derive_key
from modules.qr_utils import generate_qr_for_public_key, read_qr
from modules.logger import log_action
from modules.pubkey_search import search_public_key
from modules.file_crypto import encrypt_file_with_metadata, decrypt_file
from modules.auth import verify_passphrase, validate_passphrase
from gui.key_status_ui import KeyStorageWindow

class DashboardWindow:
    def __init__(self, root, main_window, user):
        self.root = root
        self.main_window = main_window
        self.user = user
        self.root.title(f"Dashboard - {user['full_name']}")
        self.root.transient(main_window.root)
        self.root.grab_set()

        self.min_width = 400
        self.min_height = 700  # Adjusted for removed button

        self.root.configure(padx=20, pady=20)

        tk.Label(root, text=f"Tên: {user['full_name']}", anchor="w").pack(fill="x", pady=2)
        tk.Label(root, text=f"Email: {user['email']}", anchor="w").pack(fill="x", pady=2)
        tk.Label(root, text=f"Số điện thoại: {user['phone']}", anchor="w").pack(fill="x", pady=2)
        tk.Label(root, text=f"Ngày sinh: {user['dob']}", anchor="w").pack(fill="x", pady=2)
        tk.Label(root, text=f"Địa chỉ: {user['address']}", anchor="w").pack(fill="x", pady=2)

        tk.Frame(root, height=2, bd=1, relief="sunken").pack(fill="x", pady=10)

        tk.Button(root, text="Cập nhật thông tin", command=self.open_update_info).pack(pady=10)
        tk.Button(root, text="Tạo mới RSA keys", command=self.create_new_keys).pack(pady=10)
        tk.Button(root, text="Gia hạn RSA keys", command=self.extend_keys).pack(pady=10)
        tk.Button(root, text="Xem RSA keys", command=self.view_keys).pack(pady=10)
        tk.Button(root, text="Tạo QR code cho Public key", command=self.generate_qr_code).pack(pady=10)
        tk.Button(root, text="Đọc QR code Public key", command=self.read_qr_code).pack(pady=10)
        tk.Button(root, text="Tìm kiếm Public key", command=self.search_public_key).pack(pady=10)
        tk.Button(root, text="Mã hóa tệp", command=self.encrypt_file).pack(pady=10)
        tk.Button(root, text="Giải mã tệp", command=self.decrypt_file).pack(pady=10)
        tk.Button(root, text="Đăng xuất", command=self.logout).pack(pady=10)

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

    def open_update_info(self):
        update_window = tk.Toplevel(self.root)
        update_window.title("Cập nhật thông tin")
        update_window.transient(self.root)
        update_window.grab_set()

        tk.Label(update_window, text="Tên đầy đủ").pack(pady=5)
        name_entry = tk.Entry(update_window)
        name_entry.insert(0, self.user['full_name'])
        name_entry.pack(pady=5)

        tk.Label(update_window, text="Ngày sinh (DD/MM/YYYY)").pack(pady=5)
        dob_entry = tk.Entry(update_window)
        dob_entry.insert(0, self.user['dob'])
        dob_entry.pack(pady=5)
        dob_error = tk.Label(update_window, text="", fg="red")
        dob_error.pack()

        tk.Label(update_window, text="Số điện thoại").pack(pady=5)
        phone_entry = tk.Entry(update_window)
        phone_entry.insert(0, self.user['phone'])
        phone_entry.pack(pady=5)
        phone_error = tk.Label(update_window, text="", fg="red")
        phone_error.pack()

        tk.Label(update_window, text="Địa chỉ").pack(pady=5)
        address_entry = tk.Entry(update_window)
        address_entry.insert(0, self.user['address'])
        address_entry.pack(pady=5)

        def save_changes():
            new_name = name_entry.get()
            new_dob = dob_entry.get()
            new_phone = phone_entry.get()
            new_address = address_entry.get()

            dob_error.config(text="")
            phone_error.config(text="")

            if not all([new_name, new_dob, new_phone, new_address]):
                messagebox.showerror("Lỗi", "Tất cả các trường đều bắt buộc")
                return

            if not self.validate_dob(new_dob):
                dob_error.config(text="Ngày không hợp lệ hoặc sai định dạng (dùng DD/MM/YYYY)")
                return

            if not self.validate_phone(new_phone):
                phone_error.config(text="Định dạng số điện thoại không hợp lệ")
                return

            users_file = Path("./data/users.json")
            try:
                with open(users_file, "r") as f:
                    users = json.load(f)
                for user in users:
                    if user["email"] == self.user["email"]:
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
                log_action(self.user["email"], "update_info", "success")
                messagebox.showinfo("Thành công", "Thông tin đã được cập nhật thành công")
                update_window.destroy()
                self.root.destroy()
                new_dashboard = tk.Toplevel(self.main_window.root)
                DashboardWindow(new_dashboard, self.main_window, self.user)
            except Exception as e:
                log_action(self.user["email"], "update_info", f"failed: {str(e)}")
                messagebox.showerror("Lỗi", f"Không thể cập nhật thông tin: {str(e)}")

        button_frame = tk.Frame(update_window)
        button_frame.pack(pady=10)
        tk.Button(button_frame, text="Lưu", command=save_changes).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Hủy", command=update_window.destroy).pack(side=tk.LEFT, padx=5)

        update_window.update_idletasks()
        req_width = update_window.winfo_reqwidth() + 40
        req_height = update_window.winfo_reqheight() + 40
        x = (update_window.winfo_screenwidth() - req_width) // 2
        y = (update_window.winfo_screenheight() - req_height) // 2
        update_window.geometry(f"{req_width}x{req_height}+{x}+{y}")

    def create_new_keys(self):
        passphrase_window = tk.Toplevel(self.root)
        passphrase_window.title("Tạo mới RSA keys")
        passphrase_window.transient(self.root)
        passphrase_window.grab_set()

        tk.Label(passphrase_window, text="Nhập passphrase").pack(pady=5)
        passphrase_entry = tk.Entry(passphrase_window, show="*")
        passphrase_entry.pack(pady=5)

        tk.Label(passphrase_window, text="Nhập recovery code (tùy chọn)").pack(pady=5)
        recovery_entry = tk.Entry(passphrase_window, show="*")
        recovery_entry.pack(pady=5)

        error_label = tk.Label(passphrase_window, text="", fg="red")
        error_label.pack()

        def submit_passphrase():
            passphrase = passphrase_entry.get().strip()
            recovery_code = recovery_entry.get().strip() or None
            if not passphrase:
                error_label.config(text="Passphrase là bắt buộc")
                return

            valid, error = validate_passphrase(passphrase)
            if not valid:
                error_label.config(text=error)
                return

            success, message = verify_passphrase(self.user["email"], passphrase)
            if not success:
                error_label.config(text="Passphrase không hợp lệ")
                log_action(self.user["email"], "create_rsa_keys", f"failed: {message}")
                return

            if recovery_code:
                try:
                    with open(Path("./data/users.json"), "r") as f:
                        users = json.load(f)
                    user = next((u for u in users if u["email"] == self.user["email"]), None)
                    if not user:
                        error_label.config(text="Không tìm thấy người dùng")
                        return
                    recovery_code_hash = base64.b64decode(user["recovery_code_hash"])
                    recovery_salt = base64.b64decode(user["recovery_code_salt"])
                    input_hash = derive_key(recovery_code, recovery_salt)
                    if recovery_code_hash != input_hash:
                        error_label.config(text="Recovery code không hợp lệ")
                        log_action(self.user["email"], "create_rsa_keys", "failed: Invalid recovery code")
                        return
                except Exception as e:
                    error_label.config(text=f"Lỗi: {str(e)}")
                    log_action(self.user["email"], "create_rsa_keys", f"failed: {str(e)}")
                    return

            try:
                key_data = generate_rsa_keypair(self.user["email"], passphrase, recovery_code, mode="renew")
                update_public_key_store(self.user["email"])
                log_action(self.user["email"], "create_rsa_keys", "success")
                messagebox.showinfo("Thành công", "RSA keys được tạo thành công")
                passphrase_window.destroy()
            except Exception as e:
                log_action(self.user["email"], "create_rsa_keys", f"failed: {str(e)}")
                error_label.config(text=f"Lỗi: {str(e)}")

        button_frame = tk.Frame(passphrase_window)
        button_frame.pack(pady=10)
        tk.Button(button_frame, text="Tạo", command=submit_passphrase).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Hủy", command=passphrase_window.destroy).pack(side=tk.LEFT, padx=5)

        passphrase_window.update_idletasks()
        req_width = passphrase_window.winfo_reqwidth() + 40
        req_height = passphrase_window.winfo_reqheight() + 40
        x = (passphrase_window.winfo_screenwidth() - req_width) // 2
        y = (passphrase_window.winfo_screenheight() - req_height) // 2
        passphrase_window.geometry(f"{req_width}x{req_height}+{x}+{y}")

    def extend_keys(self):
        passphrase_window = tk.Toplevel(self.root)
        passphrase_window.title("Gia hạn RSA keys")
        passphrase_window.transient(self.root)
        passphrase_window.grab_set()

        tk.Label(passphrase_window, text="Nhập passphrase").pack(pady=5)
        passphrase_entry = tk.Entry(passphrase_window, show="*")
        passphrase_entry.pack(pady=5)

        tk.Label(passphrase_window, text="Nhập recovery code (tùy chọn)").pack(pady=5)
        recovery_entry = tk.Entry(passphrase_window, show="*")
        recovery_entry.pack(pady=5)

        error_label = tk.Label(passphrase_window, text="", fg="red")
        error_label.pack()

        def submit_passphrase():
            passphrase = passphrase_entry.get().strip()
            recovery_code = recovery_entry.get().strip() or None
            if not passphrase:
                error_label.config(text="Passphrase là bắt buộc")
                return

            valid, error = validate_passphrase(passphrase)
            if not valid:
                error_label.config(text=error)
                return

            success, message = verify_passphrase(self.user["email"], passphrase)
            if not success:
                error_label.config(text="Passphrase không hợp lệ")
                log_action(self.user["email"], "extend_rsa_keys", f"failed: {message}")
                return

            if recovery_code:
                try:
                    with open(Path("./data/users.json"), "r") as f:
                        users = json.load(f)
                    user = next((u for u in users if u["email"] == self.user["email"]), None)
                    if not user:
                        error_label.config(text="Không tìm thấy người dùng")
                        return
                    recovery_code_hash = base64.b64decode(user["recovery_code_hash"])
                    recovery_salt = base64.b64decode(user["recovery_code_salt"])
                    input_hash = derive_key(recovery_code, recovery_salt)
                    if recovery_code_hash != input_hash:
                        error_label.config(text="Recovery code không hợp lệ")
                        log_action(self.user["email"], "extend_rsa_keys", "failed: Invalid recovery code")
                        return
                except Exception as e:
                    error_label.config(text=f"Lỗi: {str(e)}")
                    log_action(self.user["email"], "extend_rsa_keys", f"failed: {str(e)}")
                    return

            try:
                key_data = generate_rsa_keypair(self.user["email"], passphrase, recovery_code, mode="extend")
                update_public_key_store(self.user["email"])
                log_action(self.user["email"], "extend_rsa_keys", "success")
                messagebox.showinfo("Thành công", "RSA keys đã được gia hạn thành công")
                passphrase_window.destroy()
            except Exception as e:
                log_action(self.user["email"], "extend_rsa_keys", f"failed: {str(e)}")
                error_label.config(text=f"Lỗi: {str(e)}")

        button_frame = tk.Frame(passphrase_window)
        button_frame.pack(pady=10)
        tk.Button(button_frame, text="Gia hạn", command=submit_passphrase).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Hủy", command=passphrase_window.destroy).pack(side=tk.LEFT, padx=5)

        passphrase_window.update_idletasks()
        req_width = passphrase_window.winfo_reqwidth() + 40
        req_height = passphrase_window.winfo_reqheight() + 40
        x = (passphrase_window.winfo_screenwidth() - req_width) // 2
        y = (passphrase_window.winfo_screenheight() - req_height) // 2
        passphrase_window.geometry(f"{req_width}x{req_height}+{x}+{y}")

    def view_keys(self):
        safe_email = self.user["email"].replace("@", "_at_").replace(".", "_dot_")
        current_key_path = Path(f"./data/{safe_email}/rsa_keypair.json")
        now = datetime.now(ZoneInfo("Asia/Ho_Chi_Minh"))
        try:
            with open(current_key_path, "r") as f:
                key_data = json.load(f)
                key_data = update_key_status(key_data, now)
                with open(current_key_path, "w") as f:
                    json.dump(key_data, f, indent=4)
            update_public_key_store(self.user["email"])
            log_action(self.user["email"], "view_keys", "success: Updated key status")
            key_window = tk.Toplevel(self.root)
            KeyStorageWindow(key_window, self, safe_email)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            log_action(self.user["email"], "view_keys", f"failed: {str(e)}")
            messagebox.showerror("Lỗi", "Không tìm thấy RSA keys. Vui lòng tạo mới.")

    def generate_qr_code(self):
        safe_email = self.user["email"].replace("@", "_at_").replace(".", "_dot_")
        try:
            qr_path, message = generate_qr_for_public_key(self.user["email"], safe_email)
            qr_window = tk.Toplevel(self.root)
            qr_window.title("QR Code Public Key")
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
            messagebox.showerror("Lỗi", f"Không thể tạo QR code: {str(e)}")
            log_action(self.user["email"], "generate_qr_code", f"failed: {str(e)}")

    def read_qr_code(self):
        file_path = filedialog.askopenfilename(filetypes=[("PNG Images", "*.png"), ("All Files", "*.*")])
        if not file_path:
            return

        try:
            qr_data, status_msg = read_qr(self.user["email"], file_path)
            qr_info_window = tk.Toplevel(self.root)
            qr_info_window.title("Thông tin QR Code")
            qr_info_window.transient(self.root)
            qr_info_window.grab_set()

            tk.Label(qr_info_window, text=f"Email: {qr_data['email']}", anchor="w").pack(fill="x", pady=5)
            tk.Label(qr_info_window, text=f"Ngày tạo: {datetime.fromisoformat(qr_data['created']).strftime('%Y-%m-%d')}", anchor="w").pack(fill="x", pady=5)
            tk.Label(qr_info_window, text=f"Hết hạn: {datetime.fromisoformat(qr_data['expires']).strftime('%Y-%m-%d')}", anchor="w").pack(fill="x", pady=5)
            tk.Label(qr_info_window, text=f"Public Key: {qr_data['public_key']}", anchor="w").pack(fill="x", pady=5)
            tk.Label(qr_info_window, text=f"Lưu trữ: {status_msg}", anchor="w").pack(fill="x", pady=5)
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
            messagebox.showerror("Lỗi", f"Không thể đọc QR code: {str(e)}")

    def search_public_key(self):
        search_window = tk.Toplevel(self.root)
        search_window.title("Tìm kiếm Public Key")
        search_window.transient(self.root)
        search_window.grab_set()

        tk.Label(search_window, text="Nhập Email để tìm kiếm").pack(pady=5)
        email_entry = tk.Entry(search_window)
        email_entry.pack(pady=5)
        error_label = tk.Label(search_window, text="", fg="red")
        error_label.pack()

        def perform_search():
            search_email = email_entry.get().strip()
            if not search_email:
                error_label.config(text="Email là bắt buộc")
                return

            try:
                result, message, similar_emails = search_public_key(self.user["email"], search_email)

                if result is None:
                    if similar_emails:
                        similar_emails_str = "\n".join(similar_emails)
                        messagebox.showinfo("Không tìm thấy", f"{message}\nEmail tương tự:\n{similar_emails_str}")
                    else:
                        messagebox.showinfo("Không tìm thấy", message)
                    return

                result_window = tk.Toplevel(self.root)
                result_window.title(f"Public Key - {search_email}")
                result_window.transient(self.root)
                result_window.grab_set()

                tk.Label(result_window, text=f"Email: {search_email}", anchor="w").pack(fill="x", pady=5)
                tk.Label(result_window, text=f"Ngày tạo: {datetime.fromisoformat(result['created']).strftime('%Y-%m-%d')}", anchor="w").pack(fill="x", pady=5)
                tk.Label(result_window, text=f"Hết hạn: {datetime.fromisoformat(result['expires']).strftime('%Y-%m-%d')}", anchor="w").pack(fill="x", pady=5)
                tk.Label(result_window, text=f"Trạng thái: {result['status']}", anchor="w").pack(fill="x", pady=5)
                tk.Label(result_window, text=f"Public Key: {result['public_key'][:20]}...", anchor="w").pack(fill="x", pady=5)
                tk.Button(result_window, text="Đóng", command=result_window.destroy).pack(pady=10)

                result_window.update_idletasks()
                req_width = max(result_window.winfo_reqwidth() + 40, 400)
                req_height = max(result_window.winfo_reqheight() + 40, 300)
                x = (result_window.winfo_screenwidth() - req_width) // 2
                y = (result_window.winfo_screenheight() - req_height) // 2
                result_window.geometry(f"{req_width}x{req_height}+{x}+{y}")

            except Exception as e:
                messagebox.showerror("Lỗi", f"Không thể tìm kiếm public key: {str(e)}")

        button_frame = tk.Frame(search_window)
        button_frame.pack(pady=10)
        tk.Button(button_frame, text="Tìm kiếm", command=perform_search).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Hủy", command=search_window.destroy).pack(side=tk.LEFT, padx=5)

        search_window.update_idletasks()
        req_width = search_window.winfo_reqwidth() + 40
        req_height = search_window.winfo_reqheight() + 40
        x = (search_window.winfo_screenwidth() - req_width) // 2
        y = (search_window.winfo_screenheight() - req_height) // 2
        search_window.geometry(f"{req_width}x{req_height}+{x}+{y}")

    def encrypt_file(self):
        encrypt_window = tk.Toplevel(self.root)
        encrypt_window.title("Mã hóa tệp")
        encrypt_window.transient(self.root)
        encrypt_window.grab_set()

        tk.Label(encrypt_window, text="Chọn tệp để mã hóa").pack(pady=5)
        file_entry = tk.Entry(encrypt_window, width=50)
        file_entry.pack(pady=5)
        tk.Button(encrypt_window, text="Duyệt", command=lambda: file_entry.insert(0, filedialog.askopenfilename())).pack(pady=5)

        tk.Label(encrypt_window, text="Email người nhận").pack(pady=5)
        email_entry = tk.Entry(encrypt_window)
        email_entry.pack(pady=5)

        tk.Label(encrypt_window, text="Định dạng lưu").pack(pady=5)
        split_key_var = tk.BooleanVar(value=False)
        tk.Radiobutton(encrypt_window, text="Tệp .enc duy nhất", variable=split_key_var, value=False).pack()
        tk.Radiobutton(encrypt_window, text="Tách riêng tệp .enc và .key", variable=split_key_var, value=True).pack()

        error_label = tk.Label(encrypt_window, text="", fg="red")
        error_label.pack()

        def perform_encryption():
            input_path = file_entry.get().strip()
            recipient_email = email_entry.get().strip()
            split_key = split_key_var.get()

            if not input_path or not recipient_email:
                error_label.config(text="Tệp và email người nhận là bắt buộc")
                return

            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, recipient_email):
                error_label.config(text="Định dạng email người nhận không hợp lệ")
                return

            try:
                enc_path, key_path = encrypt_file_with_metadata(input_path, recipient_email, self.user["email"], split_key)
                message = f"Tệp được mã hóa thành công: {enc_path}"
                if key_path:
                    message += f"\nTệp khóa: {key_path}"
                messagebox.showinfo("Thành công", message)
                encrypt_window.destroy()
            except ValueError as e:
                error_label.config(text=str(e))
            except Exception as e:
                error_label.config(text=f"Mã hóa thất bại: {str(e)}")

        button_frame = tk.Frame(encrypt_window)
        button_frame.pack(pady=10)
        tk.Button(button_frame, text="Mã hóa", command=perform_encryption).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Hủy", command=encrypt_window.destroy).pack(side=tk.LEFT, padx=5)

        encrypt_window.update_idletasks()
        req_width = max(encrypt_window.winfo_reqwidth() + 40, 400)
        req_height = max(encrypt_window.winfo_reqheight() + 40, 300)
        x = (encrypt_window.winfo_screenwidth() - req_width) // 2
        y = (encrypt_window.winfo_screenheight() - req_height) // 2
        encrypt_window.geometry(f"{req_width}x{req_height}+{x}+{y}")

    def decrypt_file(self):
        decrypt_window = tk.Toplevel(self.root)
        decrypt_window.title("Giải mã tệp")
        decrypt_window.transient(self.root)
        decrypt_window.grab_set()

        safe_email = self.user["email"].replace("@", "_at_").replace(".", "_dot_")
        storage_dir = Path(f"data/{safe_email}/storage")

        tk.Label(decrypt_window, text="Chọn tệp mã hóa (.enc)").pack(pady=5)
        file_entry = tk.Entry(decrypt_window, width=50)
        file_entry.pack(pady=5)
        tk.Button(decrypt_window, text="Duyệt", command=lambda: file_entry.insert(0, filedialog.askopenfilename(
            initialdir=storage_dir, filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")]
        ))).pack(pady=5)

        tk.Label(decrypt_window, text="Nhập passphrase").pack(pady=5)
        passphrase_entry = tk.Entry(decrypt_window, show="*")
        passphrase_entry.pack(pady=5)

        error_label = tk.Label(decrypt_window, text="", fg="red")
        error_label.pack()

        def perform_decryption():
            enc_path = file_entry.get().strip()
            passphrase = passphrase_entry.get().strip()

            if not enc_path:
                error_label.config(text="Tệp mã hóa là bắt buộc")
                return
            if not passphrase:
                error_label.config(text="Passphrase là bắt buộc")
                return

            try:
                output_path, metadata = decrypt_file(enc_path, passphrase, self.user["email"])
                result_window = tk.Toplevel(self.root)
                result_window.title("Kết quả giải mã")
                result_window.transient(self.root)
                result_window.grab_set()

                tk.Label(result_window, text=f"Tệp đã giải mã: {output_path}", anchor="w").pack(fill="x", pady=5)
                tk.Label(result_window, text="Metadata:", anchor="w").pack(fill="x", pady=5)
                for key, value in metadata.items():
                    tk.Label(result_window, text=f"{key}: {value}", anchor="w").pack(fill="x", pady=2)
                tk.Button(result_window, text="Đóng", command=result_window.destroy).pack(pady=10)

                result_window.update_idletasks()
                req_width = max(result_window.winfo_reqwidth() + 40, 400)
                req_height = max(result_window.winfo_reqheight() + 40, 300)
                x = (result_window.winfo_screenwidth() - req_width) // 2
                y = (result_window.winfo_screenheight() - req_height) // 2
                result_window.geometry(f"{req_width}x{req_height}+{x}+{y}")

                messagebox.showinfo("Thành công", f"Tệp được giải mã thành công: {output_path}")
                decrypt_window.destroy()
            except ValueError as e:
                error_label.config(text=str(e))
            except Exception as e:
                error_label.config(text=f"Giải mã thất bại: {str(e)}")

        button_frame = tk.Frame(decrypt_window)
        button_frame.pack(pady=10)
        tk.Button(button_frame, text="Giải mã", command=perform_decryption).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Hủy", command=decrypt_window.destroy).pack(side=tk.LEFT, padx=5)

        decrypt_window.update_idletasks()
        req_width = max(decrypt_window.winfo_reqwidth() + 40, 400)
        req_height = max(decrypt_window.winfo_reqheight() + 40, 300)
        x = (decrypt_window.winfo_screenwidth() - req_width) // 2
        y = (decrypt_window.winfo_screenheight() - req_height) // 2
        decrypt_window.geometry(f"{req_width}x{req_height}+{x}+{y}")

    def logout(self):
        self.main_window.enable_buttons()
        self.root.destroy()