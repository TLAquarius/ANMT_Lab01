import tkinter as tk
from tkinter import messagebox, ttk, filedialog
from datetime import datetime
import re, base64
import json
from pathlib import Path
from zoneinfo import ZoneInfo
from PIL import Image, ImageTk
from modules.rsa_keys import generate_rsa_keypair, update_public_key_store, derive_key
from pyzbar.pyzbar import decode
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
        self.root.title(f"Dashboard - {email}")
        self.root.transient(main_window.root)
        self.root.grab_set()

        self.min_width = 400
        self.min_height = 800

        self.root.configure(padx=20, pady=20)

        # Load user data from users.json
        self.user = self.load_user_data()
        if not self.user:
            messagebox.showerror("Error", "User data not found")
            self.logout()
            return

        tk.Label(root, text=f"Name: {self.user['full_name']}", anchor="w").pack(fill="x", pady=2)
        tk.Label(root, text=f"Email: {self.user['email']}", anchor="w").pack(fill="x", pady=2)
        tk.Label(root, text=f"Phone: {self.user['phone']}", anchor="w").pack(fill="x", pady=2)
        tk.Label(root, text=f"Date of Birth: {self.user['dob']}", anchor="w").pack(fill="x", pady=2)
        tk.Label(root, text=f"Address: {self.user['address']}", anchor="w").pack(fill="x", pady=2)

        tk.Frame(root, height=2, bd=1, relief="sunken").pack(fill="x", pady=10)

        # Admin button for admin users
        if is_admin(self.email):
            tk.Button(root, text="Quản Trị", command=self.open_admin).pack(pady=10)

        tk.Button(root, text="Update Information", command=self.open_update_info).pack(pady=10)
        tk.Button(root, text="View Keys", command=self.view_keys).pack(pady=10)
        tk.Button(root, text="Generate Public Key QR Code", command=self.generate_qr_code).pack(pady=10)
        tk.Button(root, text="Read Public Key QR Code", command=self.read_qr_code).pack(pady=10)
        tk.Button(root, text="Search Public Key", command=self.search_public_key_ui).pack(pady=10)
        tk.Button(root, text="Encrypt File", command=self.encrypt_file).pack(pady=10)
        tk.Button(root, text="Decrypt File", command=self.decrypt_file).pack(pady=10)
        tk.Button(root, text="File Sign", command=self.sign_file).pack(pady=10)
        tk.Button(root, text="Signature Verify", command=self.verify_signature).pack(pady=10)
        tk.Button(root, text="Logout", command=self.logout).pack(pady=10)

        self.adjust_window_size()

    def load_user_data(self):
        """Load user data from users.json based on email."""
        try:
            with open(Path("./data/users.json"), "r") as f:
                users = json.load(f)
            return next((user for user in users if user["email"] == self.email), None)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            log_action(self.email, "load_user_data", f"failed: {str(e)}")
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
        log_action(self.email, "open_admin_window", "success")

    def open_update_info(self):
        update_window = tk.Toplevel(self.root)
        update_window.title("Update Information")
        update_window.transient(self.root)
        update_window.grab_set()

        tk.Label(update_window, text="Full Name").pack(pady=5)
        name_entry = tk.Entry(update_window)
        name_entry.insert(0, self.user['full_name'])
        name_entry.pack(pady=5)

        tk.Label(update_window, text="Date of Birth (DD/MM/YYYY)").pack(pady=5)
        dob_entry = tk.Entry(update_window)
        dob_entry.insert(0, self.user['dob'])
        dob_entry.pack(pady=5)
        dob_error = tk.Label(update_window, text="", fg="red")
        dob_error.pack()

        tk.Label(update_window, text="Phone Number").pack(pady=5)
        phone_entry = tk.Entry(update_window)
        phone_entry.insert(0, self.user['phone'])
        phone_entry.pack(pady=5)
        phone_error = tk.Label(update_window, text="", fg="red")
        phone_error.pack()

        tk.Label(update_window, text="Address").pack(pady=5)
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
                messagebox.showerror("Error", "All fields are required")
                return

            if not self.validate_dob(new_dob):
                dob_error.config(text="Invalid date or format (use DD/MM/YYYY)")
                return

            if not self.validate_phone(new_phone):
                phone_error.config(text="Invalid phone number format")
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
                log_action(self.email, "update_info", "success")
                messagebox.showinfo("Success", "Information updated successfully")
                update_window.destroy()
                self.root.destroy()
                new_dashboard = tk.Toplevel(self.main_window.root)
                DashboardWindow(new_dashboard, self.main_window, self.email)
            except Exception as e:
                log_action(self.email, "update_info", f"failed: {str(e)}")
                messagebox.showerror("Error", f"Failed to update information: {str(e)}")

        button_frame = tk.Frame(update_window)
        button_frame.pack(pady=10)
        tk.Button(button_frame, text="Save", command=save_changes).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Cancel", command=update_window.destroy).pack(side=tk.LEFT, padx=5)

        update_window.update_idletasks()
        req_width = update_window.winfo_reqwidth() + 40
        req_height = update_window.winfo_reqheight() + 40
        x = (update_window.winfo_screenwidth() - req_width) // 2
        y = (update_window.winfo_screenheight() - req_height) // 2
        update_window.geometry(f"{req_width}x{req_height}+{x}+{y}")

    def create_new_keys(self, callback=None):
        passphrase_window = tk.Toplevel(self.root)
        passphrase_window.title("Enter Passphrase")
        passphrase_window.transient(self.root)
        passphrase_window.grab_set()

        tk.Label(passphrase_window, text="Enter your passphrase").pack(pady=5)
        passphrase_entry = tk.Entry(passphrase_window, show="*")
        passphrase_entry.pack(pady=5)

        tk.Label(passphrase_window, text="Enter recovery code (optional for recovery)").pack(pady=5)
        recovery_entry = tk.Entry(passphrase_window, show="*")
        recovery_entry.pack(pady=5)

        error_label = tk.Label(passphrase_window, text="", fg="red")
        error_label.pack()

        def submit_passphrase():
            passphrase = passphrase_entry.get().strip()
            recovery_code = recovery_entry.get().strip() or None
            if not passphrase:
                error_label.config(text="Passphrase is required")
                return

            valid, error = validate_passphrase(passphrase)
            if not valid:
                error_label.config(text=error)
                return

            success, message = verify_passphrase(self.email, passphrase)
            if not success:
                error_label.config(text="Invalid Passphrase")
                log_action(self.email, "create_rsa_keys", f"failed: {message}")
                return

            if recovery_code:
                try:
                    with open(Path("./data/users.json"), "r") as f:
                        users = json.load(f)
                    user = next((u for u in users if u["email"] == self.email), None)
                    if not user:
                        error_label.config(text="User not found")
                        return
                    recovery_code_hash = base64.b64decode(user["recovery_code_hash"])
                    recovery_salt = base64.b64decode(user["recovery_code_salt"])
                    input_hash = derive_key(recovery_code, recovery_salt)
                    if recovery_code_hash != input_hash:
                        error_label.config(text="Invalid recovery code")
                        log_action(self.email, "create_rsa_keys", "failed: Invalid recovery code")
                        return
                except Exception as e:
                    error_label.config(text=f"Lỗi: {str(e)}")
                    log_action(self.email, "create_rsa_keys", f"failed: {str(e)}")
                    return

            try:
                key_data = generate_rsa_keypair(self.email, passphrase, recovery_code, mode="renew")
                update_public_key_store(self.email)
                log_action(self.email, "create_rsa_keys", "success")
                messagebox.showinfo("Success", "New RSA keys created successfully")
                passphrase_window.destroy()
                if callback:
                    callback()
            except Exception as e:
                log_action(self.email, "create_rsa_keys", f"failed: {str(e)}")
                error_label.config(text=f"Error: {str(e)}")

        button_frame = tk.Frame(passphrase_window)
        button_frame.pack(pady=10)
        tk.Button(button_frame, text="Submit", command=submit_passphrase).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Cancel", command=passphrase_window.destroy).pack(side=tk.LEFT, padx=5)

        passphrase_window.update_idletasks()
        req_width = passphrase_window.winfo_reqwidth() + 40
        req_height = passphrase_window.winfo_reqheight() + 40
        x = (passphrase_window.winfo_screenwidth() - req_width) // 2
        y = (passphrase_window.winfo_screenheight() - req_height) // 2
        passphrase_window.geometry(f"{req_width}x{req_height}+{x}+{y}")

    def extend_keys(self, callback=None):
        passphrase_window = tk.Toplevel(self.root)
        passphrase_window.title("Enter Passphrase")
        passphrase_window.transient(self.root)
        passphrase_window.grab_set()

        tk.Label(passphrase_window, text="Enter your passphrase").pack(pady=5)
        passphrase_entry = tk.Entry(passphrase_window, show="*")
        passphrase_entry.pack(pady=5)

        tk.Label(passphrase_window, text="Enter recovery code (optional for recovery)").pack(pady=5)
        recovery_entry = tk.Entry(passphrase_window, show="*")
        recovery_entry.pack(pady=5)

        error_label = tk.Label(passphrase_window, text="", fg="red")
        error_label.pack()

        def submit_passphrase():
            passphrase = passphrase_entry.get().strip()
            recovery_code = recovery_entry.get().strip() or None
            if not passphrase:
                error_label.config(text="Passphrase is required")
                return

            valid, error = validate_passphrase(passphrase)
            if not valid:
                error_label.config(text=error)
                return

            success, message = verify_passphrase(self.email, passphrase)
            if not success:
                error_label.config(text="Passphrase is invalid")
                log_action(self.email, "extend_rsa_keys", f"failed: {message}")
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
                        error_label.config(text="Recovery code không hợp lệ")
                        log_action(self.email, "extend_rsa_keys", "failed: Invalid recovery code")
                        return
                except Exception as e:
                    error_label.config(text=f"Lỗi: {str(e)}")
                    log_action(self.email, "extend_rsa_keys", f"failed: {str(e)}")
                    return

            try:
                key_data = generate_rsa_keypair(self.email, passphrase, recovery_code, mode="extend")
                update_public_key_store(self.email)
                log_action(self.email, "extend_rsa_keys", "success")
                messagebox.showinfo("Success", "RSA key expiration extended successfully")
                passphrase_window.destroy()
                if callback:
                    callback()
            except Exception as e:
                log_action(self.email, "extend_rsa_keys", f"failed: {str(e)}")
                error_label.config(text=f"Error: {str(e)}")

        button_frame = tk.Frame(passphrase_window)
        button_frame.pack(pady=10)
        tk.Button(button_frame, text="Submit", command=submit_passphrase).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Cancel", command=passphrase_window.destroy).pack(side=tk.LEFT, padx=5)

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
            qr_window.title("Public Key QR Code")
            qr_window.transient(self.root)
            qr_window.grab_set()

            img = Image.open(qr_path)
            img = img.resize((200, 200), Image.Resampling.LANCZOS)
            qr_image = ImageTk.PhotoImage(img)
            tk.Label(qr_window, image=qr_image).pack(pady=10)
            tk.Label(qr_window, text=message).pack(pady=5)
            tk.Button(qr_window, text="Close", command=qr_window.destroy).pack(pady=10)
            qr_window.qr_image = qr_image

            qr_window.update_idletasks()
            req_width = max(qr_window.winfo_reqwidth() + 40, 300)
            req_height = max(qr_window.winfo_reqheight() + 40, 300)
            x = (qr_window.winfo_screenwidth() - req_width) // 2
            y = (qr_window.winfo_screenheight() - req_height) // 2
            qr_window.geometry(f"{req_width}x{req_height}+{x}+{y}")

        except ValueError as e:
            messagebox.showerror("Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate QR code: {str(e)}")
            log_action(self.email, "generate_qr_code", f"failed: {str(e)}")

    def read_qr_code(self):
        file_path = filedialog.askopenfilename(filetypes=[("PNG Images", "*.png"), ("All Files", "*.*")])
        if not file_path:
            return

        try:
            qr_data, status_msg = read_qr(self.email, file_path)
            qr_info_window = tk.Toplevel(self.root)
            qr_info_window.title("QR Code Information")
            qr_info_window.transient(self.root)
            qr_info_window.grab_set()

            tk.Label(qr_info_window, text=f"Email: {qr_data['email']}", anchor="w").pack(fill="x", pady=5)
            tk.Label(qr_info_window, text=f"Created: {datetime.fromisoformat(qr_data['created']).strftime('%Y-%m-%d')}", anchor="w").pack(fill="x", pady=5)
            tk.Label(qr_info_window, text=f"Expires: {datetime.fromisoformat(qr_data['expires']).strftime('%Y-%m-%d')}", anchor="w").pack(fill="x", pady=5)
            tk.Label(qr_info_window, text=f"Public Key: {qr_data['public_key']}", anchor="w").pack(fill="x", pady=5)
            tk.Label(qr_info_window, text=f"Storage: {status_msg}", anchor="w").pack(fill="x", pady=5)
            tk.Button(qr_info_window, text="Close", command=qr_info_window.destroy).pack(pady=10)

            qr_info_window.update_idletasks()
            req_width = max(qr_info_window.winfo_reqwidth() + 40, 400)
            req_height = max(qr_info_window.winfo_reqheight() + 40, 300)
            x = (qr_info_window.winfo_screenwidth() - req_width) // 2
            y = (qr_info_window.winfo_screenheight() - req_height) // 2
            qr_info_window.geometry(f"{req_width}x{req_height}+{x}+{y}")

        except ValueError as e:
            messagebox.showerror("Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read QR code: {str(e)}")

    def search_public_key_ui(self):
        search_window = tk.Toplevel(self.root)
        search_window.title("Tìm kiếm Public Key")
        search_window.transient(self.root)
        search_window.grab_set()

        tk.Label(search_window, text="Nhập Email để tìm kiếm").pack(pady=5)
        search_entry = tk.Entry(search_window)
        search_entry.pack(pady=5)
        error_label = tk.Label(search_window, text="", fg="red")
        error_label.pack()

        def perform_search():
            search_email = search_entry.get().strip()
            if not search_email:
                error_label.config(text="Email là bắt buộc")
                return

            try:
                result, message, similar_emails = search_public_key(self.email, search_email)
                log_action(self.email, "search_public_key_ui", f"result: {result}")

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
                result_window.configure(padx=20, pady=20)

                # Frame for key details
                key_frame = tk.Frame(result_window)
                key_frame.pack(fill="both", pady=10)

                # Error label for invalid data
                error_label_result = tk.Label(key_frame, text="", fg="red")
                error_label_result.pack(anchor="w", pady=5)

                # Entry widgets for key details
                tk.Label(key_frame, text="Email:").pack(anchor="w")
                email_entry = tk.Entry(key_frame, width=50)
                email_entry.insert(0, search_email)
                email_entry.config(state="readonly")
                email_entry.pack(fill="x", pady=2)
                log_action(self.email, "search_public_key_ui", f"email_entry: {search_email}")

                tk.Label(key_frame, text="Khóa công khai (Rút gọn):").pack(anchor="w")
                public_key_entry = tk.Entry(key_frame, width=50)
                truncated_key = result["public_key"][:20] + "..." if len(result["public_key"]) > 20 else result[
                    "public_key"]
                public_key_entry.insert(0, truncated_key)
                public_key_entry.config(state="readonly")
                public_key_entry.pack(fill="x", pady=2)
                log_action(self.email, "search_public_key_ui", f"public_key_entry: {truncated_key}")

                tk.Label(key_frame, text="Ngày tạo:").pack(anchor="w")
                created_entry = tk.Entry(key_frame, width=50)
                created = datetime.fromisoformat(result["created"]).strftime("%Y-%m-%d %H:%M:%S")
                created_entry.insert(0, created)
                created_entry.config(state="readonly")
                created_entry.pack(fill="x", pady=2)
                log_action(self.email, "search_public_key_ui", f"created_entry: {created}")

                tk.Label(key_frame, text="Ngày hết hạn:").pack(anchor="w")
                expires_entry = tk.Entry(key_frame, width=50)
                expires = datetime.fromisoformat(result["expires"]).strftime("%Y-%m-%d %H:%M:%S")
                expires_entry.insert(0, expires)
                expires_entry.config(state="readonly")
                expires_entry.pack(fill="x", pady=2)
                log_action(self.email, "search_public_key_ui", f"expires_entry: {expires}")

                tk.Label(key_frame, text="Trạng thái:").pack(anchor="w")
                status_entry = tk.Entry(key_frame, width=50)
                status = result["status"]
                status_entry.insert(0, status)
                status_entry.config(state="readonly")
                status_entry.pack(fill="x", pady=2)
                log_action(self.email, "search_public_key_ui", f"status_entry: {status}")

                tk.Label(key_frame, text="Số ngày còn lại:").pack(anchor="w")
                valid_days_entry = tk.Entry(key_frame, width=50)
                now = datetime.now(ZoneInfo("Asia/Ho_Chi_Minh"))
                expires_dt = datetime.fromisoformat(result["expires"])
                valid_days = (expires_dt - now).days
                valid_days_left = str(valid_days) if result["status"] != "revoked" else "Revoked"
                valid_days_entry.insert(0, valid_days_left)
                valid_days_entry.config(state="readonly")
                valid_days_entry.pack(fill="x", pady=2)
                log_action(self.email, "search_public_key_ui", f"valid_days_entry: {valid_days_left}")

                # Force UI update
                key_frame.update()

                # Validate required fields
                required_fields = ["public_key", "created", "expires", "status"]
                if not all(field in result for field in required_fields):
                    error_label_result.config(text="Dữ liệu khóa không đầy đủ.")
                    log_action(self.email, "search_public_key_ui", f"failed: Missing required fields {result}")
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
                    log_action(self.email, "search_public_key_ui", f"qr_code loaded: {qr_path}")
                except FileNotFoundError:
                    log_action(self.email, "search_public_key_ui", f"qr_code not found: {qr_path}")

                # Close button
                button_frame = tk.Frame(result_window)
                button_frame.pack(pady=10)
                tk.Button(button_frame, text="Đóng", command=result_window.destroy).pack(side=tk.LEFT, padx=5)

                # Adjust window size
                result_window.update_idletasks()
                req_width = max(key_frame.winfo_reqwidth() + 60, 600)
                req_height = max(key_frame.winfo_reqheight() + 100, 500)
                x = (result_window.winfo_screenwidth() - req_width) // 2
                y = (result_window.winfo_screenheight() - req_height) // 2
                result_window.geometry(f"{req_width}x{req_height}+{x}+{y}")
                result_window.minsize(600, 500)

            except Exception as e:
                log_action(self.email, "search_public_key_ui", f"failed: {str(e)}")
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
        encrypt_window.title("Encrypt File")
        encrypt_window.transient(self.root)
        encrypt_window.grab_set()

        tk.Label(encrypt_window, text="Select File to Encrypt").pack(pady=5)
        file_entry = tk.Entry(encrypt_window, width=50)
        file_entry.pack(pady=5)
        tk.Button(encrypt_window, text="Browse", command=lambda: file_entry.insert(0, filedialog.askopenfilename())).pack(pady=5)

        tk.Label(encrypt_window, text="Recipient Email").pack(pady=5)
        email_entry = tk.Entry(encrypt_window)
        email_entry.pack(pady=5)

        tk.Label(encrypt_window, text="Save Format").pack(pady=5)
        split_key_var = tk.BooleanVar(value=False)
        tk.Radiobutton(encrypt_window, text="Single .enc file", variable=split_key_var, value=False).pack()
        tk.Radiobutton(encrypt_window, text="Separate .enc and .key files", variable=split_key_var, value=True).pack()

        error_label = tk.Label(encrypt_window, text="", fg="red")
        error_label.pack()

        def perform_encryption():
            input_path = file_entry.get().strip()
            recipient_email = email_entry.get().strip()
            split_key = split_key_var.get()

            if not input_path or not recipient_email:
                error_label.config(text="File and recipient email are required")
                return

            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, recipient_email):
                error_label.config(text="Invalid recipient email format")
                return

            try:
                enc_path, key_path = encrypt_file_with_metadata(input_path, recipient_email, self.email, split_key)
                message = f"File encrypted successfully: {enc_path}"
                if key_path:
                    message += f"\nKey file: {key_path}"
                messagebox.showinfo("Success", message)
                encrypt_window.destroy()
            except ValueError as e:
                error_label.config(text=str(e))
            except Exception as e:
                error_label.config(text=f"Encryption failed: {str(e)}")

        button_frame = tk.Frame(encrypt_window)
        button_frame.pack(pady=10)
        tk.Button(button_frame, text="Encrypt", command=perform_encryption).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Cancel", command=encrypt_window.destroy).pack(side=tk.LEFT, padx=5)

        encrypt_window.update_idletasks()
        req_width = max(encrypt_window.winfo_reqwidth() + 40, 400)
        req_height = max(encrypt_window.winfo_reqheight() + 40, 300)
        x = (encrypt_window.winfo_screenwidth() - req_width) // 2
        y = (encrypt_window.winfo_screenheight() - req_height) // 2
        encrypt_window.geometry(f"{req_width}x{req_height}+{x}+{y}")

    def decrypt_file(self):
        decrypt_window = tk.Toplevel(self.root)
        decrypt_window.title("Decrypt File")
        decrypt_window.transient(self.root)
        decrypt_window.grab_set()

        safe_email = self.email.replace("@", "_at_").replace(".", "_dot_")
        storage_dir = Path(f"data/{safe_email}/storage")

        tk.Label(decrypt_window, text="Select Encrypted File (.enc)").pack(pady=5)
        file_entry = tk.Entry(decrypt_window, width=50)
        file_entry.pack(pady=5)
        tk.Button(decrypt_window, text="Browse", command=lambda: file_entry.insert(0, filedialog.askopenfilename(
            initialdir=storage_dir, filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")]
        ))).pack(pady=5)

        tk.Label(decrypt_window, text="Enter Passphrase").pack(pady=5)
        passphrase_entry = tk.Entry(decrypt_window, show="*")
        passphrase_entry.pack(pady=5)

        error_label = tk.Label(decrypt_window, text="", fg="red")
        error_label.pack()

        def perform_decryption():
            enc_path = file_entry.get().strip()
            passphrase = passphrase_entry.get().strip()

            if not enc_path:
                error_label.config(text="Encrypted file is required")
                return

            if not passphrase:
                error_label.config(text="Passphrase is required")
                return

            valid, error = validate_passphrase(passphrase)
            if not valid:
                error_label.config(text=error)
                return

            success, message = verify_passphrase(self.email, passphrase)
            if not success:
                error_label.config(text="Invalid Passphrase")
                log_action(self.email, "decrypt_file", f"failed: {message}")
                return

            try:
                output_path, metadata = decrypt_file(enc_path, passphrase, self.email)
                result_window = tk.Toplevel(self.root)
                result_window.title("Decryption Result")
                result_window.transient(self.root)
                result_window.grab_set()

                tk.Label(result_window, text=f"Decrypted File: {output_path}", anchor="w").pack(fill="x", pady=5)
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

                messagebox.showinfo("Success", f"File decrypted successfully: {output_path}")
                decrypt_window.destroy()
            except ValueError as e:
                error_label.config(text=str(e))
            except Exception as e:
                error_label.config(text=f"Decryption failed: {str(e)}")

        button_frame = tk.Frame(decrypt_window)
        button_frame.pack(pady=10)
        tk.Button(button_frame, text="Decrypt", command=perform_decryption).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Cancel", command=decrypt_window.destroy).pack(side=tk.LEFT, padx=5)

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
        sign_window.configure(padx=10, pady=10)

        tk.Label(sign_window, text="Chọn file để ký").pack(pady=5)
        file_entry = tk.Entry(sign_window, width=50)
        file_entry.pack(pady=5)
        tk.Button(sign_window, text="Browse", command=lambda: file_entry.insert(tk.END, filedialog.askopenfilename())).pack(pady=5)

        tk.Label(sign_window, text="Nhập Passphrase của bạn").pack(pady=5)
        passphrase_entry = tk.Entry(sign_window, show="*")
        passphrase_entry.pack(pady=5)

        def perform_sign():
            file_path = file_entry.get().strip()
            passphrase = passphrase_entry.get().strip()

            if not file_path or not passphrase:
                messagebox.showerror("Lỗi", "Vui lòng chọn file và nhập passphrase.", parent=sign_window)
                return

            try:
                success, message, sig_path = sign_file(file_path, self.email, passphrase)
                if success:
                    messagebox.showinfo("Thành công", message, parent=sign_window)
                    sign_window.destroy()
                else:
                    messagebox.showerror("Lỗi", message, parent=sign_window)
            except Exception as e:
                messagebox.showerror("Lỗi", f"Đã xảy ra lỗi không mong muốn: {str(e)}", parent=sign_window)
                log_action(self.email, "sign_file_gui", f"failed: {str(e)}")

        button_frame = tk.Frame(sign_window)
        button_frame.pack(pady=10)
        tk.Button(button_frame, text="Ký", command=perform_sign).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Hủy", command=sign_window.destroy).pack(side=tk.LEFT, padx=5)

        sign_window.update_idletasks()
        x = (sign_window.winfo_screenwidth() - sign_window.winfo_width()) // 2
        y = (sign_window.winfo_screenheight() - sign_window.winfo_height()) // 2
        sign_window.geometry(f"+{x}+{y}")

    def verify_signature(self):
        verify_window = tk.Toplevel(self.root)
        verify_window.title("Xác Thực Chữ Ký")
        verify_window.transient(self.root)
        verify_window.grab_set()
        verify_window.configure(padx=10, pady=10)

        tk.Label(verify_window, text="Chọn file gốc").pack(pady=5)
        file_entry = tk.Entry(verify_window, width=50)
        file_entry.pack(pady=5)
        tk.Button(verify_window, text="Browse", command=lambda: file_entry.insert(tk.END, filedialog.askopenfilename())).pack(pady=5)

        tk.Label(verify_window, text="Chọn file chữ ký (.sig)").pack(pady=5)
        sig_entry = tk.Entry(verify_window, width=50)
        sig_entry.pack(pady=5)
        tk.Button(verify_window, text="Browse", command=lambda: sig_entry.insert(tk.END, filedialog.askopenfilename(
            filetypes=[("Signature Files", "*.sig"), ("All Files", "*.*")]
        ))).pack(pady=5)

        def perform_verify():
            file_path = file_entry.get().strip()
            sig_path = sig_entry.get().strip()

            if not file_path or not sig_path:
                messagebox.showerror("Lỗi", "Vui lòng chọn cả file gốc và file chữ ký.", parent=verify_window)
                return

            try:
                # Pass current user's email for logging purposes
                result = verify_signature(file_path, sig_path, self.email)

                if result.get("valid"):
                    message = (f"Xác thực thành công!\n\n"
                               f"Người ký: {result.get('signer_email', 'N/A')}\n"
                               f"Thời gian ký: {datetime.fromisoformat(result['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}")
                    messagebox.showinfo("Thành công", message, parent=verify_window)
                else:
                    error_message = result.get("message", "Lỗi không xác định.")
                    messagebox.showerror("Thất bại", f"Xác thực chữ ký thất bại.\nLý do: {error_message}", parent=verify_window)
                verify_window.destroy()
            except Exception as e:
                messagebox.showerror("Lỗi", f"Đã xảy ra lỗi trong quá trình xác thực: {str(e)}", parent=verify_window)
                log_action(self.email, "verify_signature_gui", f"failed: {str(e)}")

        button_frame = tk.Frame(verify_window)
        button_frame.pack(pady=10)
        tk.Button(button_frame, text="Xác thực", command=perform_verify).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Hủy", command=verify_window.destroy).pack(side=tk.LEFT, padx=5)

        verify_window.update_idletasks()
        x = (verify_window.winfo_screenwidth() - verify_window.winfo_width()) // 2
        y = (verify_window.winfo_screenheight() - verify_window.winfo_height()) // 2
        verify_window.geometry(f"+{x}+{y}")

    def logout(self):
        log_action(self.email, "logout", "success")
        self.main_window.enable_buttons()
        self.root.destroy()