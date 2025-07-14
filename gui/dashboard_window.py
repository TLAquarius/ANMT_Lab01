import tkinter as tk
from tkinter import messagebox, ttk, filedialog
from datetime import datetime
import re
import json
from pathlib import Path
from zoneinfo import ZoneInfo
from PIL import Image, ImageTk
from modules.rsa_keys import generate_rsa_keypair, update_key_status, update_public_key_store
from modules.qr_utils import generate_qr_for_public_key, read_qr
from modules.logger import log_action
from modules.pubkey_search import search_public_key
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
        self.min_height = 600

        self.root.configure(padx=20, pady=20)

        tk.Label(root, text=f"Name: {user['full_name']}", anchor="w").pack(fill="x", pady=2)
        tk.Label(root, text=f"Email: {user['email']}", anchor="w").pack(fill="x", pady=2)
        tk.Label(root, text=f"Phone: {user['phone']}", anchor="w").pack(fill="x", pady=2)
        tk.Label(root, text=f"Date of Birth: {user['dob']}", anchor="w").pack(fill="x", pady=2)
        tk.Label(root, text=f"Address: {user['address']}", anchor="w").pack(fill="x", pady=2)

        tk.Frame(root, height=2, bd=1, relief="sunken").pack(fill="x", pady=10)

        tk.Button(root, text="Update Information", command=self.open_update_info).pack(pady=10)
        tk.Button(root, text="Create New RSA Keys", command=self.create_new_keys).pack(pady=10)
        tk.Button(root, text="Extend RSA Key Expiration", command=self.extend_keys).pack(pady=10)
        tk.Button(root, text="View Keys", command=self.view_keys).pack(pady=10)
        tk.Button(root, text="Generate Public Key QR Code", command=self.generate_qr_code).pack(pady=10)
        tk.Button(root, text="Read Public Key QR Code", command=self.read_qr_code).pack(pady=10)
        tk.Button(root, text="Search Public Key", command=self.search_public_key).pack(pady=10)
        tk.Button(root, text="Logout", command=self.logout).pack(pady=10)

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
                messagebox.showinfo("Success", "Information updated successfully")
                update_window.destroy()
                self.root.destroy()
                new_dashboard = tk.Toplevel(self.main_window.root)
                DashboardWindow(new_dashboard, self.main_window, self.user)
            except Exception as e:
                log_action(self.user["email"], "update_info", f"failed: {str(e)}")
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

    def create_new_keys(self):
        passphrase_window = tk.Toplevel(self.root)
        passphrase_window.title("Enter Passphrase")
        passphrase_window.transient(self.root)
        passphrase_window.grab_set()

        tk.Label(passphrase_window, text="Enter your passphrase").pack(pady=5)
        passphrase_entry = tk.Entry(passphrase_window, show="*")
        passphrase_entry.pack(pady=5)
        error_label = tk.Label(passphrase_window, text="", fg="red")
        error_label.pack()

        def submit_passphrase():
            passphrase = passphrase_entry.get()
            if not passphrase:
                error_label.config(text="Passphrase is required")
                return
            try:
                safe_email = self.user["email"].replace("@", "_at_").replace(".", "_dot_")
                key_data = generate_rsa_keypair(safe_email, passphrase, mode="renew")
                update_public_key_store(safe_email)
                log_action(self.user["email"], "create_rsa_keys", "success")
                messagebox.showinfo("Success", "New RSA keys created successfully")
                passphrase_window.destroy()
            except Exception as e:
                log_action(self.user["email"], "create_rsa_keys", f"failed: {str(e)}")
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

    def extend_keys(self):
        passphrase_window = tk.Toplevel(self.root)
        passphrase_window.title("Enter Passphrase")
        passphrase_window.transient(self.root)
        passphrase_window.grab_set()

        tk.Label(passphrase_window, text="Enter your passphrase").pack(pady=5)
        passphrase_entry = tk.Entry(passphrase_window, show="*")
        passphrase_entry.pack(pady=5)
        error_label = tk.Label(passphrase_window, text="", fg="red")
        error_label.pack()

        def submit_passphrase():
            passphrase = passphrase_entry.get()
            if not passphrase:
                error_label.config(text="Passphrase is required")
                return
            try:
                safe_email = self.user["email"].replace("@", "_at_").replace(".", "_dot_")
                key_data = generate_rsa_keypair(safe_email, passphrase, mode="extend")
                update_public_key_store(safe_email)
                log_action(self.user["email"], "extend_rsa_keys", "success")
                messagebox.showinfo("Success", "RSA key expiration extended successfully")
                passphrase_window.destroy()
            except Exception as e:
                log_action(self.user["email"], "extend_rsa_keys", f"failed: {str(e)}")
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
        safe_email = self.user["email"].replace("@", "_at_").replace(".", "_dot_")
        current_key_path = Path(f"./data/{safe_email}/rsa_keypair.json")
        now = datetime.now(ZoneInfo("Asia/Ho_Chi_Minh"))
        try:
            with open(current_key_path, "r") as f:
                key_data = json.load(f)
                key_data = update_key_status(key_data, now)
                with open(current_key_path, "w") as f:
                    json.dump(key_data, f, indent=4)
            update_public_key_store(safe_email)
            log_action(self.user["email"], "view_keys", "success: Updated key status")
        except (FileNotFoundError, json.JSONDecodeError) as e:
            log_action(self.user["email"], "view_keys", f"failed: {str(e)}")
        key_window = tk.Toplevel(self.root)
        KeyStorageWindow(key_window, self, safe_email)

    def generate_qr_code(self):
        """Generate and display a QR code for the user's public key."""
        safe_email = self.user["email"].replace("@", "_at_").replace(".", "_dot_")
        try:
            qr_path, message = generate_qr_for_public_key(self.user["email"], safe_email)
            # Display QR code
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
            qr_window.qr_image = qr_image  # Keep reference to avoid garbage collection

            # Adjust window size
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
            log_action(self.user["email"], "generate_qr_code", f"failed: {str(e)}")

    def read_qr_code(self):
        """Read a QR code and display its information."""
        file_path = filedialog.askopenfilename(filetypes=[("PNG Images", "*.png"), ("All Files", "*.*")])
        if not file_path:
            return

        try:
            qr_data, status_msg = read_qr(self.user["email"], file_path)
            # Display QR code information
            qr_info_window = tk.Toplevel(self.root)
            qr_info_window.title("QR Code Information")
            qr_info_window.transient(self.root)
            qr_info_window.grab_set()

            tk.Label(qr_info_window, text=f"Email: {qr_data['email']}", anchor="w").pack(fill="x", pady=5)
            tk.Label(qr_info_window, text=f"Created: {datetime.fromisoformat(qr_data['created']).strftime('%Y-%m-%d')}", anchor="w").pack(fill="x", pady=5)
            tk.Label(qr_info_window, text=f"Expires: {datetime.fromisoformat(qr_data['expires']).strftime('%Y-%m-%d')}", anchor="w").pack(fill="x", pady=5)
            tk.Label(qr_info_window, text=f"Status: {qr_data['status']}", anchor="w").pack(fill="x", pady=5)
            tk.Label(qr_info_window, text=f"Public Key: {qr_data['public_key'][:20]}...", anchor="w").pack(fill="x", pady=5)
            tk.Label(qr_info_window, text=f"Storage: {status_msg}", anchor="w").pack(fill="x", pady=5)
            tk.Button(qr_info_window, text="Close", command=qr_info_window.destroy).pack(pady=10)

            # Adjust window size
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

    def search_public_key(self):
        """Search for another user's public key by email and display its information."""
        search_window = tk.Toplevel(self.root)
        search_window.title("Search Public Key")
        search_window.transient(self.root)
        search_window.grab_set()

        tk.Label(search_window, text="Enter Email to Search").pack(pady=5)
        email_entry = tk.Entry(search_window)
        email_entry.pack(pady=5)
        error_label = tk.Label(search_window, text="", fg="red")
        error_label.pack()

        def perform_search():
            search_email = email_entry.get().strip()
            if not search_email:
                error_label.config(text="Email is required")
                return

            try:
                result, message, similar_emails = search_public_key(self.user["email"], search_email)

                if result is None:
                    if similar_emails:
                        similar_emails_str = "\n".join(similar_emails)
                        messagebox.showinfo("Not Found", f"{message}\nSimilar emails:\n{similar_emails_str}")
                    else:
                        messagebox.showinfo("Not Found", message)
                    return

                # Display key information
                result_window = tk.Toplevel(self.root)
                result_window.title(f"Public Key - {search_email}")
                result_window.transient(self.root)
                result_window.grab_set()

                tk.Label(result_window, text=f"Email: {search_email}", anchor="w").pack(fill="x", pady=5)
                tk.Label(result_window, text=f"Created: {datetime.fromisoformat(result['created']).strftime('%Y-%m-%d %H:%M:%S')}", anchor="w").pack(fill="x", pady=5)
                tk.Label(result_window, text=f"Expires: {datetime.fromisoformat(result['expires']).strftime('%Y-%m-%d %H:%M:%S')}", anchor="w").pack(fill="x", pady=5)
                tk.Label(result_window, text=f"Status: {result['status']}", anchor="w").pack(fill="x", pady=5)
                tk.Label(result_window, text=f"Public Key: {result['public_key']}", anchor="w").pack(fill="x", pady=5)
                tk.Button(result_window, text="Close", command=result_window.destroy).pack(pady=10)

                # Adjust window size
                result_window.update_idletasks()
                req_width = max(result_window.winfo_reqwidth() + 40, 400)
                req_height = max(result_window.winfo_reqheight() + 40, 300)
                x = (result_window.winfo_screenwidth() - req_width) // 2
                y = (result_window.winfo_screenheight() - req_height) // 2
                result_window.geometry(f"{req_width}x{req_height}+{x}+{y}")

            except Exception as e:
                messagebox.showerror("Error", f"Failed to search public key: {str(e)}")

        button_frame = tk.Frame(search_window)
        button_frame.pack(pady=10)
        tk.Button(button_frame, text="Search", command=perform_search).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Cancel", command=search_window.destroy).pack(side=tk.LEFT, padx=5)

        search_window.update_idletasks()
        req_width = search_window.winfo_reqwidth() + 40
        req_height = search_window.winfo_reqheight() + 40
        x = (search_window.winfo_screenwidth() - req_width) // 2
        y = (search_window.winfo_screenheight() - req_height) // 2
        search_window.geometry(f"{req_width}x{req_height}+{x}+{y}")

    def logout(self):
        self.main_window.enable_buttons()
        self.root.destroy()