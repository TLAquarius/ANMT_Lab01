import tkinter as tk
from tkinter import messagebox
import re
from datetime import datetime
from modules.auth import sign_up

class SignupWindow:
    def __init__(self, root, main_window):
        self.root = root  # Toplevel window
        self.main_window = main_window  # MainWindow instance
        self.root.title("Sign Up")
        self.root.transient(main_window.root)
        self.root.grab_set()

        # Minimum window size
        self.min_width = 400
        self.min_height = 550

        # Add padding
        self.root.configure(padx=20, pady=20)

        # Labels and entries with error labels
        tk.Label(root, text="Email").pack(pady=5)
        self.email_entry = tk.Entry(root)
        self.email_entry.pack(pady=5)
        self.email_error = tk.Label(root, text="", fg="red")
        self.email_error.pack()

        tk.Label(root, text="Full Name").pack(pady=5)
        self.name_entry = tk.Entry(root)
        self.name_entry.pack(pady=5)

        tk.Label(root, text="Date of Birth (DD/MM/YYYY)").pack(pady=5)
        self.dob_entry = tk.Entry(root)
        self.dob_entry.pack(pady=5)
        self.dob_error = tk.Label(root, text="", fg="red")
        self.dob_error.pack()

        tk.Label(root, text="Phone Number").pack(pady=5)
        self.phone_entry = tk.Entry(root)
        self.phone_entry.pack(pady=5)
        self.phone_error = tk.Label(root, text="", fg="red")
        self.phone_error.pack()

        tk.Label(root, text="Address").pack(pady=5)
        self.address_entry = tk.Entry(root)
        self.address_entry.pack(pady=5)

        tk.Label(root, text="Passphrase").pack(pady=5)
        self.passphrase_entry = tk.Entry(root, show="*")
        self.passphrase_entry.pack(pady=5)
        self.passphrase_error = tk.Label(root, text="", fg="red")
        self.passphrase_error.pack()

        tk.Label(root, text="Confirm Passphrase").pack(pady=5)
        self.confirm_passphrase_entry = tk.Entry(root, show="*")
        self.confirm_passphrase_entry.pack(pady=5)
        self.confirm_passphrase_error = tk.Label(root, text="", fg="red")
        self.confirm_passphrase_error.pack()

        # Checkbox for toggling passphrase visibility
        self.show_passphrase_var = tk.BooleanVar()
        tk.Checkbutton(
            root,
            text="Show Passphrases",
            variable=self.show_passphrase_var,
            command=self.toggle_passphrase
        ).pack(pady=5)

        # Button frame for Submit and Back buttons
        button_frame = tk.Frame(root)
        button_frame.pack(pady=20)
        tk.Button(button_frame, text="Sign Up", command=self.submit).pack(side=tk.LEFT, padx=10)
        tk.Button(button_frame, text="Back", command=self.go_back).pack(side=tk.LEFT, padx=10)

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
            messagebox.showerror("Error", "Vui lòng điền đầy đủ thông tin")
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
            messagebox.showinfo("Success", f"{message}\nMã khôi phục: {recovery_code}\nVui lòng ghi nhớ mã này")
            self.go_back()
        else:
            messagebox.showerror("Error", message)

    def go_back(self):
        """Close the signup window and re-enable main window buttons."""
        self.main_window.enable_buttons()
        self.root.destroy()