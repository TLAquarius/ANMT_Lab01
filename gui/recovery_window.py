import tkinter as tk
from tkinter import messagebox
from modules.auth import reset_passphrase, validate_passphrase

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

        tk.Label(root, text="Mã khôi phục").pack(pady=5)
        self.recovery_code_entry = tk.Entry(root)
        self.recovery_code_entry.pack(pady=5)

        tk.Label(root, text="Passphrase mới").pack(pady=5)
        self.passphrase_entry = tk.Entry(root, show="*")
        self.passphrase_entry.pack(pady=5)

        # Submit button
        tk.Button(root, text="Reset Passphrase", command=self.submit).pack(pady=20)

    def submit(self):
        email = self.email_entry.get()
        recovery_code = self.recovery_code_entry.get()
        new_passphrase = self.passphrase_entry.get()

        if not all([email, recovery_code, new_passphrase]):
            messagebox.showerror("Error", "Vui lòng điền đầy đủ thông tin")
            return

        # Validate new passphrase
        valid, error = validate_passphrase(new_passphrase)
        if not valid:
            messagebox.showerror("Error", error)
            return

        success, message = reset_passphrase(email, recovery_code, new_passphrase)
        if success:
            messagebox.showinfo("Success", message)
            self.root.destroy()
        else:
            messagebox.showerror("Error", message)