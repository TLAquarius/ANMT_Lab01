import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from modules.file_sign import sign_file, get_signature_status_color, get_signature_status_icon

class FileSignGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Ký số file - ANMT Lab")
        self.geometry("480x340")
        self.configure(bg="#f5f5f5")
        self.resizable(False, False)
        self.create_styles()
        self.create_widgets()

    def create_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TLabel", font=("Segoe UI", 11), background="#f5f5f5")
        style.configure("TEntry", font=("Segoe UI", 11), padding=4)
        style.configure("TButton", font=("Segoe UI", 11, "bold"), background="#1976d2", foreground="white", padding=6)
        style.map("TButton", background=[("active", "#1565c0")])
        style.configure("Result.TLabel", font=("Segoe UI", 12, "bold"), padding=8)

    def create_widgets(self):
        frm = ttk.Frame(self, padding=20)
        frm.pack(fill=tk.BOTH, expand=True)

        # Chọn file
        self.file_path_var = tk.StringVar()
        ttk.Label(frm, text="Chọn file để ký số:").grid(row=0, column=0, sticky="w")
        file_entry = ttk.Entry(frm, textvariable=self.file_path_var, width=32)
        file_entry.grid(row=1, column=0, sticky="ew", pady=4)
        ttk.Button(frm, text="Browse", command=self.browse_file).grid(row=1, column=1, padx=6)

        # Email
        ttk.Label(frm, text="Email người ký:").grid(row=2, column=0, sticky="w", pady=(12,0))
        self.email_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.email_var, width=32).grid(row=3, column=0, columnspan=2, sticky="ew", pady=4)

        # Passphrase
        ttk.Label(frm, text="Passphrase:").grid(row=4, column=0, sticky="w", pady=(12,0))
        self.passphrase_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.passphrase_var, show="*", width=32).grid(row=5, column=0, columnspan=2, sticky="ew", pady=4)

        # Nút ký số
        ttk.Button(frm, text="Ký số file", command=self.sign_file_action).grid(row=6, column=0, columnspan=2, pady=18)

        # Kết quả
        self.result_label = ttk.Label(frm, text="", style="Result.TLabel", anchor="center")
        self.result_label.grid(row=7, column=0, columnspan=2, sticky="ew", pady=8)

        frm.columnconfigure(0, weight=1)
        frm.columnconfigure(1, weight=0)

    def browse_file(self):
        file_path = filedialog.askopenfilename(title="Chọn file để ký số")
        if file_path:
            self.file_path_var.set(file_path)

    def sign_file_action(self):
        file_path = self.file_path_var.get()
        email = self.email_var.get()
        passphrase = self.passphrase_var.get()
        if not file_path or not email or not passphrase:
            messagebox.showwarning("Thiếu thông tin", "Vui lòng nhập đầy đủ thông tin!")
            return
        success, msg, sig_path = sign_file(file_path, email, passphrase)
        status = "valid" if success else "invalid"
        color = get_signature_status_color(status)
        icon = get_signature_status_icon(status)
        self.result_label.configure(text=f"{icon} {msg}", foreground=color)
        if success:
            messagebox.showinfo("Ký số thành công", msg)
        else:
            messagebox.showerror("Ký số thất bại", msg)

if __name__ == "__main__":
    app = FileSignGUI()
    app.mainloop()
