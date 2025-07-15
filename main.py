import tkinter as tk
from tkinter import ttk
from gui.register_window import SignupWindow
from gui.login_window import LoginWindow
from gui.recovery_window import RecoveryWindow
from gui.admin_panel import AdminWindow

class MainWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Demo Đồ Án 1 (22127124-22127392-22127485)")
        self.min_width = 340
        self.min_height = 320
        self.root.configure(bg="#F5F7FA")
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TButton",
                        background="#1976D2",
                        foreground="white",
                        font="SegoeUI 12 bold",
                        borderwidth=0,
                        focusthickness=3,
                        focuscolor="#2196F3",
                        padding=10)
        style.map("TButton",
                  background=[('active', '#2196F3'), ('pressed', '#1565C0')])
        style.configure("TLabel",
                        background="#F5F7FA",
                        foreground="#222",
                        font="SegoeUI 14 bold")

        main_frame = tk.Frame(root, bg="#FFFFFF", bd=0, highlightthickness=0)
        main_frame.pack(padx=20, pady=20, fill="both", expand=True)
        main_frame.configure(bg="#FFFFFF")
        main_frame.pack_propagate(False)

        title_label = ttk.Label(main_frame, text="CHỌN CHỨC NĂNG", style="TLabel")
        title_label.pack(pady=(10, 20))

        self.signup_button = ttk.Button(main_frame, text="Đăng ký", command=self.open_signup, style="TButton")
        self.signup_button.pack(pady=10, fill="x")
        self.login_button = ttk.Button(main_frame, text="Đăng nhập", command=self.open_login, style="TButton")
        self.login_button.pack(pady=10, fill="x")
        self.reset_button = ttk.Button(main_frame, text="Khôi phục tài khoản", command=self.open_reset, style="TButton")
        self.reset_button.pack(pady=10, fill="x")

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

    def disable_buttons(self):
        self.signup_button.state(["disabled"])
        self.login_button.state(["disabled"])

    def enable_buttons(self):
        self.signup_button.state(["!disabled"])
        self.login_button.state(["!disabled"])

    def open_signup(self):
        signup_window = tk.Toplevel(self.root)
        SignupWindow(signup_window, self)

    def open_login(self):
        login_window = tk.Toplevel(self.root)
        LoginWindow(login_window, self)

    def open_reset(self):
        reset_window = tk.Toplevel(self.root)
        RecoveryWindow(reset_window, self)

    def open_admin(self, admin_email):
        admin_window = tk.Toplevel(self.root)
        AdminWindow(admin_window, self, admin_email)

if __name__ == "__main__":
    root = tk.Tk()
    app = MainWindow(root)
    root.mainloop()