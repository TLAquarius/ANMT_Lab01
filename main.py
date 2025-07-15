import tkinter as tk
from gui.register_window import SignupWindow
from gui.login_window import LoginWindow
from gui.recovery_window import RecoveryWindow
from gui.admin_panel import AdminWindow

class MainWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Demo Đồ Án 1 (22127124-22127392-22127485)")
        self.min_width = 300
        self.min_height = 200
        self.root.configure(padx=20, pady=20)

        tk.Label(root, text="CHỌN CHỨC NĂNG").pack(pady=10)

        self.signup_button = tk.Button(root, text="Đăng ký", command=self.open_signup)
        self.signup_button.pack(pady=10)
        self.login_button = tk.Button(root, text="Đăng nhập", command=self.open_login)
        self.login_button.pack(pady=10)
        self.reset_button = tk.Button(root, text="Khôi phục tài khoản", command=self.open_reset)
        self.reset_button.pack(pady=10)

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
        self.signup_button.config(state="disabled")
        self.login_button.config(state="disabled")

    def enable_buttons(self):
        self.signup_button.config(state="normal")
        self.login_button.config(state="normal")

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