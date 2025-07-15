import tkinter as tk
from gui.register_window import SignupWindow
from gui.login_window import LoginWindow
from gui.recovery_window import RecoveryWindow
from gui.admin_panel import AdminWindow

class MainWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Authentication System")
        self.min_width = 300
        self.min_height = 200
        self.root.configure(padx=20, pady=20)

        tk.Label(root, text="Welcome to the Authentication System").pack(pady=10)

        self.signup_button = tk.Button(root, text="Sign Up", command=self.open_signup)
        self.signup_button.pack(pady=10)
        self.login_button = tk.Button(root, text="Login", command=self.open_login)
        self.login_button.pack(pady=10)
        self.reset_button = tk.Button(root, text="Reset Passphrase", command=self.open_reset)
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

    def open_signup(self):
        signup_window = tk.Toplevel(self.root)
        SignupWindow(signup_window, self)

    def open_login(self):
        login_window = tk.Toplevel(self.root)
        LoginWindow(login_window, self)

    def open_reset(self):
        reset_window = tk.Toplevel(self.root)
        RecoveryWindow(reset_window, self)

if __name__ == "__main__":
    root = tk.Tk()
    app = MainWindow(root)
    root.mainloop()