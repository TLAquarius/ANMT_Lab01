import tkinter as tk
from gui.register_window import SignupWindow
from gui.login_window import LoginWindow

class MainWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Authentication System")
        self.min_width = 300
        self.min_height = 200
        self.root.configure(padx=20, pady=20)

        # Welcome label
        tk.Label(root, text="Welcome to the Authentication System").pack(pady=10)

        # Buttons
        self.signup_button = tk.Button(root, text="Sign Up", command=self.open_signup)
        self.signup_button.pack(pady=10)
        self.login_button = tk.Button(root, text="Login", command=self.open_login)
        self.login_button.pack(pady=10)

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

    def disable_buttons(self):
        """Disable the signup and login buttons."""
        self.signup_button.config(state="disabled")
        self.login_button.config(state="disabled")

    def enable_buttons(self):
        """Enable the signup and login buttons."""
        self.signup_button.config(state="normal")
        self.login_button.config(state="normal")

    def open_signup(self):
        """Open the signup window and disable main window buttons."""
        self.disable_buttons()
        signup_window = tk.Toplevel(self.root)
        SignupWindow(signup_window, self)  # Pass self (MainWindow instance)

    def open_login(self):
        """Open the login window and disable main window buttons."""
        self.disable_buttons()
        login_window = tk.Toplevel(self.root)
        LoginWindow(login_window, self)  # Pass self (MainWindow instance)

if __name__ == "__main__":
    root = tk.Tk()
    app = MainWindow(root)
    root.mainloop()