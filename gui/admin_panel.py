import tkinter as tk
from tkinter import ttk, messagebox
from modules.admin import list_users, lock_unlock_user, view_system_log, set_user_role, is_admin
from modules.logger import log_action

class AdminWindow:
    def __init__(self, root, main_window, admin_email):
        if not is_admin(admin_email):
            log_action(admin_email, "open_admin_window", "failed: Not an admin")
            messagebox.showerror("Lỗi", "Bạn không có quyền admin")
            root.destroy()
            return

        self.root = root
        self.main_window = main_window
        self.admin_email = admin_email
        self.root.title("Bảng Quản Trị")
        self.root.configure(padx=20, pady=20)

        # User list frame
        tk.Label(self.root, text="Danh Sách Tài Khoản").pack(pady=10)
        self.tree = ttk.Treeview(self.root, columns=("Email", "Full Name", "Role", "Status"), show="headings")
        self.tree.heading("Email", text="Email")
        self.tree.heading("Full Name", text="Họ Tên")
        self.tree.heading("Role", text="Vai Trò")
        self.tree.heading("Status", text="Trạng Thái")
        self.tree.pack(pady=10, fill="both", expand=True)

        # Buttons
        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=10)
        tk.Button(button_frame, text="Khóa Tài Khoản", command=self.lock_user).pack(side="left", padx=5)
        tk.Button(button_frame, text="Mở Khóa Tài Khoản", command=self.unlock_user).pack(side="left", padx=5)
        tk.Button(button_frame, text="Đặt Làm Admin", command=lambda: self.set_role("admin")).pack(side="left", padx=5)
        tk.Button(button_frame, text="Xóa Quyền Admin", command=lambda: self.set_role("user")).pack(side="left", padx=5)
        tk.Button(button_frame, text="Xem Log Hệ Thống", command=self.view_log).pack(side="left", padx=5)
        tk.Button(button_frame, text="Đóng", command=self.close).pack(side="left", padx=5)

        # Log display
        self.log_text = tk.Text(self.root, height=10, width=80, state="disabled")
        self.log_text.pack(pady=10, fill="both", expand=True)

        # Load users
        self.load_users()

        # Adjust window size
        self.adjust_window_size()

    def adjust_window_size(self):
        """Adjust window size to fit all elements."""
        self.root.update_idletasks()
        req_width = max(self.root.winfo_reqwidth() + 40, 600)
        req_height = max(self.root.winfo_reqheight() + 40, 400)
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - req_width) // 2
        y = (screen_height - req_height) // 2
        self.root.geometry(f"{req_width}x{req_height}+{x}+{y}")
        self.root.minsize(600, 400)

    def load_users(self):
        """Load and display the list of users."""
        for item in self.tree.get_children():
            self.tree.delete(item)
        success, users, error = list_users(self.admin_email)
        if not success:
            messagebox.showerror("Lỗi", error)
            return
        for user in users:
            role_display = "Quản Trị" if user["role"] == "admin" else "Người Dùng"
            status_display = "Mở Khóa" if user["status"] == "unlocked" else "Khóa"
            self.tree.insert("", "end", values=(user["email"], user["full_name"], role_display, status_display))

    def lock_user(self):
        """Lock the selected user account."""
        selected = self.tree.selection()
        if not selected:
            messagebox.showerror("Lỗi", "Vui lòng chọn một tài khoản")
            return
        email = self.tree.item(selected[0])["values"][0]
        success, message = lock_unlock_user(self.admin_email, email, True)
        if success:
            messagebox.showinfo("Thành Công", message)
            self.load_users()
        else:
            messagebox.showerror("Lỗi", message)

    def unlock_user(self):
        """Unlock the selected user account."""
        selected = self.tree.selection()
        if not selected:
            messagebox.showerror("Lỗi", "Vui lòng chọn một tài khoản")
            return
        email = self.tree.item(selected[0])["values"][0]
        success, message = lock_unlock_user(self.admin_email, email, False)
        if success:
            messagebox.showinfo("Thành Công", message)
            self.load_users()
        else:
            messagebox.showerror("Lỗi", message)

    def set_role(self, role):
        """Set the role of the selected user."""
        selected = self.tree.selection()
        if not selected:
            messagebox.showerror("Lỗi", "Vui lòng chọn một tài khoản")
            return
        email = self.tree.item(selected[0])["values"][0]
        success, message = set_user_role(self.admin_email, email, role)
        if success:
            messagebox.showinfo("Thành Công", message)
            self.load_users()
        else:
            messagebox.showerror("Lỗi", message)

    def view_log(self):
        """Display the system log."""
        success, logs, error = view_system_log(self.admin_email)
        if not success:
            messagebox.showerror("Lỗi", error)
            return
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", tk.END)
        for log in logs:
            self.log_text.insert(tk.END, f"{log['timestamp']} | {log['email']} | {log['action']} | {log['status']}\n")
        self.log_text.config(state="disabled")

    def close(self):
        """Close the admin window and re-enable main window buttons."""
        self.main_window.enable_buttons()
        self.root.destroy()