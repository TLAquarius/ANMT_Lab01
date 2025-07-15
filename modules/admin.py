import json
from pathlib import Path
from modules.logger import log_action

USERS_FILE = Path("./data/users.json")

def is_admin(email: str) -> bool:
    """Check if the user is an admin."""
    try:
        with open(USERS_FILE, "r") as f:
            users = json.load(f)
        user = next((u for u in users if u["email"] == email), None)
        return user and user["role"] == "admin"
    except (FileNotFoundError, json.JSONDecodeError):
        return False

def list_users(admin_email: str) -> tuple[bool, list, str]:
    """List all users (admin only)."""
    if not is_admin(admin_email):
        log_action(admin_email, "Liệt kê danh sách người dùng", "Failed: Không có quyền admin")
        return False, [], "Không có quyền admin"
    try:
        with open(USERS_FILE, "r") as f:
            users = json.load(f)
        user_list = [
            {
                "email": user["email"],
                "full_name": user["full_name"],
                "role": user["role"],
                "status": user["status"]
            }
            for user in users
        ]
        log_action(admin_email, "Liệt kê danh sách người dùng", "Success")
        return True, user_list, ""
    except (FileNotFoundError, json.JSONDecodeError) as e:
        log_action(admin_email, "Liệt kê danh sách người dùng", f"Failed: {str(e)}")
        return False, [], f"Error: {str(e)}"

def lock_unlock_user(admin_email: str, target_email: str, lock: bool) -> tuple[bool, str]:
    """Lock or unlock a user account (admin only)."""
    if not is_admin(admin_email):
        log_action(admin_email, "Khóa/mở khóa tài khoản", "Failed: Không có quyền admin")
        return False, "Không có quyền admin"
    if admin_email == target_email:
        log_action(admin_email, "Khóa/mở khóa tài khoản", "failed: Không thể khóa/mở khóa chính mình")
        return False, "Không thể khóa/mở khóa chính mình"
    try:
        with open(USERS_FILE, "r") as f:
            users = json.load(f)
        user = next((u for u in users if u["email"] == target_email), None)
        if not user:
            log_action(admin_email, "Khóa/mở khóa tài khoản", f"Failed: Tài khoản {target_email} không tồn tại")
            return False, "Tài khoản không tồn tại"
        new_status = "locked" if lock else "unlocked"
        if user["status"] == new_status:
            log_action(admin_email, "Khóa/mở khóa tài khoản", f"Failed: Tài khoản {target_email} đã {new_status} sẵn")
            return False, f"Tài khoản đã {'bị khóa' if lock else 'được mở khóa'}"
        user["status"] = new_status
        user["failed_attempts"] = 0
        user["lockout_until"] = None
        with open(USERS_FILE, "w") as f:
            json.dump(users, f, indent=4)
        log_action(admin_email, "Khóa/mở khóa tài khoản", f"Success: Tài khoản {target_email} được {new_status}")
        return True, f"Tài khoản đã được {'khóa' if lock else 'mở khóa'}"
    except Exception as e:
        log_action(admin_email, "Khóa/mở khóa tài khoản", f"Failed: {str(e)}")
        return False, f"Error: {str(e)}"

def view_system_log(admin_email: str) -> tuple[bool, list, str]:
    """View system-wide activity log (admin only)."""
    if not is_admin(admin_email):
        log_action(admin_email, "Xem log hệ thống", "Failed: Không có quyền admin")
        return False, [], "Không có quyền admin"
    try:
        log_entries = []
        with open("./data/security.log", "r") as f:
            for line in f:
                try:
                    log_entries.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    continue
        log_action(admin_email, "Xem log hệ thống", "Success")
        log_entries.reverse()
        return True, log_entries, ""
    except FileNotFoundError:
        log_action(admin_email, "Xem log hệ thống", "Failed: Không tìm thấy file log")
        return False, [], "Không tìm thấy file log"
    except Exception as e:
        log_action(admin_email, "Xem log hệ thống", f"Failed: {str(e)}")
        return False, [], f"Error: {str(e)}"

def set_user_role(admin_email: str, target_email: str, role: str) -> tuple[bool, str]:
    """Set a user's role to admin or user (admin only, cannot demote self)."""
    if not is_admin(admin_email):
        log_action(admin_email, "Sửa quyền người dùng", "Failed: Không có quyền admin")
        return False, "Không có quyền admin"
    if admin_email == target_email and role != "admin":
        log_action(admin_email, "Sửa quyền người dùng", "Failed: Không thể tự xóa quyền admin")
        return False, "Không thể tự xóa quyền admin"
    if role not in ["admin", "user"]:
        log_action(admin_email, "Sửa quyền người dùng", f"Failed: Vai trò không hợp lệ {role}")
        return False, "Vai trò không hợp lệ"
    try:
        with open(USERS_FILE, "r") as f:
            users = json.load(f)
        user = next((u for u in users if u["email"] == target_email), None)
        if not user:
            log_action(admin_email, "Sửa quyền người dùng", f"Failed: Tài khoản {target_email} không tồn tại")
            return False, "Tài khoản không tồn tại"
        if user["role"] == role:
            log_action(admin_email, "Sửa quyền người dùng", f"Failed: Tài khoản {target_email} đã là {role} sẵn")
            return False, f"Tài khoản đã là {role}"
        user["role"] = role
        with open(USERS_FILE, "w") as f:
            json.dump(users, f, indent=4)
        log_action(admin_email, "Sửa quyền người dùng", f"Success: Đã đặt vai trò của {target_email} thành {role}")
        return True, f"Đã đặt vai trò của {target_email} thành {role}"
    except Exception as e:
        log_action(admin_email, "Sửa quyền người dùng", f"Failed: {str(e)}")
        return False, f"Error: {str(e)}"