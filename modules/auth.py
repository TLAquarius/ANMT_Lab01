import os
import json
import base64
import re
import random
import string
import pyotp
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from modules.rsa_keys import generate_rsa_keypair, update_public_key_store, derive_key
from pathlib import Path
from modules.logger import log_action

USERS_FILE = "./data/users.json"
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=5)

def validate_passphrase(passphrase: str) -> tuple[bool, str]:
    """Validate passphrase strength: 8+ chars, uppercase, number, special char."""
    if len(passphrase) < 8:
        return False, "Passphrase phải dài tối thiểu 8 ký tự"
    if not re.search(r"[A-Z]", passphrase):
        return False, "Passphrase phải chứa tối thiểu 1 chữ viết hoa"
    if not re.search(r"[0-9]", passphrase):
        return False, "Passphrase phải chứa ít nhất 1 chữ số"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", passphrase):
        return False, "Passphrase phải chứa ít nhất một ký tự đặc biệt"
    return True, ""

def verify_passphrase(email: str, passphrase: str) -> tuple[bool, str]:
    """Verify passphrase against stored hash in users.json."""
    try:
        with open(USERS_FILE, "r") as f:
            users = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        log_action(email, "Kiểm tra mật khẩu", "Failed: Chưa có người dùng đăng ký")
        return False, "Chưa có user"

    user = next((u for u in users if u["email"] == email), None)
    if not user:
        log_action(email, "Kiểm tra mật khẩu", "Failed: Email không tồn tại")
        return False, "Email không tồn tại"

    stored_hash = base64.b64decode(user["hashed_passphrase"])
    salt = base64.b64decode(user["salt"])
    input_hash = derive_key(passphrase, salt)
    if stored_hash == input_hash:
        log_action(email, "Kiểm tra mật khẩu", "Success")
        return True, ""
    else:
        log_action(email, "Kiểm tra mật khẩu", "failed: Passphrase bị sai")
        return False, "Passphrase không hợp lệ"

def generate_recovery_code() -> str:
    """Generate a 16-character alphanumeric recovery code."""
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(16))

def sign_up(email: str, full_name: str, dob: str, phone: str, address: str, passphrase: str) -> tuple[bool, str, str]:
    """Register a new user, generate RSA key pair, and return recovery code."""
    try:
        # Load existing users
        try:
            with open(USERS_FILE, "r") as f:
                users = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            users = []

        # Check email uniqueness
        if any(user["email"] == email for user in users):
            log_action(email, "Đăng ký", "Failed: Email đã tồn tại")
            return False, "Email đã tồn tại", ""

        # Validate passphrase
        valid, error = validate_passphrase(passphrase)
        if not valid:
            log_action(email, "Đăng ký", f"Failed: {error}")
            return False, error, ""

        # Hash passphrase
        salt = os.urandom(16)
        hashed_passphrase = derive_key(passphrase, salt)

        # Generate recovery code and hash it
        recovery_code = generate_recovery_code()
        recovery_salt = os.urandom(16)
        recovery_code_hash = derive_key(recovery_code, recovery_salt)

        # Generate RSA key pair
        key_data = generate_rsa_keypair(email, passphrase, recovery_code)
        update_public_key_store(email)

        # Create user profile, assign admin role if first user
        user = {
            "email": email,
            "full_name": full_name,
            "dob": dob,
            "phone": phone,
            "address": address,
            "hashed_passphrase": base64.b64encode(hashed_passphrase).decode(),
            "salt": base64.b64encode(salt).decode(),
            "role": "admin" if not users else "user",
            "status": "unlocked",
            "totp_secret": pyotp.random_base32(),
            "failed_attempts": 0,
            "lockout_until": None,
            "recovery_code_hash": base64.b64encode(recovery_code_hash).decode(),
            "recovery_code_salt": base64.b64encode(recovery_salt).decode()
        }
        users.append(user)

        # Save users
        os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
        with open(USERS_FILE, "w") as f:
            json.dump(users, f, indent=4)

        safe_email = email.replace("@", "_at_").replace(".", "_dot_")
        # Create user folder structure in data directory
        data_dir = Path("./data")
        user_dir = data_dir / safe_email
        storage_dir = user_dir / "storage"
        public_keys_dir = data_dir / "public_keys"

        # Create directories
        user_dir.mkdir(parents=True, exist_ok=True)
        storage_dir.mkdir(parents=True, exist_ok=True)
        public_keys_dir.mkdir(parents=True, exist_ok=True)

        log_action(email, "Đăng ký", f"Success: Người dùng được cấp quyền {'admin' if not users else 'user'}")
        return True, "Đăng ký thành công", recovery_code

    except Exception as e:
        log_action(email, "Đăng ký", f"Failed: {str(e)}")
        return False, f"Error: {str(e)}", ""

def get_remaining_lockout_time(lockout_until: str) -> int:
    """Calculate remaining lockout time in seconds, or 0 if not locked."""
    if not lockout_until:
        return 0
    lockout_time = datetime.fromisoformat(lockout_until)
    now = datetime.now(ZoneInfo("Asia/Ho_Chi_Minh"))
    remaining = (lockout_time - now).total_seconds()
    return max(0, int(remaining))

def verify_login(email: str, passphrase: str) -> tuple[bool, dict, str]:
    """Verify user login credentials with login attempt limits."""
    try:
        with open(USERS_FILE, "r") as f:
            users = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        log_action(email, "Đăng nhập", "failed: Chưa có người dùng")
        return False, None, "Chưa có user"

    for user in users:
        if user["email"] == email:
            # Check lockout status
            remaining_time = get_remaining_lockout_time(user.get("lockout_until"))
            if remaining_time > 0:
                log_action(email, "Đăng nhập", f"Failed: Tài khoản đã bị khóa. Thử lại sau {remaining_time} giây.")
                return False, None, f"Tài khoản đã bị khóa. Thử lại sau {remaining_time} giây."

            stored_hash = base64.b64decode(user["hashed_passphrase"])
            salt = base64.b64decode(user["salt"])
            input_hash = derive_key(passphrase, salt)

            if stored_hash == input_hash:
                # Reset failed attempts on successful login
                user["failed_attempts"] = 0
                user["lockout_until"] = None
                with open(USERS_FILE, "w") as f:
                    json.dump(users, f, indent=4)
                if user["status"] == "unlocked":
                    log_action(email, "Đăng nhập", "Success")
                    return True, user, ""
                else:
                    log_action(email, "Đăng nhập", "Failed: Tài khoản đã bị khóa")
                    return False, None, "Tài khoản đã bị khóa"
            else:
                # Increment failed attempts
                user["failed_attempts"] = user.get("failed_attempts", 0) + 1
                if user["failed_attempts"] >= MAX_LOGIN_ATTEMPTS:
                    user["lockout_until"] = (datetime.now(ZoneInfo("Asia/Ho_Chi_Minh")) + LOCKOUT_DURATION).isoformat()
                    user["failed_attempts"] = 0
                with open(USERS_FILE, "w") as f:
                    json.dump(users, f, indent=4)
                log_action(email, "Đăng nhập", f"Failed: Passphrase bị sai (số lần nhập sai {user['failed_attempts']})")
                if user.get("lockout_until"):
                    remaining_time = get_remaining_lockout_time(user["lockout_until"])
                    log_action(email, "Đăng nhập", f"Failed: Tài khoản đã bị khóa. Thử lại sau {remaining_time} giây.")
                    return False, None, f"Tài khoản đã bị khóa. Thử lại sau {remaining_time} giây."
                return False, None, "Tên người dùng hoặc mật khẩu bị sai"

    log_action(email, "Đăng nhập", "Failed: Email không tồn tại")
    return False, None, "Tên người dùng hoặc mật khẩu bị sai"
