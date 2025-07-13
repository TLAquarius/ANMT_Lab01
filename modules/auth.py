import os
import json
import base64
import re
import random
import string
import pyotp
import qrcode
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from modules.rsa_keys import generate_rsa_keypair, update_public_key_store
from pathlib import Path
from modules.logger import log_action

USERS_FILE = "./data/users.json"

def validate_passphrase(passphrase: str) -> tuple[bool, str]:
    """Validate passphrase strength: 8+ chars, uppercase, number, special char."""
    if len(passphrase) < 8:
        return False, "Mật khẩu phải dài tối thiểu 8 ký tự"
    if not re.search(r"[A-Z]", passphrase):
        return False, "Mật khẩu phải chứa tối thiểu 1 chữ viết hoa"
    if not re.search(r"[0-9]", passphrase):
        return False, "Mật khẩu phải chứa ít nhất 1 chữ số"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", passphrase):
        return False, "Mật khẩu phải chứa ít nhất một ký tự đặc biệt"
    return True, ""

def hash_passphrase(passphrase: str, salt: bytes) -> bytes:
    """Hash passphrase with salt using PBKDF2 and SHA-256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(passphrase.encode())

def sign_up(email: str, full_name: str, dob: str, phone: str, address: str, passphrase: str) -> tuple[bool, str]:
    """Register a new user, generate RSA key pair, and create user folder structure."""
    try:
        # Load existing users
        try:
            with open(USERS_FILE, "r") as f:
                users = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            users = []

        # Check email uniqueness
        if any(user["email"] == email for user in users):
            log_action(email, "sign_up", "failed: Email already exists")
            return False, "Email already exists"

        # Validate passphrase
        valid, error = validate_passphrase(passphrase)
        if not valid:
            log_action(email, "sign_up", f"failed: {error}")
            return False, error

        # Hash passphrase
        salt = os.urandom(16)
        hashed_passphrase = hash_passphrase(passphrase, salt)

        # Create user profile
        user = {
            "email": email,
            "full_name": full_name,
            "dob": dob,
            "phone": phone,
            "address": address,
            "hashed_passphrase": base64.b64encode(hashed_passphrase).decode(),
            "salt": base64.b64encode(salt).decode(),
            "role": "user",
            "status": "unlocked",
            "totp_secret": pyotp.random_base32()
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

        # Create empty JSON files
        (user_dir / "rsa_keypair.json").write_text("")
        (user_dir / "archived_keys.json").write_text("")
        (public_keys_dir / f"{safe_email}.json").write_text("")

        log_action(email, "sign_up", "success")
        return True, "User registered successfully"

    except Exception as e:
        log_action(email, "sign_up", f"failed: {str(e)}")
        return False, f"Error: {str(e)}"


def generate_otp() -> tuple[str, str, str]:
    """Generate a 6-digit OTP with creation/expiration times."""
    otp = ''.join(random.choices(string.digits, k=6))
    created = datetime.now(ZoneInfo("Asia/Ho_Chi_Minh")).isoformat()
    expires = (datetime.now(ZoneInfo("Asia/Ho_Chi_Minh")) + timedelta(minutes=5)).isoformat()
    return otp, created, expires


def verify_login(email: str, passphrase: str) -> tuple[bool, dict, str]:
    """Verify user login credentials."""
    try:
        with open(USERS_FILE, "r") as f:
            users = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        log_action(email, "login", "failed: No users registered")
        return False, None, "Chưa có user"

    for user in users:
        if user["email"] == email:
            stored_hash = base64.b64decode(user["hashed_passphrase"])
            salt = base64.b64decode(user["salt"])
            input_hash = hash_passphrase(passphrase, salt)
            if stored_hash == input_hash:
                if(user["status"] == "unlocked"):
                    log_action(email, "login", "success: Passphrase verified")
                    return True, user, ""
                else:
                    log_action(email, "login", "failed: Locked user")
                    return False, None, "Tài khoản đã bị khóa"
            else:
                log_action(email, "login", "failed: Incorrect passphrase")
                return False, None, "Tên người dùng hay mật khẩu bị sai"

    log_action(email, "login", "failed: Email not found")
    return False, None, "Tên người dùng hoặc mật khẩu bị sai"


def generate_totp_qr(email: str, totp_secret: str) -> str:
    """Generate TOTP QR code and save to user's folder."""
    totp = pyotp.TOTP(totp_secret)
    uri = totp.provisioning_uri(name=email, issuer_name="CryptoDemo")
    qr = qrcode.QRCode()
    qr.add_data(uri)
    qr.make(fit=True)
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    qr_path = f"./data/{safe_email}/qrTOTP.png"
    os.makedirs(os.path.dirname(qr_path), exist_ok=True)
    qr.make_image(fill_color="black", back_color="white").save(qr_path)
    return qr_path

def verify_totp(totp_secret: str, code: str) -> bool:
    """Verify TOTP code."""
    totp = pyotp.TOTP(totp_secret)
    return totp.verify(code)