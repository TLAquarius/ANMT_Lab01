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
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from modules.rsa_keys import generate_rsa_keypair, update_public_key_store, decrypt_user_private_key_with_recovery, derive_key
from pathlib import Path
from modules.logger import log_action

USERS_FILE = "./data/users.json"
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=5)

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
            log_action(email, "sign_up", "failed: Email already exists")
            return False, "Email đã tồn tại", ""

        # Validate passphrase
        valid, error = validate_passphrase(passphrase)
        if not valid:
            log_action(email, "sign_up", f"failed: {error}")
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

        # Create empty JSON files
        (user_dir / "rsa_keypair.json").write_text("")
        (user_dir / "archived_keys.json").write_text("")
        (public_keys_dir / f"{safe_email}.json").write_text("")

        log_action(email, "sign_up", "success")
        return True, "Đăng ký thành công", recovery_code

    except Exception as e:
        log_action(email, "sign_up", f"failed: {str(e)}")
        return False, f"Error: {str(e)}", ""

def generate_otp() -> tuple[str, str, str]:
    """Generate a 6-digit OTP with creation/expiration times."""
    otp = ''.join(random.choices(string.digits, k=6))
    created = datetime.now(ZoneInfo("Asia/Ho_Chi_Minh")).isoformat()
    expires = (datetime.now(ZoneInfo("Asia/Ho_Chi_Minh")) + timedelta(minutes=5)).isoformat()
    return otp, created, expires

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
        log_action(email, "login", "failed: No users registered")
        return False, None, "Chưa có user"

    for user in users:
        if user["email"] == email:
            # Check lockout status
            remaining_time = get_remaining_lockout_time(user.get("lockout_until"))
            if remaining_time > 0:
                log_action(email, "login", f"failed: Account locked for {remaining_time} seconds")
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
                if(user["status"] == "unlocked"):
                    log_action(email, "login", "success: Passphrase verified")
                    return True, user, ""
                else:
                    log_action(email, "login", "failed: Locked user")
                    return False, None, "Tài khoản đã bị khóa"
            else:
                # Increment failed attempts
                user["failed_attempts"] = user.get("failed_attempts", 0) + 1
                if user["failed_attempts"] >= MAX_LOGIN_ATTEMPTS:
                    user["lockout_until"] = (datetime.now(ZoneInfo("Asia/Ho_Chi_Minh")) + LOCKOUT_DURATION).isoformat()
                    user["failed_attempts"] = 0
                with open(USERS_FILE, "w") as f:
                    json.dump(users, f, indent=4)
                log_action(email, "login", f"failed: Incorrect passphrase (attempt {user['failed_attempts']})")
                if user.get("lockout_until"):
                    remaining_time = get_remaining_lockout_time(user["lockout_until"])
                    return False, None, f"Tài khoản đã bị khóa. Thử lại sau {remaining_time} giây."
                return False, None, "Tên người dùng hoặc mật khẩu bị sai"

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

def reset_passphrase(email: str, recovery_code: str, new_passphrase: str) -> tuple[bool, str]:
    """Reset passphrase using recovery code and re-encrypt RSA private key."""
    try:
        # Load users
        try:
            with open(USERS_FILE, "r") as f:
                users = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            log_action(email, "reset_passphrase", "failed: No users registered")
            return False, "No users registered"

        # Find user
        user = next((u for u in users if u["email"] == email), None)
        if not user:
            log_action(email, "reset_passphrase", "failed: Email not found")
            return False, "Email không tồn tại"

        # Verify recovery code
        recovery_code_hash = base64.b64decode(user["recovery_code_hash"])
        recovery_salt = base64.b64decode(user["recovery_code_salt"])
        input_hash = derive_key(recovery_code, recovery_salt)
        if recovery_code_hash != input_hash:
            log_action(email, "reset_passphrase", "failed: Invalid recovery code")
            return False, "Mã khôi phục không hợp lệ"

        # Validate new passphrase
        valid, error = validate_passphrase(new_passphrase)
        if not valid:
            log_action(email, "reset_passphrase", f"failed: {error}")
            return False, error

        # Decrypt private key with recovery code
        private_key = decrypt_user_private_key_with_recovery(email, recovery_code)

        # Re-encrypt private key with new passphrase
        new_salt = os.urandom(16)
        new_hashed_passphrase = derive_key(new_passphrase, new_salt)
        aes_key = derive_key(new_passphrase, new_salt)
        iv = os.urandom(12)
        aesgcm = AESGCM(aes_key)
        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        priv_enc = aesgcm.encrypt(iv, priv_bytes, None)

        # Re-encrypt with new recovery code for future resets
        new_recovery_salt = os.urandom(16)
        recovery_aes_key = derive_key(recovery_code, new_recovery_salt)
        recovery_iv = os.urandom(12)
        recovery_aesgcm = AESGCM(recovery_aes_key)
        priv_enc_recovery = recovery_aesgcm.encrypt(recovery_iv, priv_bytes, None)

        # Update rsa_keypair.json
        safe_email = email.replace("@", "_at_").replace(".", "_dot_")
        key_path = f"./data/{safe_email}/rsa_keypair.json"
        with open(key_path, "r") as f:
            key_data = json.load(f)
        key_data.update({
            "private_key_enc": base64.b64encode(priv_enc).decode(),
            "salt": base64.b64encode(new_salt).decode(),
            "iv": base64.b64encode(iv).decode(),
            "private_key_enc_recovery": base64.b64encode(priv_enc_recovery).decode(),
            "recovery_salt": base64.b64encode(new_recovery_salt).decode(),
            "recovery_iv": base64.b64encode(recovery_iv).decode()
        })
        with open(key_path, "w") as f:
            json.dump(key_data, f, indent=4)

        # Update users.json with new passphrase hash and salt
        user["hashed_passphrase"] = base64.b64encode(new_hashed_passphrase).decode()
        user["salt"] = base64.b64encode(new_salt).decode()
        with open(USERS_FILE, "w") as f:
            json.dump(users, f, indent=4)

        log_action(email, "reset_passphrase", "success")
        return True, "Passphrase reset thành công"

    except Exception as e:
        log_action(email, "reset_passphrase", f"failed: {str(e)}")
        return False, f"Error: {str(e)}"