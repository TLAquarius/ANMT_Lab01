import os
import json
import base64
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from modules.logger import log_action
from pathlib import Path

PUBLIC_KEY_DIR = Path("./data/public_keys")

def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derives AES key from passphrase using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000,
    )
    return kdf.derive(passphrase.encode())

def update_key_status(key_data, now):
    """Update the status of a key based on its expiration and current time."""
    expires = datetime.fromisoformat(key_data["expires"])
    valid_days = (expires - now).days
    if key_data["status"] == "in used":
        if valid_days < 0:
            key_data["status"] = "expired"
        elif valid_days <= 30:
            key_data["status"] = "almost expired"
    return key_data

def update_public_key_store(email: str):
    """Update public key store with the current key for the user (single dict)."""
    PUBLIC_KEY_DIR.mkdir(parents=True, exist_ok=True)
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    public_key_path = PUBLIC_KEY_DIR / f"{safe_email}.json"
    now = datetime.now(ZoneInfo("Asia/Ho_Chi_Minh"))

    # Load current key
    key_data = {}
    try:
        with open(f"./data/{safe_email}/rsa_keypair.json", "r") as f:
            key_data = json.load(f)
            key_data = update_key_status(key_data, now)
            with open(f"./data/{safe_email}/rsa_keypair.json", "w") as f:
                json.dump(key_data, f, indent=4)
        public_key_data = {
            "public_key": key_data["public_key"],
            "created": key_data["created"],
            "expires": key_data["expires"],
            "status": key_data["status"],
            "email": email
        }
        with open(public_key_path, "w") as f:
            json.dump(public_key_data, f, indent=4)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        log_action(email, "update_public_key_store", f"failed: {str(e)}")
        if public_key_path.exists():
            public_key_path.unlink()

def load_current_public_key(recipient_email):
    """Load recipient's RSA public key from file."""
    safe_email = recipient_email.replace("@", "_at_").replace(".", "_dot_")
    update_public_key_store(recipient_email)
    try:
        with open(f"./data/{safe_email}/rsa_keypair.json", "r") as f:
            key_data = json.load(f)
        public_pem = base64.b64decode(key_data["public_key"])
        public_key = serialization.load_pem_public_key(public_pem)
        return public_key
    except Exception as e:
        log_action(recipient_email, "load_public_key", f"failed: {str(e)}")
        raise

def generate_rsa_keypair(email: str, passphrase: str, recovery_code: str = None, mode="create") -> dict:
    """Generate or extend RSA key pair with 90-day expiration."""
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    key_path = Path(f"./data/{safe_email}/rsa_keypair.json")
    key_path.parent.mkdir(parents=True, exist_ok=True)
    time_now = datetime.now(ZoneInfo("Asia/Ho_Chi_Minh"))

    if mode == "extend":
        try:
            with open(key_path, "r") as f:
                current_key_data = json.load(f)
            public_pem = base64.b64decode(current_key_data["public_key"])
            public_key = serialization.load_pem_public_key(public_pem)
            priv_enc = base64.b64decode(current_key_data["private_key_enc"])
            salt = base64.b64decode(current_key_data["salt"])
            iv = base64.b64decode(current_key_data["iv"])
            aes_key = derive_key(passphrase, salt)
            aesgcm = AESGCM(aes_key)
            priv_bytes = aesgcm.decrypt(iv, priv_enc, None)
            private_key = serialization.load_pem_private_key(priv_bytes, password=None)

            new_salt = os.urandom(16)
            new_aes_key = derive_key(passphrase, new_salt)
            new_iv = os.urandom(12)
            new_aesgcm = AESGCM(new_aes_key)
            new_priv_enc = new_aesgcm.encrypt(new_iv, priv_bytes, None)

            recovery_enc_data = None
            if recovery_code:
                recovery_salt = os.urandom(16)
                recovery_aes_key = derive_key(recovery_code, recovery_salt)
                recovery_iv = os.urandom(12)
                recovery_aesgcm = AESGCM(recovery_aes_key)
                priv_enc_recovery = recovery_aesgcm.encrypt(recovery_iv, priv_bytes, None)
                recovery_enc_data = {
                    "private_key_enc_recovery": base64.b64encode(priv_enc_recovery).decode(),
                    "recovery_salt": base64.b64encode(recovery_salt).decode(),
                    "recovery_iv": base64.b64encode(recovery_iv).decode()
                }

            current_key_data.update({
                "private_key_enc": base64.b64encode(new_priv_enc).decode(),
                "salt": base64.b64encode(new_salt).decode(),
                "iv": base64.b64encode(new_iv).decode(),
                "renew": time_now.isoformat(),
                "expires": (time_now + timedelta(days=90)).isoformat(),
                "status": "in used"
            })
            if recovery_enc_data:
                current_key_data.update(recovery_enc_data)
            elif not recovery_code and "private_key_enc_recovery" in current_key_data:
                current_key_data.pop("private_key_enc_recovery", None)
                current_key_data.pop("recovery_salt", None)
                current_key_data.pop("recovery_iv", None)

            with open(key_path, "w") as f:
                json.dump(current_key_data, f, indent=4)
            update_public_key_store(email)
            log_action(email, "generate_rsa_keypair", "success: Extended existing key with new encryption")
            return current_key_data
        except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
            log_action(email, "generate_rsa_keypair", f"failed: {str(e)}")
            # Fall through to generate new key if extension fails

    # Generate new RSA key pair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Serialize keys
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Encrypt private key using AES-GCM
    salt = os.urandom(16)
    aes_key = derive_key(passphrase, salt)
    iv = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    priv_enc = aesgcm.encrypt(iv, priv_bytes, associated_data=None)

    # Encrypt private key with recovery code (if provided)
    recovery_enc_data = None
    if recovery_code:
        recovery_salt = os.urandom(16)
        recovery_aes_key = derive_key(recovery_code, recovery_salt)
        recovery_iv = os.urandom(12)
        recovery_aesgcm = AESGCM(recovery_aes_key)
        priv_enc_recovery = recovery_aesgcm.encrypt(recovery_iv, priv_bytes, None)
        recovery_enc_data = {
            "private_key_enc_recovery": base64.b64encode(priv_enc_recovery).decode(),
            "recovery_salt": base64.b64encode(recovery_salt).decode(),
            "recovery_iv": base64.b64encode(recovery_iv).decode()
        }

    # Create key data dictionary
    new_time = datetime.now(ZoneInfo("Asia/Ho_Chi_Minh"))
    key_data = {
        "public_key": base64.b64encode(pub_bytes).decode(),
        "private_key_enc": base64.b64encode(priv_enc).decode(),
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode(),
        "created": new_time.isoformat(),
        "expires": (new_time + timedelta(days=90)).isoformat(),
        "renew": "",
        "status": "in used",
        "key_size": 2048,
        "format": "PEM",
        "algorithm": "RSA",
        "public_exponent": 65537,
        "encryption_mode": "AES-GCM"
    }

    # Add recovery encryption data if available
    if recovery_enc_data:
        key_data.update(recovery_enc_data)

    # Save new key pair, overwriting any existing key
    with open(key_path, "w") as f:
        json.dump(key_data, f, indent=4)

    update_public_key_store(email)
    log_action(email, "generate_rsa_keypair", f"success: Generated new key{' with recovery code' if recovery_code else ''}")
    return key_data

def get_private_key_for_decryption(email: str, passphrase: str, message_timestamp: str) -> object:
    """Retrieve the private key for decryption, validating against message timestamp."""
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    key_path = Path(f"./data/{safe_email}/rsa_keypair.json")
    message_time = datetime.fromisoformat(message_timestamp)

    try:
        with open(key_path, "r") as f:
            key_data = json.load(f)
        key_created = datetime.fromisoformat(key_data["created"])
        key_expires = datetime.fromisoformat(key_data["expires"])
        if key_created <= message_time <= key_expires:
            priv_enc = base64.b64decode(key_data["private_key_enc"])
            salt = base64.b64decode(key_data["salt"])
            iv = base64.b64decode(key_data["iv"])
            aes_key = derive_key(passphrase, salt)
            aesgcm = AESGCM(aes_key)
            priv_bytes = aesgcm.decrypt(iv, priv_enc, None)
            return serialization.load_pem_private_key(priv_bytes, password=None)
        else:
            log_action(email, "get_private_key_for_decryption", f"failed: Message timestamp {message_timestamp} not valid for current key")
            raise ValueError("The file was encrypted with an old key and is no longer valid")
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
        log_action(email, "get_private_key_for_decryption", f"failed: {str(e)}")
        raise ValueError("No valid private key found for the message's timestamp")

def verify_signature(email: str, signature: bytes, data: bytes, message_timestamp: str) -> bool:
    """Verify a signature, ensuring it was signed with the current key."""
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    key_path = Path(f"./data/{safe_email}/rsa_keypair.json")
    message_time = datetime.fromisoformat(message_timestamp)

    try:
        with open(key_path, "r") as f:
            key_data = json.load(f)
        key_created = datetime.fromisoformat(key_data["created"])
        key_expires = datetime.fromisoformat(key_data["expires"])
        if key_created <= message_time <= key_expires:
            public_pem = base64.b64decode(key_data["public_key"])
            public_key = serialization.load_pem_public_key(public_pem)
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            log_action(email, "verify_signature", "success: Signature verified")
            return True
        else:
            log_action(email, "verify_signature", f"failed: Message timestamp {message_timestamp} not valid for current key")
            raise ValueError("The file was signed with an old key and is no longer valid")
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
        log_action(email, "verify_signature", f"failed: {str(e)}")
        raise ValueError("No valid public key found for the message's timestamp")


def decrypt_user_private_key_with_recovery(email: str, recovery_code: str) -> tuple[bool, object, str]:
    """Decrypt the user's current RSA private key using recovery code."""
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    key_path = Path(f"./data/{safe_email}/rsa_keypair.json")
    try:
        with open(key_path, "r") as f:
            key_data = json.load(f)

        if "private_key_enc_recovery" not in key_data:
            log_action(email, "decrypt_user_private_key_with_recovery", "failed: No recovery code associated with key")
            return False, None, "Khóa riêng không thể khôi phục vì không có recovery code lúc tạo key. Tạo khóa mới thành công"
        priv_enc = base64.b64decode(key_data["private_key_enc_recovery"])
        salt = base64.b64decode(key_data["recovery_salt"])
        iv = base64.b64decode(key_data["recovery_iv"])

        aes_key = derive_key(recovery_code, salt)
        aesgcm = AESGCM(aes_key)
        priv_bytes = aesgcm.decrypt(iv, priv_enc, None)

        log_action(email, "decrypt_user_private_key_with_recovery", "success")
        return True, serialization.load_pem_private_key(priv_bytes, password=None), "Khóa riêng được khôi phục thành công"
    except (FileNotFoundError, json.JSONDecodeError):
        log_action(email, "decrypt_user_private_key_with_recovery", "failed: Key file not found or invalid")
        return False, None, "Không tìm thấy tệp khóa hoặc tệp không hợp lệ"
    except Exception as e:
        log_action(email, "decrypt_user_private_key_with_recovery", f"failed: {str(e)}")
        return False, None, f"Không thể giải mã khóa riêng: {str(e)}"


def store_new_public_key_from_qr(safe_email: str, key_data: dict) -> bool:
    """Store a new public key from a QR code if it's not already in the store."""
    public_key_path = PUBLIC_KEY_DIR / f"{safe_email}.json"
    PUBLIC_KEY_DIR.mkdir(parents=True, exist_ok=True)
    try:
        with open(public_key_path, "r") as f:
            existing_key = json.load(f)
        if existing_key == key_data:
            log_action(safe_email.replace("_at_", "@").replace("_dot_", "."),"store_new_public_key_from_qr", "failed: Key already exists")
            return False
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    with open(public_key_path, "w") as f:
        json.dump(key_data, f, indent=4)
    log_action(safe_email.replace("_at_", "@").replace("_dot_", "."),"store_new_public_key_from_qr", "success: Stored new public key")
    return True
def get_active_private_key(email: str, passphrase: str) -> object:
    """
    Lấy khóa riêng đang hoạt động (chưa hết hạn) của người dùng để ký.
    Ném ra ValueError nếu khóa đã hết hạn, không tìm thấy hoặc passphrase không chính xác.
    """
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    key_path = Path(f"./data/{safe_email}/rsa_keypair.json")
    now = datetime.now(ZoneInfo("Asia/Ho_Chi_Minh"))

    try:
        with open(key_path, "r") as f:
            key_data = json.load(f)

        # Kiểm tra xem khóa có hợp lệ để ký không
        key_expires = datetime.fromisoformat(key_data["expires"])
        if now > key_expires:
            log_action(email, "get_active_private_key", "failed: Key is expired")
            raise ValueError("Khóa RSA của bạn đã hết hạn. Vui lòng tạo khóa mới.")

        # Giải mã khóa riêng. Thao tác này sẽ thất bại nếu passphrase sai.
        priv_enc = base64.b64decode(key_data["private_key_enc"])
        salt = base64.b64decode(key_data["salt"])
        iv = base64.b64decode(key_data["iv"])
        aes_key = derive_key(passphrase, salt)
        aesgcm = AESGCM(aes_key)
        priv_bytes = aesgcm.decrypt(iv, priv_enc, None)

        log_action(email, "get_active_private_key", "success")
        return serialization.load_pem_private_key(priv_bytes, password=None)

    except (FileNotFoundError, json.JSONDecodeError):
        log_action(email, "get_active_private_key", "failed: Key file not found or invalid")
        raise ValueError("Không tìm thấy tệp khóa RSA. Vui lòng tạo khóa trước.")
    except ValueError as e:
        # Bắt lỗi từ aesgcm.decrypt (passphrase sai) hoặc lỗi hết hạn ở trên
        if "decryption" in str(e).lower() or "ciphertext" in str(e).lower():
            log_action(email, "get_active_private_key", "failed: Invalid passphrase")
            raise ValueError("Passphrase không hợp lệ.")
        log_action(email, "get_active_private_key", f"failed: {str(e)}")
        raise e  # Ném lại lỗi gốc (ví dụ: thông báo hết hạn)
    except Exception as e:
        log_action(email, "get_active_private_key", f"failed: Unexpected error {str(e)}")
        raise ValueError(f"Lỗi không xác định khi truy xuất khóa: {str(e)}")