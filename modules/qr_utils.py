import json
from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo
import qrcode
from pyzbar.pyzbar import decode
from PIL import Image
import base64
from modules.key_status import update_key_status
from modules.logger import log_action

PUBLIC_KEY_DIR = Path("./data/public_keys")

def generate_qr_for_public_key(email: str, safe_email: str) -> tuple[Path, str]:
    """Generate a QR code with the user's current public key."""
    key_path = Path(f"./data/{safe_email}/rsa_keypair.json")
    now = datetime.now(ZoneInfo("Asia/Ho_Chi_Minh"))
    try:
        with open(key_path, "r") as f:
            key_data = json.load(f)
            key_data = update_key_status(key_data, now)
            with open(key_path, "w") as f:
                json.dump(key_data, f, indent=4)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        log_action(email, "Tạo mã QR public key", f"Failed: {str(e)}")
        raise ValueError("Không tìm thấy key")

    data = {
        "email": email,
        "created": key_data["created"],
        "expires": key_data["expires"],
        "public_key": key_data["public_key"]
    }
    qr = qrcode.make(json.dumps(data))
    path_out = Path(f"./data/{safe_email}/public_key_qr.png")
    path_out.parent.mkdir(parents=True, exist_ok=True)
    qr.save(path_out)
    log_action(email, "Tạo mã QR public key", f"Success: Mã QR lưu tại {path_out}")
    return path_out, f"QR code saved at {path_out}"

def store_new_public_key_from_qr(safe_email: str, key_data: dict) -> bool:
    """Store a new public key from a QR code if it's not already in the store."""
    public_key_path = PUBLIC_KEY_DIR / f"{safe_email}.json"
    PUBLIC_KEY_DIR.mkdir(parents=True, exist_ok=True)
    try:
        with open(public_key_path, "r") as f:
            existing_key = json.load(f)
        if existing_key == key_data:
            log_action(safe_email.replace("_at_", "@").replace("_dot_", "."),"Lưu public key từ mã QR", "Failed: Key đã tồn tại")
            return False
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    with open(public_key_path, "w") as f:
        json.dump(key_data, f, indent=4)
    log_action(safe_email.replace("_at_", "@").replace("_dot_", "."),"Lưu public key từ mã QR", "Success")
    return True

def read_qr(email: str, qr_path: str) -> tuple[dict, str]:
    """Read a QR code and store its public key if new."""
    try:
        img = Image.open(qr_path)
        decoded = decode(img)
        if not decoded:
            log_action(email, "Đọc mã QR public key", "Failed: Không tìm thấy mã QR trong ảnh")
            raise ValueError("Không tìm thấy mã QR trong ảnh")
        data = json.loads(decoded[0].data.decode())
        qr_email = data["email"]
        safe_email = qr_email.replace("@", "_at_").replace(".", "_dot_")
        try:
            datetime.fromisoformat(data["created"])
            expires = datetime.fromisoformat(data["expires"])
            base64.b64decode(data["public_key"])
        except (KeyError, ValueError, TypeError) as e:
            log_action(email, "Đọc mã QR public key", f"Failed: Không chứa data public key - {str(e)}")
            raise ValueError(f"Không chứa data public key - {str(e)}")

        now = datetime.now(ZoneInfo("Asia/Ho_Chi_Minh"))
        valid_days = (expires - now).days
        status = "Còn hạn"

        if valid_days < 0:
            status = "Hết hạn"
        elif valid_days <= 30:
            status = "Gần hết hạn"
        key_data = {
            "public_key": data["public_key"],
            "created": data["created"],
            "expires": data["expires"],
            "status": status,
            "email": qr_email
        }
        stored = store_new_public_key_from_qr(safe_email, key_data)
        status_msg = "Đã thêm vào kho public_keys" if stored else "Key đã tồn tại trong kho public_keys"
        log_action(email, "Đọc mã QR public key", f"Success: {status_msg}")
        return data, status_msg
    except Exception as e:
        log_action(email, "Đọc mã QR public key", f"Failed: {str(e)}")
        raise