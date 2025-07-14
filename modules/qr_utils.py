import json
from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo
import qrcode
from pyzbar.pyzbar import decode
from PIL import Image
import base64
from modules.rsa_keys import update_key_status, store_new_public_key_from_qr
from modules.logger import log_action


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
        log_action(email, "generate_qr_code", f"failed: {str(e)}")
        raise ValueError("No RSA key found. Please create a key first.")

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
    log_action(email, "generate_qr_code", f"success: QR code saved at {path_out}")
    return path_out, f"QR code saved at {path_out}"


def read_qr(email: str, qr_path: str) -> tuple[dict, str]:
    """Read a QR code and store its public key if new."""
    try:
        img = Image.open(qr_path)
        decoded = decode(img)
        if not decoded:
            log_action(email, "read_qr_code", "failed: No QR code found")
            raise ValueError("No QR code found in the image")
        data = json.loads(decoded[0].data.decode())
        qr_email = data["email"]
        safe_email = qr_email.replace("@", "_at_").replace(".", "_dot_")
        try:
            datetime.fromisoformat(data["created"])
            expires = datetime.fromisoformat(data["expires"])
            base64.b64decode(data["public_key"])
        except (KeyError, ValueError, TypeError) as e:
            log_action(email, "read_qr_code", f"failed: Invalid data - {str(e)}")
            raise ValueError(f"Invalid QR code data: {str(e)}")

        now = datetime.now(ZoneInfo("Asia/Ho_Chi_Minh"))
        valid_days = (expires - now).days
        status = "in used"

        if valid_days < 0:
            status = "expired"
        elif valid_days <= 30:
            status = "almost expired"
        key_data = {
            "public_key": data["public_key"],
            "created": data["created"],
            "expires": data["expires"],
            "status": status,
            "email": qr_email
        }
        stored = store_new_public_key_from_qr(safe_email, key_data)
        status_msg = "Added to public key store" if stored else "Key already exists in public key store"
        log_action(email, "read_qr_code", f"success: {status_msg}")
        return data, status_msg
    except Exception as e:
        log_action(email, "read_qr_code", f"failed: {str(e)}")
        raise