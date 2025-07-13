import json
from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo
import qrcode
from pyzbar.pyzbar import decode
from PIL import Image
import base64
from modules.rsa_keys import update_key_status
from modules.logger import log_action

PUBLIC_KEY_DIR = Path("./data/public_keys")


def store_new_public_key_from_qr(email: str, key_data: dict) -> bool:
    """Store a new public key from a QR code if it doesn't exist in the public key store."""
    PUBLIC_KEY_DIR.mkdir(parents=True, exist_ok=True)
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    public_key_path = PUBLIC_KEY_DIR / f"{safe_email}.json"
    now = datetime.now(ZoneInfo("Asia/Ho_Chi_Minh"))

    try:
        with open(public_key_path, "r") as f:
            public_keys = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        public_keys = []

    # Check if the public key already exists
    for existing_key in public_keys:
        if existing_key["public_key"] == key_data["public_key"]:
            log_action(email, "store_new_public_key", f"failed: Public keys already exists")
            return False  # Key already exists

    # Update status of the new key
    key_data = update_key_status(key_data, now)
    public_keys.append({
        "public_key": key_data["public_key"],
        "created": key_data["created"],
        "expires": key_data["expires"],
        "status": key_data["status"],
        "email": email
    })

    with open(public_key_path, "w") as f:
        json.dump(public_keys, f, indent=4)
    log_action(email, "store_new_public_key", f"success: Added new key created {key_data['created']}")
    return True


def generate_qr_for_public_key(email: str, safe_email: str) -> tuple[Path, str]:
    """Generate a QR code with email, public key, created date, expires date, and status."""
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
        "public_key": key_data["public_key"],
        "status": key_data["status"]
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
        try:
            datetime.fromisoformat(data["created"])
            datetime.fromisoformat(data["expires"])
            base64.b64decode(data["public_key"])
        except (KeyError, ValueError, TypeError) as e:
            log_action(email, "read_qr_code", f"failed: Invalid data - {str(e)}")
            raise ValueError(f"Invalid QR code data: {str(e)}")
        key_data = {
            "public_key": data["public_key"],
            "created": data["created"],
            "expires": data["expires"],
            "status": data["status"]
        }
        stored = store_new_public_key_from_qr(email, key_data)
        status_msg = "Added to public key store" if stored else "Key already exists in public key store"
        log_action(email, "read_qr_code", f"success: {status_msg}")
        return data, status_msg
    except Exception as e:
        log_action(email, "read_qr_code", f"failed: {str(e)}")
        raise