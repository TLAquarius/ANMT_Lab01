import json
from datetime import datetime
from zoneinfo import ZoneInfo
from modules.logger import log_action
from pathlib import Path

PUBLIC_KEY_DIR = Path("./data/public_keys")

def update_key_status(key_data, now):
    """Update the status of a key based on its expiration and current time."""
    expires = datetime.fromisoformat(key_data["expires"])
    valid_days = (expires - now).days
    if valid_days < 0:
        key_data["status"] = "Hết hạn"
    elif valid_days <= 30:
        key_data["status"] = "Gần hết hạn"
    else:
        key_data["status"] = "Còn hạn"
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
        log_action(email, "Update trạng thái và kho public key", f"Success: Update cho {email}")
    except (FileNotFoundError, json.JSONDecodeError) as e:
        log_action(email, "Update trạng thái và kho public key", f"Failed: {str(e)}")
        if public_key_path.exists():
            public_key_path.unlink()