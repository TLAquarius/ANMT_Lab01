import json
from zoneinfo import ZoneInfo
from datetime import datetime
LOG_FILE = "../data/security.log"
def log_action(email, action, status):
    """Log security events to security.log."""
    timestamp = datetime.now(ZoneInfo("Asia/Ho_Chi_Minh")).isoformat()
    log_entry = {
        "timestamp": timestamp,
        "email": email,
        "action": action,
        "status": status
    }
    with open(LOG_FILE, "a") as f:
        json.dump(log_entry, f)
        f.write("\n")