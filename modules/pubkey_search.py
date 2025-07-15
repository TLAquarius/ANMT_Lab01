import json
from pathlib import Path
from datetime import datetime
import base64
from modules.logger import log_action
import re

def search_public_key(current_user_email: str, search_email: str) -> tuple[dict | None, str, list]:
    """Search for a user's current public key by email, checking users.json first.

    Args:
        current_user_email: Email of the current user (for logging).
        search_email: Email to search for.

    Returns:
        - (key_data, success_message, []): If a valid key is found.
        - (None, error_message, similar_emails): If user or key not found, or key is invalid/empty.
    """
    # Validate email format
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, search_email):
        log_action(current_user_email, "Tìm kiếm public key", f"Thất bại: Email không đúng định dạng - {search_email}")
        return None, "Email không đúng định dạng", []

    # Check users.json first
    users_file = Path("./data/users.json")
    try:
        with open(users_file, "r") as f:
            users = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        log_action(current_user_email, "Tìm kiếm public key", "Thất bại: Không tìm thấy users.json hoặc dữ liệu bị lỗi")
        return None, "Không thể đọc dữ liệu người dùng (users.json)", []

    # Verify user exists
    email_exists = any(user["email"] == search_email for user in users)
    if not email_exists:
        similar_emails = [
            user["email"] for user in users
            if search_email.lower() in user["email"].lower() and user["email"] != search_email
        ]
        log_action(current_user_email, "Tìm kiếm public key", f"Failed: Không tìm thấy email {search_email}")
        return None, f"Không tìm thấy người dùng với email {search_email}", similar_emails

    # Check public key file
    safe_email = search_email.replace("@", "_at_").replace(".", "_dot_")
    public_key_path = Path(f"./data/public_keys/{safe_email}.json")
    if not public_key_path.exists():
        log_action(current_user_email, "Tìm kiếm public key", f"Failed: Không có public key cho {search_email}")
        return None, f"Người dùng {search_email} chưa tạo public key", []

    # Check if file is empty
    if public_key_path.stat().st_size == 0:
        log_action(current_user_email, "Tìm kiếm public key", f"Failed: File public key trống - {search_email}")
        return None, f"Người dùng {search_email} chưa tạo public key", []

    # Load and validate key data
    try:
        with open(public_key_path, "r") as f:
            key_data = json.load(f)
    except json.JSONDecodeError:
        log_action(current_user_email, "Tìm kiếm public key", f"Failed: File public key bị lỗi - {search_email}")
        return None, f"Người dùng {search_email} chưa tạo public key hợp lệ", []

    # Validate key data (single dict)
    if not isinstance(key_data, dict) or not key_data:
        log_action(current_user_email, "Tìm kiếm public key",f"Failed: Dữ liệu public key không hợp lệ - {search_email}")
        return None, f"Người dùng {search_email} chưa tạo public key hợp lệ", []

    # Validate key fields
    required_fields = ["public_key", "created", "expires", "status", "email"]
    if not all(field in key_data for field in required_fields):
        log_action(current_user_email, "Tìm kiếm public key",f"Failed: Dữ liệu public key thiếu thông tin - {search_email}")
        return None, f"Người dùng {search_email} chưa tạo public key đầy đủ thông tin", []

    # Validate data formats
    try:
        datetime.fromisoformat(key_data["created"])
        datetime.fromisoformat(key_data["expires"])
        base64.b64decode(key_data["public_key"])
    except (ValueError, TypeError) as e:
        log_action(current_user_email, "Tìm kiếm public key",f"Failed: Dữ liệu public key không hợp lệ - {search_email} - {str(e)}")
        return None, f"Public key của {search_email} không hợp lệ", []

    # Successful
    log_action(current_user_email, "Tìm kiếm public key", f"Success: Tìm thấy public key của {search_email}")
    return key_data, f"Tìm thấy public key của {search_email}", []