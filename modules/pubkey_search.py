import json
from pathlib import Path
from datetime import datetime
import base64
from modules.logger import log_action

def search_public_key(current_user_email: str, search_email: str) -> tuple[dict | None, str, list]:
    """Search for a user's public key by email.

    Args:
        current_user_email: Email of the current user (for logging).
        search_email: Email to search for.

    Returns:
        - (key_data, success_message, []) if a valid key is found.
        - (None, error_message, similar_emails) if user/key not found or invalid.
    """
    # Validate email format
    import re
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, search_email):
        log_action(current_user_email, "search_public_key", f"failed: Invalid email format {search_email}")
        return None, "Invalid email format", []

    # Convert to safe_email
    safe_email = search_email.replace("@", "_at_").replace(".", "_dot_")
    public_key_path = Path(f"data/public_keys/{safe_email}.json")
    users_file = Path("data/users.json")

    # Check if email exists in users.json
    try:
        with open(users_file, "r") as f:
            users = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        log_action(current_user_email, "search_public_key", f"failed: users.json error - {str(e)}")
        return None, "User database not found or invalid", []

    email_exists = any(user["email"] == search_email for user in users)
    if not email_exists:
        # Find similar emails (case-insensitive substring match)
        similar_emails = [
            user["email"] for user in users
            if search_email.lower() in user["email"].lower() and user["email"] != search_email
        ][:5]  # Limit to 5 suggestions
        log_action(current_user_email, "search_public_key", f"failed: Email {search_email} not found")
        return None, f"No user found with email {search_email}", similar_emails

    # Check public key file
    if not public_key_path.exists():
        log_action(current_user_email, "search_public_key", f"failed: No public key for {search_email}")
        return None, f"User {search_email} doesn't have any public key", []

    # Check if file is empty
    if public_key_path.stat().st_size == 0:
        log_action(current_user_email, "search_public_key", f"failed: Empty public key file for {search_email}")
        return None, f"User {search_email} doesn't have any public key", []

    # Load key data
    try:
        with open(public_key_path, "r") as f:
            key_data = json.load(f)
    except json.JSONDecodeError as e:
        log_action(current_user_email, "search_public_key", f"failed: Invalid public key file for {search_email} - {str(e)}")
        return None, f"User {search_email} doesn't have any public key", []

    # Handle key data (first entry if a list)
    if isinstance(key_data, list) and len(key_data) > 0:
        key_info = key_data[0]
    elif isinstance(key_data, dict) and key_data:
        key_info = key_data
    else:
        log_action(current_user_email, "search_public_key", f"failed: No valid public key data for {search_email}")
        return None, f"User {search_email} doesn't have any public key", []

    # Validate key fields
    required_fields = ["public_key", "created", "expires", "status"]
    if not all(field in key_info for field in required_fields):
        log_action(current_user_email, "search_public_key", f"failed: Incomplete public key data for {search_email}")
        return None, f"User {search_email} doesn't have any public key", []

    # Validate data formats
    try:
        datetime.fromisoformat(key_info["created"])
        datetime.fromisoformat(key_info["expires"])
        base64.b64decode(key_info["public_key"])
    except (ValueError, TypeError) as e:
        log_action(current_user_email, "search_public_key", f"failed: Invalid public key data for {search_email} - {str(e)}")
        return None, f"User {search_email} doesn't have any public key", []

    log_action(current_user_email, "search_public_key", f"success: Found public key for {search_email}")
    return key_info, f"Public key found for {search_email}", []