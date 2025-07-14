import json
from pathlib import Path
from datetime import datetime
import base64
from modules.logger import log_action

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
    import re
    if not re.match(email_pattern, search_email):
        log_action(current_user_email, "search_public_key", f"failed: Invalid email format {search_email}")
        return None, "Invalid email format", []

    # Check users.json first
    users_file = Path("./data/users.json")
    try:
        with open(users_file, "r") as f:
            users = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        log_action(current_user_email, "search_public_key", "failed: users.json not found or invalid")
        return None, "User database not found or invalid", []

    # Verify user exists
    email_exists = any(user["email"] == search_email for user in users)
    if not email_exists:
        similar_emails = [
            user["email"] for user in users
            if search_email.lower() in user["email"].lower() and user["email"] != search_email
        ]
        log_action(current_user_email, "search_public_key", f"failed: Email {search_email} not found")
        return None, f"Email {search_email} not found", similar_emails

    # Check public key file
    safe_email = search_email.replace("@", "_at_").replace(".", "_dot_")
    public_key_path = Path(f"./data/public_keys/{safe_email}.json")
    if not public_key_path.exists():
        log_action(current_user_email, "search_public_key", f"failed: No public key for {search_email}")
        return None, f"User {search_email} hasn't created public keys yet", []

    # Check if file is empty
    if public_key_path.stat().st_size == 0:
        log_action(current_user_email, "search_public_key", f"failed: Empty public key file for {search_email}")
        return None, f"User {search_email} hasn't created public keys yet", []

    # Load and validate key data
    try:
        with open(public_key_path, "r") as f:
            key_data = json.load(f)
    except json.JSONDecodeError:
        log_action(current_user_email, "search_public_key", f"failed: Invalid public key file for {search_email}")
        return None, f"User {search_email} hasn't created public keys yet", []

    # Validate key data (single dict)
    if not isinstance(key_data, dict) or not key_data:
        log_action(current_user_email, "search_public_key", f"failed: No valid public key data for {search_email}")
        return None, f"User {search_email} hasn't created public keys yet", []

    # Validate key fields
    required_fields = ["public_key", "created", "expires", "status", "email"]
    if not all(field in key_data for field in required_fields):
        log_action(current_user_email, "search_public_key", f"failed: Incomplete public key data for {search_email}")
        return None, f"User {search_email} hasn't created public keys yet", []

    # Validate data formats
    try:
        datetime.fromisoformat(key_data["created"])
        datetime.fromisoformat(key_data["expires"])
        base64.b64decode(key_data["public_key"])
    except (ValueError, TypeError) as e:
        log_action(current_user_email, "search_public_key", f"failed: Invalid public key data for {search_email} - {str(e)}")
        return None, f"User {search_email} hasn't created public keys yet", []

    log_action(current_user_email, "search_public_key", f"success: Found public key for {search_email}")
    return key_data, f"Public key found for {search_email}", []