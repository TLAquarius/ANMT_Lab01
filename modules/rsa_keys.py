import os
import json
import base64
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from modules.logger import log_action

PUBLIC_KEY_DIR = "./data/public_keys"
def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derives AES key from passphrase using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000,
    )
    return kdf.derive(passphrase.encode())


def archive_old_key(email: str, current_key_data: dict):
    """Archive an expired key pair to archived_keys.json."""
    archive_path = f"./data/{email}/archived_keys.json"
    os.makedirs(f"./data/{email}", exist_ok=True)

    # Load existing archived keys or initialize empty list
    try:
        with open(archive_path, "r") as f:
            archived_keys = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        archived_keys = []

    # Add the current key to the archive
    archived_keys.append(current_key_data)

    # Save updated archive
    with open(archive_path, "w") as f:
        json.dump(archived_keys, f, indent=4)

def generate_rsa_keypair(email: str, passphrase: str, recovery_code: str = None, mode="create") -> dict:
    """Generate RSA key pair with dual encryption (passphrase + recovery code)."""
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    key_path = f"./data/{safe_email}/rsa_keypair.json"
    os.makedirs(f"./data/{safe_email}", exist_ok=True)

    # Check if a key pair already exists
    current_key_data = None
    try:
        with open(key_path, "r") as f:
            current_key_data = json.load(f)
            if mode == "extend":
                current_key_data["renew"] = datetime.now(ZoneInfo("Asia/Ho_Chi_Minh")).isoformat()
                current_key_data["expires"] = (datetime.now(ZoneInfo("Asia/Ho_Chi_Minh")) + timedelta(days=90)).isoformat()
                current_key_data["status"] = "in used"
                with open(key_path, "w") as f:
                    json.dump(current_key_data, f, indent=4)
                return current_key_data  # Return existing key if not expired
            elif mode == "renew":
                # Archive expired key
                if(datetime.fromisoformat(current_key_data["expires"]) > datetime.now(ZoneInfo("Asia/Ho_Chi_Minh"))):
                    current_key_data["status"] = "revoked"
                else:
                    current_key_data["status"] = "expired"
                    archive_old_key(email, current_key_data)
    except (FileNotFoundError, json.JSONDecodeError):
        pass  # No existing key, proceed to generate new one

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
    key_data = {
        "public_key": base64.b64encode(pub_bytes).decode(),
        "private_key_enc": base64.b64encode(priv_enc).decode(),
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode(),
        "created": datetime.now(ZoneInfo("Asia/Ho_Chi_Minh")).isoformat(),
        "expires": (datetime.now(ZoneInfo("Asia/Ho_Chi_Minh")) + timedelta(days=90)).isoformat(),
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

    # Save new key pair
    with open(key_path, "w") as f:
        json.dump(key_data, f, indent=4)

    return key_data


def update_public_key_store(email: str):
    """Update public key store with current and archived keys for the user."""
    os.makedirs(PUBLIC_KEY_DIR, exist_ok=True)
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    public_key_path = f"{PUBLIC_KEY_DIR}/{safe_email}.json"

    # Load current key
    try:
        with open(f"./data/{safe_email}/rsa_keypair.json", "r") as f:
            key_data = json.load(f)
            public_keys = [{
                "public_key": key_data["public_key"],
                "created": key_data["created"],
                "expires": key_data["expires"],
                "status": key_data["status"],
                "email": email
            }]
    except (FileNotFoundError, json.JSONDecodeError):
        public_keys = []

    # Load archived keys
    try:
        with open(f"./data/{safe_email}/archived_keys.json", "r") as f:
            archived_keys = json.load(f)
            for key_data in archived_keys:
                public_keys.append({
                    "public_key": key_data["public_key"],
                    "created": key_data["created"],
                    "expires": key_data["expires"],
                    "status": key_data["status"],
                    "email": email
                })
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    # Save to public key store
    with open(public_key_path, "w") as f:
        json.dump(public_keys, f, indent=4)

def load_public_key_from_file(recipient_email):
    """Load recipient's RSA public key from file."""
    try:
        with open(f"./data/{recipient_email}/rsa_keypair.json", "r") as f:
            key_data = json.load(f)
        public_pem = base64.b64decode(key_data["public_key"])
        public_key = serialization.load_pem_public_key(public_pem)
        return public_key
    except Exception as e:
        log_action(recipient_email, "load_public_key", f"failed: {str(e)}")
        raise

def get_private_key_for_decryption(email: str, passphrase: str, message_timestamp: str) -> object:
    """Retrieve the appropriate private key for decrypting a message based on its timestamp."""
    key_path = f"./data/{email}/rsa_keypair.json"
    archive_path = f"./data/{email}/archived_keys.json"
    message_time = datetime.fromisoformat(message_timestamp)

    # Try current key first
    try:
        with open(key_path, "r") as f:
            key_data = json.load(f)
            key_created = datetime.fromisoformat(key_data["created"])
            key_expires = datetime.fromisoformat(key_data["expires"])
            # Check if the key was valid at the time the message was created
            if key_created <= message_time <= key_expires:
                priv_enc = base64.b64decode(key_data["private_key_enc"])
                salt = base64.b64decode(key_data["salt"])
                iv = base64.b64decode(key_data["iv"])
                aes_key = derive_key(passphrase, salt)
                aesgcm = AESGCM(aes_key)
                priv_bytes = aesgcm.decrypt(iv, priv_enc, None)
                return serialization.load_pem_private_key(priv_bytes, password=None)
    except (FileNotFoundError, json.JSONDecodeError, ValueError):
        pass

    # Try archived keys
    try:
        with open(archive_path, "r") as f:
            archived_keys = json.load(f)
            for key_data in archived_keys:
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
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    raise ValueError("No valid private key found for the message's timestamp")

def decrypt_user_private_key_with_recovery(email: str, recovery_code: str) -> object:
    """Decrypt the user's current RSA private key using recovery code."""
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")
    key_path = f"./data/{safe_email}/rsa_keypair.json"
    try:
        with open(key_path, "r") as f:
            key_data = json.load(f)
        
        # Check if recovery encryption is available
        if "private_key_enc_recovery" not in key_data:
            raise ValueError("Recovery decryption not available for this key")
        
        priv_enc = base64.b64decode(key_data["private_key_enc_recovery"])
        salt = base64.b64decode(key_data["recovery_salt"])
        iv = base64.b64decode(key_data["recovery_iv"])
        
        # Derive the AES key using the recovery code and stored salt
        aes_key = derive_key(recovery_code, salt)
        aesgcm = AESGCM(aes_key)
        priv_bytes = aesgcm.decrypt(iv, priv_enc, None)
        
        return serialization.load_pem_private_key(priv_bytes, password=None)
    except Exception as e:
        raise ValueError(f"Failed to decrypt private key with recovery code: {str(e)}")

if __name__ == "__main__":
    generate_rsa_keypair("test@gmail", "test")