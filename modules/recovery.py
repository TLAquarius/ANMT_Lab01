import os
import json
import base64
from pathlib import Path
from modules.rsa_keys import generate_rsa_keypair, update_public_key_store, decrypt_user_private_key_with_recovery, derive_key, get_private_key_for_decryption
from modules.logger import log_action
from modules.auth import validate_passphrase
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

USERS_FILE = "./data/users.json"

def recovery_passphrase(email: str, recovery_code: str, new_passphrase: str) -> tuple[bool, str]:
    """Reset passphrase and re-encrypt or generate RSA private key."""
    try:
        # Load users
        try:
            with open(USERS_FILE, "r") as f:
                users = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            log_action(email, "recovery_passphrase", "failed: No users registered")
            return False, "Chưa có user"

        # Find user
        user = next((u for u in users if u["email"] == email), None)
        if not user:
            log_action(email, "recovery_passphrase", "failed: Email not found")
            return False, "Email không tồn tại"

        # Verify recovery code
        recovery_code_hash = base64.b64decode(user["recovery_code_hash"])
        recovery_salt = base64.b64decode(user["recovery_code_salt"])
        input_hash = derive_key(recovery_code, recovery_salt)
        if recovery_code_hash != input_hash:
            log_action(email, "recovery_passphrase", "failed: Invalid recovery code")
            return False, "Mã khôi phục không hợp lệ"

        # Validate new passphrase
        valid, error = validate_passphrase(new_passphrase)
        if not valid:
            log_action(email, "recovery_passphrase", f"failed: {error}")
            return False, error

        # Decrypt private key with recovery code
        success, private_key, message = decrypt_user_private_key_with_recovery(email, recovery_code)

        # Re-encrypt private key with new passphrase
        new_salt = os.urandom(16)
        new_hashed_passphrase = derive_key(new_passphrase, new_salt)
        if success and private_key:
            aes_key = derive_key(new_passphrase, new_salt)
            iv = os.urandom(12)
            aesgcm = AESGCM(aes_key)
            priv_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            priv_enc = aesgcm.encrypt(iv, priv_bytes, None)

            # Re-encrypt with new recovery code for future resets
            new_recovery_salt = os.urandom(16)
            recovery_aes_key = derive_key(recovery_code, new_recovery_salt)
            recovery_iv = os.urandom(12)
            recovery_aesgcm = AESGCM(recovery_aes_key)
            priv_enc_recovery = recovery_aesgcm.encrypt(recovery_iv, priv_bytes, None)

            # Update rsa_keypair.json
            safe_email = email.replace("@", "_at_").replace(".", "_dot_")
            key_path = f"./data/{safe_email}/rsa_keypair.json"
            with open(key_path, "r") as f:
                key_data = json.load(f)
            key_data.update({
                "private_key_enc": base64.b64encode(priv_enc).decode(),
                "salt": base64.b64encode(new_salt).decode(),
                "iv": base64.b64encode(iv).decode(),
                "private_key_enc_recovery": base64.b64encode(priv_enc_recovery).decode(),
                "recovery_salt": base64.b64encode(new_recovery_salt).decode(),
                "recovery_iv": base64.b64encode(recovery_iv).decode()
            })
            with open(key_path, "w") as f:
                json.dump(key_data, f, indent=4)
            log_action(email, "recovery_passphrase", "success: Re-encrypted existing key")
            # Update users.json with new passphrase hash and salt
            user["hashed_passphrase"] = base64.b64encode(new_hashed_passphrase).decode()
            user["salt"] = base64.b64encode(new_salt).decode()
            with open(USERS_FILE, "w") as f:
                json.dump(users, f, indent=4)
            update_public_key_store(email)
            return True, "Passphrase được đặt lại và RSA keys được khôi phục thành công"

        key_data = generate_rsa_keypair(email, new_passphrase, recovery_code, mode="renew")
        log_action(email, "recovery_passphrase", f"success: {message}. Generated new key")
        user["hashed_passphrase"] = base64.b64encode(new_hashed_passphrase).decode()
        user["salt"] = base64.b64encode(new_salt).decode()
        with open(USERS_FILE, "w") as f:
            json.dump(users, f, indent=4)

        update_public_key_store(email)
        return True, "Passphrase được đặt lại và RSA keys được tạo mới (key cũ không có recovery code)"

    except Exception as e:
        log_action(email, "recovery_passphrase", f"failed: {str(e)}")
        return False, f"Lỗi: {str(e)}"

def change_passphrase(email: str, old_passphrase: str, new_passphrase: str) -> tuple[bool, str]:
    """Change the user's passphrase by decrypting the private key with the old passphrase
    and re-encrypting it with the new passphrase. Update the passphrase hash in users.json."""
    try:

        # Load users.json to get user data
        users_file = Path("./data/users.json")
        with open(users_file, "r") as f:
            users = json.load(f)
        user = next((u for u in users if u["email"] == email), None)
        if not user:
            log_action(email, "change_passphrase", "failed: Email not found")
            return False, "Email not found"

        # Load rsa_keypair.json
        safe_email = email.replace("@", "_at_").replace(".", "_dot_")
        key_path = Path(f"./data/{safe_email}/rsa_keypair.json")
        with open(key_path, "r") as f:
            key_data = json.load(f)

        # Decrypt private key with old passphrase
        priv_enc = base64.b64decode(key_data["private_key_enc"])
        salt = base64.b64decode(key_data["salt"])
        iv = base64.b64decode(key_data["iv"])
        aes_key = derive_key(old_passphrase, salt)
        aesgcm = AESGCM(aes_key)
        priv_bytes = aesgcm.decrypt(iv, priv_enc, None)
        private_key = serialization.load_pem_private_key(priv_bytes, password=None)

        # Re-encrypt private key with new passphrase
        new_salt = os.urandom(16)
        new_aes_key = derive_key(new_passphrase, new_salt)
        new_iv = os.urandom(12)
        new_aesgcm = AESGCM(new_aes_key)
        new_priv_enc = new_aesgcm.encrypt(new_iv, priv_bytes, None)

        # Update key_data
        key_data.update({
            "private_key_enc": base64.b64encode(new_priv_enc).decode(),
            "salt": base64.b64encode(new_salt).decode(),
            "iv": base64.b64encode(new_iv).decode(),
        })

        # Save updated rsa_keypair.json
        with open(key_path, "w") as f:
            json.dump(key_data, f, indent=4)

        # Update users.json with new passphrase hash
        new_hashed_passphrase = derive_key(new_passphrase, new_salt)
        user["hashed_passphrase"] = base64.b64encode(new_hashed_passphrase).decode()
        user["salt"] = base64.b64encode(new_salt).decode()
        with open(users_file, "w") as f:
            json.dump(users, f, indent=4)

        log_action(email, "change_passphrase", "success")
        return True, "Passphrase changed successfully"

    except Exception as e:
        log_action(email, "change_passphrase", f"failed: {str(e)}")
        return False, f"Error: {str(e)}"