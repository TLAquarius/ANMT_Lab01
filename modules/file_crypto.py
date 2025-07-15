import json
from pathlib import Path
import base64
import os
from datetime import datetime
from zoneinfo import ZoneInfo
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from modules.rsa_keys import load_current_public_key, get_private_key_for_decryption
from modules.logger import log_action
import hashlib

# Constants
BLOCK_SIZE = 1024 * 1024  # 1MB
FILE_SIZE_THRESHOLD = 5 * 1024 * 1024  # 5MB

def encrypt_file_with_metadata(input_path: str, recipient_email: str, sender_email: str, split_key: bool = False) -> tuple[str, str | None]:
    """Encrypt a file and its metadata with block-based encryption and optional key splitting."""
    try:
        # Validate input file
        input_file = Path(input_path)
        if not input_file.exists():
            raise ValueError(f"File {input_path} không tồn tại")

        # Load recipient's public key
        try:
            public_key = load_current_public_key(recipient_email)
        except Exception as e:
            log_action(sender_email, "Mã hóa file", f"Failed: Người nhận {recipient_email} không có public key hợp lệ - {str(e)}")
            raise ValueError(f"Người nhận {recipient_email} không có public key hợp lệ")

        # Generate AES session key
        ksession = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(ksession)

        # Encrypt session key with RSA
        ksession_encrypted = public_key.encrypt(
            ksession,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Create metadata
        metadata = {
            "sender_email": sender_email,
            "recipient_email": recipient_email,
            "file_name": input_file.name,
            "timestamp": datetime.now(ZoneInfo("Asia/Ho_Chi_Minh")).isoformat()
        }

        # Encrypt metadata
        metadata_bytes = json.dumps(metadata).encode()
        metadata_iv = os.urandom(12)
        metadata_ciphertext = aesgcm.encrypt(metadata_iv, metadata_bytes, None)
        metadata_auth_tag = metadata_ciphertext[-16:]  # Last 16 bytes are the GCM auth tag
        metadata_ciphertext = metadata_ciphertext[:-16]  # Remove auth tag from ciphertext

        # Read and encrypt file in blocks
        blocks = []
        file_size = input_file.stat().st_size
        with open(input_file, "rb") as f:
            index = 0
            while True:
                block = f.read(BLOCK_SIZE if file_size > FILE_SIZE_THRESHOLD else file_size)
                if not block:
                    break
                iv = os.urandom(12)
                ciphertext = aesgcm.encrypt(iv, block, None)
                auth_tag = ciphertext[-16:]  # Last 16 bytes are the GCM auth tag
                ciphertext = ciphertext[:-16]  # Remove auth tag from ciphertext
                blocks.append({
                    "index": index,
                    "iv": base64.b64encode(iv).decode(),
                    "ciphertext": base64.b64encode(ciphertext).decode(),
                    "auth_tag": base64.b64encode(auth_tag).decode()
                })
                index += 1
                log_action(sender_email, "Mã hóa File", f"Success: Đã mã block {index} của file {input_file.name}")

        # Create output paths
        safe_recipient_email = recipient_email.replace("@", "_at_").replace(".", "_dot_")
        storage_dir = Path(f"data/{safe_recipient_email}/storage/")
        storage_dir.mkdir(parents=True, exist_ok=True)

        salt = os.urandom(16)  # 128-bit random salt
        hasher = hashlib.sha256()
        hasher.update(salt + (input_file.name).encode('utf-8'))
        hashed_file_name = hasher.hexdigest()

        enc_path = storage_dir / f"{hashed_file_name}.enc"

        # Create .enc file package
        enc_package = {
            "encrypted_metadata": {
                "iv": base64.b64encode(metadata_iv).decode(),
                "ciphertext": base64.b64encode(metadata_ciphertext).decode(),
                "auth_tag": base64.b64encode(metadata_auth_tag).decode()
            },
            "blocks": blocks
        }
        if not split_key:
            enc_package["encrypted_session_key"] = base64.b64encode(ksession_encrypted).decode()

        # Write .enc file
        with open(enc_path, "w") as f:
            json.dump(enc_package, f, indent=4)

        # Write .key file if split_key is True
        key_path = None
        if split_key:
            key_path = storage_dir / f"{hashed_file_name}.key"
            key_package = {
                "encrypted_metadata": {
                    "iv": base64.b64encode(metadata_iv).decode(),
                    "ciphertext": base64.b64encode(metadata_ciphertext).decode(),
                    "auth_tag": base64.b64encode(metadata_auth_tag).decode()
                },
                "encrypted_session_key": base64.b64encode(ksession_encrypted).decode()
            }
            with open(key_path, "w") as f:
                json.dump(key_package, f, indent=4)
            log_action(sender_email, "Mã hóa file", f"Success: {enc_path}, key: {key_path}")
            return str(enc_path), str(key_path)

        log_action(sender_email, "Mã hóa file", f"Success: {enc_path}")
        return str(enc_path), None

    except ValueError as e:
        log_action(sender_email, "Mã hóa file", f"Failed: {str(e)}")
        raise
    except Exception as e:
        log_action(sender_email, "Mã hóa file", f"Failed: Không rõ nguyên nhân - {str(e)}")
        raise

def decrypt_file(enc_path: str, passphrase: str, recipient_email: str) -> tuple[str, dict]:
    """Decrypt a file and its metadata, auto-detecting .key file if present.

    Args:
        enc_path: Path to the .enc file.
        passphrase: Passphrase to decrypt the private key.
        recipient_email: Email of the recipient (for private key lookup).

    Returns:
        (output_path, metadata): Path to decrypted file and its metadata.

    Raises:
        ValueError: For invalid files, passphrase, or key.
        Exception: For other decryption errors.
    """
    try:
        # Validate .enc file
        enc_file = Path(enc_path)
        if not enc_file.exists():
            raise ValueError(f"File cần giải mã {enc_path} không tồn tại")

        # Load .enc file
        with open(enc_file, "r") as f:
            enc_package = json.load(f)

        # Load .key file if provided, else get key from .enc
        key_path = enc_file.with_suffix(".key")
        if key_path.exists():
            with open(key_path, "r") as f:
                key_package = json.load(f)
            encrypted_ksession = base64.b64decode(key_package["encrypted_session_key"])
            key_metadata = key_package.get("metadata", {})
        else:
            if "encrypted_session_key" not in enc_package:
                raise ValueError("No session key found in .enc file and no .key file provided")
            encrypted_ksession = base64.b64decode(enc_package["encrypted_session_key"])
            key_metadata = {}

        # Decrypt private key
        metadata_timestamp = key_metadata.get("timestamp", datetime.now(ZoneInfo("Asia/Ho_Chi_Minh")).isoformat())
        try:
            private_key = get_private_key_for_decryption(recipient_email, passphrase, metadata_timestamp)
        except Exception as e:
            raise ValueError(f"Giải mã private key thất bại - {str(e)}")

        # Decrypt AES session key
        ksession = private_key.decrypt(
            encrypted_ksession,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        aesgcm = AESGCM(ksession)

        # Decrypt metadata
        if "encrypted_metadata" not in enc_package:
            raise ValueError("Không tìm thấy metadata trong file .enc")
        metadata_enc = enc_package["encrypted_metadata"]
        metadata_iv = base64.b64decode(metadata_enc["iv"])
        metadata_ciphertext = base64.b64decode(metadata_enc["ciphertext"])
        metadata_auth_tag = base64.b64decode(metadata_enc["auth_tag"])
        metadata_bytes = aesgcm.decrypt(metadata_iv, metadata_ciphertext + metadata_auth_tag, None)
        try:
            metadata = json.loads(metadata_bytes.decode())
        except json.JSONDecodeError:
            raise ValueError("Định dạng metadata sau khi giải mã không hợp lệ")

        # Validate metadata
        required_fields = ["sender_email", "recipient_email", "file_name", "timestamp"]
        if not all(k in metadata for k in required_fields):
            raise ValueError("Định dạng metadata sau khi giải mã không hợp lệ")

        # Verify all blocks are present
        blocks = sorted(enc_package["blocks"], key=lambda x: x["index"])
        expected_indices = set(range(len(blocks)))
        actual_indices = set(block["index"] for block in blocks)
        if expected_indices != actual_indices:
            raise ValueError(f"Thiếu block hay block bị lập lại")

        # Decrypt blocks
        plaintext = b""
        for block in blocks:
            iv = base64.b64decode(block["iv"])
            ciphertext = base64.b64decode(block["ciphertext"])
            auth_tag = base64.b64decode(block["auth_tag"])
            block_data = aesgcm.decrypt(iv, ciphertext + auth_tag, None)
            plaintext += block_data

        # Save decrypted file
        safe_recipient_email = recipient_email.replace("@", "_at_").replace(".", "_dot_")
        output_dir = Path(f"data/{safe_recipient_email}/storage")
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / metadata["file_name"]
        with open(output_path, "wb") as f:
            f.write(plaintext)

        # Save metadata
        metadata_path = output_dir / f"{metadata['file_name']}_metadata.json"
        with open(metadata_path, "w") as f:
            json.dump(metadata, f, indent=4)

        log_action(recipient_email, "Giải mã File", f"Success: {output_path}, metadata: {metadata_path}")
        return str(output_path), metadata

    except ValueError as e:
        log_action(recipient_email, "Giải mã File", f"Failed: {str(e)}")
        raise
    except Exception as e:
        log_action(recipient_email, "Giải mã File", f"Failed: Không rõ lỗi - {str(e)}")
        raise