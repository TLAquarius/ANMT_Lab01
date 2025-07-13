import os
import json
import base64
from datetime import datetime
from zoneinfo import ZoneInfo
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from rsa_keys import load_public_key_from_file, get_private_key_for_decryption
from logger import log_action
# Constants
BLOCK_SIZE = 1024 * 1024  # 1MB
FILE_SIZE_THRESHOLD = 5 * 1024 * 1024  # 5MB


def encrypt_file_with_metadata(input_path, output_path, sender_email, recipient_email, split_key=False):
    """Encrypt a file with block-based encryption and optional key splitting."""
    try:
        # Load recipient's public key
        public_key = load_public_key_from_file(recipient_email)

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
            "file_name": os.path.basename(input_path),
            "timestamp": datetime.now(ZoneInfo("Asia/Ho_Chi_Minh")).isoformat(),
            "encryption_algorithm": "AES-256-GCM",
            "block_size": BLOCK_SIZE
        }

        # Read and encrypt file in blocks
        blocks = []
        file_size = os.path.getsize(input_path)
        with open(input_path, "rb") as f:
            index = 0
            while True:
                block = f.read(BLOCK_SIZE)
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

        # Create .enc file package
        enc_package = {
            "metadata": metadata,
            "blocks": blocks
        }
        if not split_key:
            enc_package["encrypted_session_key"] = base64.b64encode(ksession_encrypted).decode()

        # Write .enc file
        with open(output_path, "w") as f:
            json.dump(enc_package, f, indent=4)

        # Write .key file if split_key is True
        if split_key:
            key_package = {
                "metadata": {
                    "sender_email": sender_email,
                    "recipient_email": recipient_email,
                    "file_name": os.path.basename(input_path),
                    "timestamp": metadata["timestamp"]
                },
                "encrypted_session_key": base64.b64encode(ksession_encrypted).decode()
            }
            key_path = output_path.replace(".enc", ".key")
            with open(key_path, "w") as f:
                json.dump(key_package, f, indent=4)
            log_action(sender_email, "encrypt_file", f"success: {output_path}, key: {key_path}")
        else:
            log_action(sender_email, "encrypt_file", f"success: {output_path}")

        print(f"✅ Encrypted file saved: {output_path}")
        if split_key:
            print(f"✅ Key file saved: {key_path}")

    except Exception as e:
        log_action(sender_email, "encrypt_file", f"failed: {str(e)}")
        raise

def decrypt_file(enc_path, passphrase, recipient_email, output_dir="../data/decrypted", key_path=None):
    """Decrypt a file using block-based decryption, supporting split .key file."""
    try:
        # Load .enc file
        with open(enc_path, "r") as f:
            enc_package = json.load(f)

        # Load .key file if provided, else get key from .enc
        if key_path:
            with open(key_path, "r") as f:
                key_package = json.load(f)
            encrypted_ksession = base64.b64decode(key_package["encrypted_session_key"])
        else:
            encrypted_ksession = base64.b64decode(enc_package["encrypted_session_key"])


        # Decrypt private key
        private_key = get_private_key_for_decryption(recipient_email, passphrase, enc_package["metadata"]["timestamp"])

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

        # Decrypt blocks
        plaintext = b""
        for block in sorted(enc_package["blocks"], key=lambda x: x["index"]):
            iv = base64.b64decode(block["iv"])
            ciphertext = base64.b64decode(block["ciphertext"])
            auth_tag = base64.b64decode(block["auth_tag"])
            block_data = aesgcm.decrypt(iv, ciphertext + auth_tag, None)
            plaintext += block_data

        # Save decrypted file
        metadata = enc_package["metadata"]
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, metadata["file_name"])
        with open(output_path, "wb") as f:
            f.write(plaintext)

        log_action(recipient_email, "decrypt_file", f"success: {output_path}")
        print(f"✅ File decrypted: {output_path}")
        print("🔐 Metadata:")
        for k, v in metadata.items():
            print(f"  {k}: {v}")

    except Exception as e:
        log_action(recipient_email, "decrypt_file", f"failed: {str(e)}")
        raise

# Example usage
if __name__ == "__main__":
    # Example with single .enc file
    encrypt_file_with_metadata(
        "../data/test-34.pdf",
        "../data/encrypted.enc",
        "test@gmail",
        "test@gmail",
        split_key=False
    )
    decrypt_file(
        "../data/encrypted.enc",
        "test",
        "test@gmail",
        "../data/decrypted"
    )

    # Example with separate .enc and .key files
    encrypt_file_with_metadata(
        "../data/test-34.pdf",
        "../data/encrypted_split.enc",
        "test@gmail",
        "test@gmail",
        split_key=True
    )
    decrypt_file(
        "../data/encrypted_split.enc",
        "test",
        "test@gmail",
        "../data/decrypted",
        key_path="../data/encrypted_split.key"
    )