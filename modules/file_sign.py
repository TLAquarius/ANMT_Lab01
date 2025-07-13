import os
import json
import base64
from datetime import datetime
from zoneinfo import ZoneInfo
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from modules.rsa_keys import get_private_key_for_decryption, update_public_key_store, PUBLIC_KEY_DIR
from modules.logger import log_action

LOG_FILE = "../data/security.log"
SIGNATURE_DIR = "../data/signatures"

def sign_file(file_path: str, email: str, passphrase: str, output_dir: str = SIGNATURE_DIR):
    """Sign a file and create a .sig file with metadata."""
    try:
        # Get private key
        timestamp = datetime.now(ZoneInfo("Asia/Ho_Chi_Minh")).isoformat()
        private_key = get_private_key_for_decryption(email, passphrase, timestamp)

        # Read and hash file
        with open(file_path, "rb") as f:
            data = f.read()
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        file_hash = digest.finalize()

        # Sign hash
        signature = private_key.sign(
            file_hash,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        # Create signature file
        sig_data = {
            "signature": base64.b64encode(signature).decode(),
            "metadata": {
                "signer_email": email,
                "file_name": os.path.basename(file_path),
                "timestamp": timestamp,
                "hash_algorithm": "SHA-256",
                "signature_algorithm": "RSA-PKCS1v15"
            }
        }

        # Save .sig file
        os.makedirs(output_dir, exist_ok=True)
        sig_path = os.path.join(output_dir, f"{os.path.basename(file_path)}.sig")
        with open(sig_path, "w") as f:
            json.dump(sig_data, f, indent=4)

        # Update public key store
        update_public_key_store(email)

        log_action(email, "sign_file", f"success: {sig_path}")
        print(f"✅ Signature saved: {sig_path}")
        return sig_path

    except Exception as e:
        log_action(email, "sign_file", f"failed: {str(e)}")
        raise


def verify_signature(file_path: str, sig_path: str) -> dict:
    """Verify a file's signature against all stored public keys."""
    try:
        # Load signature file
        with open(sig_path, "r") as f:
            sig_data = json.load(f)
        signature = base64.b64decode(sig_data["signature"])
        signer_email = sig_data["metadata"]["signer_email"]
        timestamp = sig_data["metadata"]["timestamp"]

        # Read and hash file
        with open(file_path, "rb") as f:
            data = f.read()
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        file_hash = digest.finalize()

        # Load all public keys
        found_valid = False
        result = {"valid": False, "signer_email": None, "timestamp": None, "error": None}

        for pub_key_file in os.listdir(PUBLIC_KEY_DIR):
            try:
                with open(f"{PUBLIC_KEY_DIR}/{pub_key_file}", "r") as f:
                    public_keys = json.load(f)
                for key_data in public_keys:
                    public_key = serialization.load_pem_public_key(
                        base64.b64decode(key_data["public_key"])
                    )
                    try:
                        public_key.verify(
                            signature,
                            file_hash,
                            padding.PKCS1v15(),
                            hashes.SHA256()
                        )
                        # Check if key was valid at signing time
                        key_created = datetime.fromisoformat(key_data["created"])
                        key_expires = datetime.fromisoformat(key_data["expires"])
                        sign_time = datetime.fromisoformat(timestamp)
                        if key_created <= sign_time <= key_expires:
                            found_valid = True
                            result = {
                                "valid": True,
                                "signer_email": key_data["email"],
                                "timestamp": timestamp,
                                "error": None
                            }
                            break
                    except Exception:
                        continue
                if found_valid:
                    break
            except (FileNotFoundError, json.JSONDecodeError):
                continue

        if not found_valid:
            result["error"] = "No valid public key found to verify the signature"

        log_action(signer_email, "verify_signature", f"{'success' if found_valid else 'failed'}: {file_path}")
        if found_valid:
            print(f"✅ Signature verified: Signed by {result['signer_email']} at {result['timestamp']}")
        else:
            print(f"❌ Signature verification failed: {result['error']}")
        return result

    except Exception as e:
        log_action(signer_email, "verify_signature", f"failed: {str(e)}")
        raise

if __name__ == "__main__":
    # Sign a file
    sign_file(
        "../data/ComputerSecurity_PRJ1.pdf",
        "test@gmail",
        "test",
        "../data/signatures"
    )

    # Verify the signature
    verify_signature(
        "../data/ComputerSecurity_PRJ1.pdf",
        "../data/signatures/ComputerSecurity_PRJ1.pdf.sig"
    )