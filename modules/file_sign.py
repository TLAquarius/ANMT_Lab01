import json
import base64
from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from modules.rsa_keys import get_active_private_key
from modules.logger import log_action

# Thư mục chứa các public key đã được lưu
PUBLIC_KEYS_DIR = Path("./data/public_keys")

def sign_file(file_path: str, signer_email: str, passphrase: str) -> tuple[bool, str, str]:
    """
    Ký một tệp bằng khóa riêng của người dùng và tạo tệp chữ ký .sig.
    Hàm này sẽ thất bại nếu passphrase không chính xác, khóa hết hạn hoặc không tồn tại.

    Args:
        file_path: Đường dẫn đến tệp cần ký.
        signer_email: Email của người ký.
        passphrase: Mật khẩu để giải mã khóa riêng.

    Returns:
        (success, message, signature_path)
    """
    try:
        input_file = Path(file_path)
        if not input_file.exists():
            raise FileNotFoundError(f"Tệp không tồn tại: {file_path}")

        # Lấy khóa riêng để ký. Hàm này sẽ ném ra ValueError nếu có lỗi.
        private_key = get_active_private_key(signer_email, passphrase)

        # Đọc và băm nội dung tệp
        with open(input_file, "rb") as f:
            data_to_sign = f.read()
        file_hash = hashes.Hash(hashes.SHA256())
        file_hash.update(data_to_sign)
        digest = file_hash.finalize()

        # Ký vào chuỗi hash
        signature = private_key.sign(
            digest,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        # Chuẩn bị dữ liệu cho tệp .sig
        timestamp = datetime.now(ZoneInfo("Asia/Ho_Chi_Minh")).isoformat()
        sig_data = {
            "signature": base64.b64encode(signature).decode('utf-8'),
            "metadata": {
                "signer_email": signer_email,
                "original_filename": input_file.name,
                "timestamp": timestamp,
                "hash_algorithm": "SHA-256",
                "signature_algorithm": "RSA-PKCS1v15"
            }
        }

        # Lưu tệp .sig
        safe_email = signer_email.replace("@", "_at_").replace(".", "_dot_")
        signature_dir = Path(f"./data/{safe_email}/signatures")
        signature_dir.mkdir(parents=True, exist_ok=True)
        signature_path = signature_dir / f"{input_file.name}.sig"

        with open(signature_path, "w") as f:
            json.dump(sig_data, f, indent=4)

        log_action(signer_email, "sign_file", f"success: Signed {input_file.name}, saved to {signature_path}")
        return True, f"Tệp đã được ký thành công! Chữ ký được lưu tại:\n{signature_path}", str(signature_path)

    except (ValueError, FileNotFoundError) as e:
        # Bắt các lỗi đã biết (passphrase sai, khóa hết hạn, tệp không tồn tại, v.v.)
        log_action(signer_email, "sign_file", f"failed: {str(e)}")
        return False, f"Lỗi khi ký tệp: {str(e)}", ""
    except Exception as e:
        # Bắt các lỗi không mong muốn khác
        log_action(signer_email, "sign_file", f"failed: Unexpected error - {str(e)}")
        return False, f"Lỗi không mong muốn đã xảy ra: {str(e)}", ""

def verify_signature(original_file_path: str, signature_file_path: str, verifier_email: str) -> dict:
    """
    Xác minh chữ ký của một tệp bằng cách sử dụng tất cả các public key đã lưu.

    Args:
        original_file_path: Đường dẫn đến tệp gốc.
        signature_file_path: Đường dẫn đến tệp .sig.
        verifier_email: Email của người thực hiện xác minh (để ghi log).

    Returns:
        Một dictionary chứa kết quả xác minh.
    """
    result = {"valid": False, "message": "Xác minh thất bại.", "signer_email": None, "timestamp": None}
    try:
        # Đọc tệp gốc và tệp chữ ký
        original_file = Path(original_file_path)
        sig_file = Path(signature_file_path)
        if not original_file.exists() or not sig_file.exists():
            result["message"] = "Tệp gốc hoặc tệp chữ ký không tồn tại."
            raise ValueError(result["message"])

        # Đọc và băm tệp gốc
        with open(original_file, "rb") as f:
            data_to_verify = f.read()
        file_hash = hashes.Hash(hashes.SHA256())
        file_hash.update(data_to_verify)
        digest = file_hash.finalize()

        # Đọc tệp chữ ký
        with open(sig_file, "r") as f:
            sig_data = json.load(f)
        signature = base64.b64decode(sig_data["signature"])
        metadata = sig_data["metadata"]
        signing_time = datetime.fromisoformat(metadata["timestamp"])

        # Duyệt qua tất cả các public key đã lưu để tìm khóa hợp lệ
        found_valid_key = False
        if not PUBLIC_KEYS_DIR.exists():
             result["message"] = "Không tìm thấy thư mục chứa các khóa công khai."
             raise FileNotFoundError(result["message"])

        for key_file in PUBLIC_KEYS_DIR.iterdir():
            if not key_file.is_file() or not key_file.name.endswith('.json'):
                continue
            try:
                with open(key_file, "r") as f:
                    key_data = json.load(f)

                # Kiểm tra xem khóa có hợp lệ tại thời điểm ký không
                key_created = datetime.fromisoformat(key_data["created"])
                key_expires = datetime.fromisoformat(key_data["expires"])

                if not (key_created <= signing_time <= key_expires):
                    continue # Bỏ qua nếu khóa không hợp lệ tại thời điểm đó

                public_key_pem = base64.b64decode(key_data["public_key"])
                public_key = serialization.load_pem_public_key(public_key_pem)

                # Thử xác minh
                public_key.verify(
                    signature,
                    digest,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )

                # Nếu không có lỗi, chữ ký hợp lệ
                result = {
                    "valid": True,
                    "message": "Chữ ký hợp lệ!",
                    "signer_email": key_data["email"],
                    "timestamp": metadata["timestamp"]
                }
                found_valid_key = True
                break # Thoát khỏi vòng lặp khi đã tìm thấy khóa hợp lệ
            except Exception:
                # Bỏ qua lỗi và thử với khóa tiếp theo
                continue

        if not found_valid_key:
            result["message"] = "Chữ ký không hợp lệ hoặc không tìm thấy khóa công khai phù hợp (có thể khóa đã hết hạn tại thời điểm ký)."

        log_action(verifier_email, "verify_signature", f"{'success' if found_valid_key else 'failed'}: {result['message']} for file {original_file.name}")
        return result

    except Exception as e:
        result["message"] = f"Lỗi khi xác minh: {str(e)}"
        log_action(verifier_email, "verify_signature", f"failed: {str(e)}")
        return result