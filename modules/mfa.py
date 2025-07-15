from PIL import Image
import pyotp
import qrcode
import string, random
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

def generate_otp() -> tuple[str, str, str]:
    """Generate a 6-digit OTP with creation/expiration times."""
    otp = ''.join(random.choices(string.digits, k=6))
    created = datetime.now(ZoneInfo("Asia/Ho_Chi_Minh")).isoformat()
    expires = (datetime.now(ZoneInfo("Asia/Ho_Chi_Minh")) + timedelta(minutes=5)).isoformat()
    return otp, created, expires

def generate_totp_qr(email: str, totp_secret: str) -> Image.Image:
    """Generate TOTP QR code as a PIL image (no saving to disk)."""
    totp = pyotp.TOTP(totp_secret)
    uri = totp.provisioning_uri(name=email, issuer_name="CryptoDemo")
    qr = qrcode.QRCode()
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    return img.convert("RGB")


def verify_totp(totp_secret: str, code: str) -> bool:
    """Verify TOTP code."""
    totp = pyotp.TOTP(totp_secret)
    return totp.verify(code)