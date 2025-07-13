import qrcode
import json
from PIL import Image
from pyzbar.pyzbar import decode

def generate_qr_for_pubkey(email, pubkey, created_date, path_out):
    data = {
        "email": email,
        "created": created_date,
        "pubkey": pubkey
    }
    qr = qrcode.make(json.dumps(data))
    qr.save(path_out)

def read_qr(qr_path):
    img = Image.open(qr_path)
    decoded = decode(img)
    if decoded:
        return json.loads(decoded[0].data.decode())
    return None

generate_qr_for_pubkey("test@gmail.com", "323313232132", "2025/7/12", r"..\data\test.png")
print(read_qr(r"..\data\test.png"))