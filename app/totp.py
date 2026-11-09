import hmac
import time

import pyotp
import qrcode
from qrcode.image.svg import SvgPathImage

STEP_SECONDS = 30


def new_secret() -> str:
    return pyotp.random_base32(32)  # 160 bit


def provisioning_uri(secret: str, account: str, issuer: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=account, issuer_name=issuer)


def match_step(secret: str, code: str, last_step: int, now: float | None = None, window: int = 1) -> int | None:
    """Trả về time-step khớp với mã, hoặc None.

    Chỉ chấp nhận step > last_step để mỗi mã OTP chỉ dùng được một lần (chống replay).
    """
    code = (code or "").strip().replace(" ", "")
    if len(code) != 6 or not code.isdigit():
        return None
    totp = pyotp.TOTP(secret)
    current = int((now if now is not None else time.time()) // STEP_SECONDS)
    for step in range(current - window, current + window + 1):
        if step > (last_step or 0) and hmac.compare_digest(totp.generate_otp(step), code):
            return step
    return None


def qr_svg(data: str) -> str:
    img = qrcode.make(data, image_factory=SvgPathImage, box_size=8, border=2)
    return img.to_string(encoding="unicode")
