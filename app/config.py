import base64
import binascii
import os
from functools import lru_cache


class Settings:
    def __init__(self) -> None:
        self.database_url = os.getenv("DATABASE_URL", "sqlite:///./data/keyvault.db")

        master = os.getenv("KV_MASTER_KEY")
        if not master:
            raise RuntimeError("Thiếu biến môi trường KV_MASTER_KEY (base64 của 32 byte ngẫu nhiên)")
        try:
            self.master_key = base64.b64decode(master, validate=True)
        except binascii.Error as exc:
            raise RuntimeError("KV_MASTER_KEY không phải base64 hợp lệ") from exc
        if len(self.master_key) != 32:
            raise RuntimeError("KV_MASTER_KEY phải là 32 byte (256 bit)")

        self.session_secret = os.getenv("KV_SESSION_SECRET")
        if not self.session_secret or len(self.session_secret) < 32:
            raise RuntimeError("Thiếu KV_SESSION_SECRET (tối thiểu 32 ký tự)")

        self.export_ttl_seconds = int(os.getenv("KV_EXPORT_TTL", "300"))
        self.export_max_attempts = int(os.getenv("KV_EXPORT_MAX_ATTEMPTS", "3"))
        self.max_otp_failures = int(os.getenv("KV_MAX_OTP_FAILURES", "5"))
        self.lockout_seconds = int(os.getenv("KV_LOCKOUT_SECONDS", "900"))
        self.session_max_age = int(os.getenv("KV_SESSION_MAX_AGE", str(8 * 3600)))
        self.display_tz = os.getenv("KV_DISPLAY_TZ", "Asia/Ho_Chi_Minh")
        self.totp_issuer = os.getenv("KV_TOTP_ISSUER", "KeyVault")
        self.cookie_secure = os.getenv("KV_COOKIE_SECURE", "true").lower() == "true"
        self.request_rate_limit = int(os.getenv("KV_REQUEST_RATE_LIMIT", "5"))      # yêu cầu / giờ / IP
        self.max_pending_requests = int(os.getenv("KV_MAX_PENDING_REQUESTS", "100"))
        self.claim_ttl_hours = int(os.getenv("KV_CLAIM_TTL_HOURS", "168"))           # 7 ngày
        self.max_key_bytes = int(os.getenv("KV_MAX_KEY_BYTES", str(64 * 1024)))


@lru_cache
def get_settings() -> Settings:
    return Settings()
