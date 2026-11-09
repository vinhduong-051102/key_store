"""Nghiệp vụ lõi. Các hàm ở đây KHÔNG commit; tầng gọi (API/dashboard) chịu trách nhiệm commit."""
import base64
import binascii
import secrets
from datetime import timedelta

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from . import totp
from .config import Settings
from .crypto import (
    DUMMY_PASSWORD_HASH,
    KeyEncryptionKey,
    aead_decrypt,
    aead_encrypt,
    hash_api_key,
    hash_password,
    new_api_key,
    parse_public_key,
    verify_password,
    wrap_for_recipient,
)
from .models import Admin, AuditLog, Export, Recipient, SecretKey, new_id, utcnow


class ServiceError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def audit(db: Session, actor_type: str, actor: str, action: str, target: str | None = None,
          ip: str | None = None, success: bool = True, details: str = "") -> None:
    db.add(AuditLog(actor_type=actor_type, actor=(actor or "?")[:100], action=action,
                    target=(target or None) and target[:200], ip=ip, success=success, details=details))


# ---------- OTP / khóa tạm ----------

def _register_failure(subject: Admin | Recipient, settings: Settings) -> None:
    subject.failed_attempts = (subject.failed_attempts or 0) + 1
    if subject.failed_attempts >= settings.max_otp_failures:
        subject.locked_until = utcnow() + timedelta(seconds=settings.lockout_seconds)
        subject.failed_attempts = 0


def _ensure_not_locked(subject: Admin | Recipient) -> None:
    if subject.locked_until and subject.locked_until > utcnow():
        raise ServiceError(429, "Tài khoản đang bị tạm khóa do nhập sai quá nhiều lần")


def verify_subject_otp(subject: Admin | Recipient, secret: str, code: str, settings: Settings) -> bool:
    _ensure_not_locked(subject)
    step = totp.match_step(secret, code, subject.last_totp_step or 0)
    if step is None:
        _register_failure(subject, settings)
        return False
    subject.last_totp_step = step
    subject.failed_attempts = 0
    subject.locked_until = None
    return True


# ---------- Admin ----------

def admin_totp_secret(kek: KeyEncryptionKey, admin: Admin) -> str:
    return kek.unwrap(admin.totp_secret_enc, f"totp|admin|{admin.id}").decode()


def create_admin(db: Session, kek: KeyEncryptionKey, username: str, password: str, secret: str) -> Admin:
    if db.scalar(select(Admin).where(Admin.username == username)):
        raise ServiceError(409, f"Admin '{username}' đã tồn tại")
    admin = Admin(id=new_id(), username=username, password_hash=hash_password(password))
    admin.totp_secret_enc = kek.wrap(secret.encode(), f"totp|admin|{admin.id}")
    admin.last_totp_step = 0
    admin.failed_attempts = 0
    db.add(admin)
    return admin


def admin_login(db: Session, kek: KeyEncryptionKey, settings: Settings,
                username: str, password: str, otp: str) -> Admin:
    admin = db.scalar(select(Admin).where(Admin.username == username))
    if admin is None:
        verify_password(password, DUMMY_PASSWORD_HASH)
        raise ServiceError(401, "Sai thông tin đăng nhập")
    _ensure_not_locked(admin)
    if not verify_password(password, admin.password_hash):
        _register_failure(admin, settings)
        raise ServiceError(401, "Sai thông tin đăng nhập")
    if not verify_subject_otp(admin, admin_totp_secret(kek, admin), otp, settings):
        raise ServiceError(401, "Sai thông tin đăng nhập")
    admin.last_login_at = utcnow()
    return admin


# ---------- Keys ----------

def parse_key_value(value_format: str, value: str, random_bytes: str, max_bytes: int) -> bytes:
    if value_format == "random":
        try:
            n = int(random_bytes)
        except ValueError as exc:
            raise ServiceError(400, "Độ dài key ngẫu nhiên không hợp lệ") from exc
        if not 16 <= n <= 1024:
            raise ServiceError(400, "Độ dài key ngẫu nhiên phải từ 16 đến 1024 byte")
        return secrets.token_bytes(n)

    if not value or not value.strip():
        raise ServiceError(400, "Giá trị key không được để trống")
    if value_format == "text":
        raw = value.replace("\r\n", "\n").encode()
    elif value_format == "hex":
        try:
            raw = bytes.fromhex("".join(value.split()))
        except ValueError as exc:
            raise ServiceError(400, "Giá trị hex không hợp lệ") from exc
    elif value_format == "base64":
        try:
            raw = base64.b64decode("".join(value.split()), validate=True)
        except binascii.Error as exc:
            raise ServiceError(400, "Giá trị base64 không hợp lệ") from exc
    else:
        raise ServiceError(400, "Định dạng không hợp lệ")
    if len(raw) > max_bytes:
        raise ServiceError(400, f"Key vượt quá {max_bytes} byte")
    return raw


def create_key(db: Session, kek: KeyEncryptionKey, *, name: str, description: str,
               value: bytes, value_format: str, actor: str) -> SecretKey:
    name = name.strip()
    if not name or len(name) > 100:
        raise ServiceError(400, "Tên key phải từ 1 đến 100 ký tự")
    if db.scalar(select(SecretKey).where(SecretKey.name == name)):
        raise ServiceError(409, f"Key '{name}' đã tồn tại")
    key = SecretKey(id=new_id(), name=name, description=description.strip(), value_format=value_format,
                    size_bytes=len(value), status="active", created_by=actor)
    dek = AESGCM.generate_key(256)
    key.ciphertext = aead_encrypt(dek, value, f"key|{key.id}".encode())
    key.dek_wrapped = kek.wrap(dek, f"key-dek|{key.id}")
    key.fingerprint = kek.fingerprint(value)
    db.add(key)
    return key


def decrypt_key_value(kek: KeyEncryptionKey, key: SecretKey) -> bytes:
    dek = kek.unwrap(key.dek_wrapped, f"key-dek|{key.id}")
    return aead_decrypt(dek, key.ciphertext, f"key|{key.id}".encode())


# ---------- Recipients ----------

def recipient_totp_secret(kek: KeyEncryptionKey, r: Recipient) -> str:
    return kek.unwrap(r.totp_secret_enc, f"totp|recipient|{r.id}").decode()


def _issue_credentials(kek: KeyEncryptionKey, r: Recipient) -> tuple[str, str]:
    api_key = new_api_key()
    r.api_key_hash = hash_api_key(api_key)
    r.api_key_prefix = api_key[:10]
    secret = totp.new_secret()
    r.totp_secret_enc = kek.wrap(secret.encode(), f"totp|recipient|{r.id}")
    r.last_totp_step = 0
    r.failed_attempts = 0
    r.locked_until = None
    return api_key, secret


def create_recipient(db: Session, kek: KeyEncryptionKey, *, name: str, description: str,
                     public_key: str, actor: str) -> tuple[Recipient, str, str]:
    name = name.strip()
    if not name or len(name) > 100:
        raise ServiceError(400, "Tên bên nhận phải từ 1 đến 100 ký tự")
    if db.scalar(select(Recipient).where(Recipient.name == name)):
        raise ServiceError(409, f"Bên nhận '{name}' đã tồn tại")
    try:
        pub = parse_public_key(public_key)
    except ValueError as exc:
        raise ServiceError(400, str(exc)) from exc
    r = Recipient(id=new_id(), name=name, description=description.strip(),
                  public_key=base64.b64encode(pub).decode(), status="pending", created_by=actor)
    api_key, secret = _issue_credentials(kek, r)
    db.add(r)
    return r, api_key, secret


def reenroll_recipient(kek: KeyEncryptionKey, r: Recipient) -> tuple[str, str]:
    r.status = "pending"
    r.activated_at = None
    return _issue_credentials(kek, r)


def confirm_enrollment(kek: KeyEncryptionKey, settings: Settings, r: Recipient, code: str) -> None:
    if r.status != "pending":
        raise ServiceError(409, "Bên nhận không ở trạng thái chờ kích hoạt")
    if not r.public_key:
        raise ServiceError(409, "Bên nhận chưa có public key (yêu cầu truy cập chưa được nhận)")
    if not verify_subject_otp(r, recipient_totp_secret(kek, r), code, settings):
        raise ServiceError(400, "Mã OTP không đúng")
    r.status = "active"
    r.activated_at = utcnow()


def find_recipient_by_api_key(db: Session, api_key: str) -> Recipient | None:
    if not api_key:
        return None
    return db.scalar(select(Recipient).where(Recipient.api_key_hash == hash_api_key(api_key)))


# ---------- Exports ----------

def export_aad(e: Export) -> bytes:
    return f"kv-export-v1|{e.id}|{e.key_id}|{e.recipient_id}".encode()


def expire_stale_exports(db: Session) -> None:
    db.execute(
        update(Export)
        .where(Export.status == "pending", Export.expires_at < utcnow())
        .values(status="expired", dek_e_wrapped=None)
    )


def create_export(db: Session, kek: KeyEncryptionKey, settings: Settings, recipient: Recipient,
                  key_id: str, ip: str | None) -> tuple[Export, bytes, bytes]:
    key = db.get(SecretKey, key_id)
    if key is None or key.status != "active" or recipient not in key.recipients:
        raise ServiceError(404, "Key không tồn tại hoặc bạn không được cấp quyền")
    if not recipient.public_key:
        raise ServiceError(409, "Bên nhận chưa có public key")
    value = decrypt_key_value(kek, key)
    now = utcnow()
    e = Export(id=new_id(), key=key, recipient=recipient, key_id=key.id, recipient_id=recipient.id,
               status="pending", attempts=0,
               created_at=now, expires_at=now + timedelta(seconds=settings.export_ttl_seconds), request_ip=ip)
    aad = export_aad(e)
    dek_e = AESGCM.generate_key(256)
    ciphertext = aead_encrypt(dek_e, value, aad)
    e.dek_e_wrapped = kek.wrap(dek_e, f"export|{e.id}")
    db.add(e)
    return e, ciphertext, aad


def unlock_export(db: Session, kek: KeyEncryptionKey, settings: Settings, recipient: Recipient,
                  export_id: str, otp: str, ip: str | None) -> tuple[Export, bytes, bytes]:
    # Khóa hàng (PostgreSQL) để các request song song không vượt qua giới hạn thử / chống replay.
    db.refresh(recipient, with_for_update=True)
    e = db.scalar(select(Export).where(Export.id == export_id).with_for_update())
    if e is None or e.recipient_id != recipient.id:
        raise ServiceError(404, "Export không tồn tại")
    if e.status != "pending":
        raise ServiceError(409, f"Export đang ở trạng thái '{e.status}', không thể mở khóa")
    if e.expires_at < utcnow():
        e.status = "expired"
        e.dek_e_wrapped = None
        raise ServiceError(410, "Export đã hết hạn")

    if not verify_subject_otp(recipient, recipient_totp_secret(kek, recipient), otp, settings):
        e.attempts += 1
        if e.attempts >= settings.export_max_attempts:
            e.status = "failed"
            e.dek_e_wrapped = None
            raise ServiceError(401, "OTP không hợp lệ. Export đã bị hủy do sai quá số lần cho phép")
        raise ServiceError(401, "OTP không hợp lệ")

    aad = export_aad(e)
    dek_e = kek.unwrap(e.dek_e_wrapped, f"export|{e.id}")
    wrapped = wrap_for_recipient(dek_e, base64.b64decode(recipient.public_key), aad)
    e.status = "consumed"
    e.dek_e_wrapped = None
    e.unlocked_at = utcnow()
    e.unlock_ip = ip
    e.attempts += 1
    return e, wrapped, aad
