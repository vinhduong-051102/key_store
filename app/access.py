"""Yêu cầu truy cập: người ngoài gửi yêu cầu qua API public, admin duyệt trên dashboard,
người xin quyền dùng claim token để nhận thông tin đăng nhập một lần duy nhất."""
import base64
import hmac
import secrets
from datetime import timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import services, totp
from .config import Settings
from .crypto import KeyEncryptionKey, hash_api_key, parse_public_key
from .models import AccessRequest, Recipient, SecretKey, new_id, utcnow
from .services import ServiceError


def _clean(value: str | None, max_len: int, field: str, required: bool = False) -> str:
    value = (value or "").strip()
    if required and not value:
        raise ServiceError(400, f"Thiếu {field}")
    if len(value) > max_len:
        raise ServiceError(400, f"{field} quá dài (tối đa {max_len} ký tự)")
    return value


def submit_request(db: Session, settings: Settings, *, name: str, contact: str, organization: str, reason: str,
                   requested_keys: str, public_key: str | None, ip: str | None,
                   user_agent: str) -> tuple[AccessRequest, str]:
    pending = db.scalar(select(func.count()).select_from(AccessRequest).where(AccessRequest.status == "pending"))
    if pending >= settings.max_pending_requests:
        raise ServiceError(503, "Hệ thống đang có quá nhiều yêu cầu chờ duyệt, vui lòng thử lại sau")
    pub_b64 = None
    if public_key and public_key.strip():
        try:
            pub_b64 = base64.b64encode(parse_public_key(public_key)).decode()
        except ValueError as exc:
            raise ServiceError(400, str(exc)) from exc
    token = "kvr_" + secrets.token_urlsafe(32)
    req = AccessRequest(
        id=new_id(),
        name=_clean(name, 100, "tên", True),
        contact=_clean(contact, 200, "thông tin liên hệ", True),
        organization=_clean(organization, 200, "tổ chức"),
        reason=_clean(reason, 2000, "lý do", True),
        requested_keys=_clean(requested_keys, 1000, "key cần truy cập"),
        public_key=pub_b64,
        claim_token_hash=hash_api_key(token),
        status="pending",
        request_ip=ip,
        user_agent=(user_agent or "")[:300],
    )
    db.add(req)
    return req, token


def find_request(db: Session, request_id: str, token: str) -> AccessRequest:
    req = db.get(AccessRequest, request_id)
    if req is None or not token or not hmac.compare_digest(req.claim_token_hash, hash_api_key(token)):
        raise ServiceError(404, "Không tìm thấy yêu cầu hoặc claim token không đúng")
    return req


def approve(db: Session, kek: KeyEncryptionKey, settings: Settings, req: AccessRequest, *,
            recipient_name: str, key_ids: list[str], note: str, actor: str) -> Recipient:
    if req.status != "pending":
        raise ServiceError(409, "Yêu cầu đã được xử lý")
    name = _clean(recipient_name, 100, "tên bên nhận", True)
    if db.scalar(select(Recipient).where(Recipient.name == name)):
        raise ServiceError(409, f"Đã có bên nhận tên '{name}'. Hãy đặt tên khác")
    r = Recipient(id=new_id(), name=name, public_key=req.public_key or "", status="pending", created_by=actor,
                  description=f"Từ yêu cầu truy cập · {req.contact}" + (f" · {req.organization}" if req.organization else ""))
    services._issue_credentials(kek, r)  # thông tin tạm, sẽ cấp mới khi người xin quyền nhận
    r.keys = list(db.scalars(select(SecretKey).where(SecretKey.id.in_(key_ids))).all()) if key_ids else []
    db.add(r)
    now = utcnow()
    req.status = "approved"
    req.recipient_id = r.id
    req.reviewed_by = actor
    req.reviewed_at = now
    req.review_note = _clean(note, 1000, "ghi chú")
    req.claim_expires_at = now + timedelta(hours=settings.claim_ttl_hours)
    return r


def reject(req: AccessRequest, *, note: str, actor: str) -> None:
    if req.status != "pending":
        raise ServiceError(409, "Yêu cầu đã được xử lý")
    req.status = "rejected"
    req.reviewed_by = actor
    req.reviewed_at = utcnow()
    req.review_note = _clean(note, 1000, "lý do từ chối")


def claim(db: Session, kek: KeyEncryptionKey, settings: Settings, req: AccessRequest, ip: str | None) -> dict:
    if req.status == "pending":
        raise ServiceError(409, "Yêu cầu chưa được duyệt")
    if req.status == "rejected":
        raise ServiceError(403, "Yêu cầu đã bị từ chối" + (f": {req.review_note}" if req.review_note else ""))
    if req.status == "claimed":
        raise ServiceError(409, "Thông tin đã được nhận trước đó. Liên hệ quản trị viên nếu cần cấp lại")
    if req.claim_expires_at and req.claim_expires_at < utcnow():
        raise ServiceError(410, "Đã quá hạn nhận thông tin. Liên hệ quản trị viên")
    r = db.get(Recipient, req.recipient_id) if req.recipient_id else None
    if r is None:
        raise ServiceError(410, "Bên nhận không còn tồn tại")

    private_key_pem = None
    if not r.public_key:
        # Server sinh cặp khóa; private key chỉ trả về một lần, KHÔNG lưu lại.
        priv = X25519PrivateKey.generate()
        raw_pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        r.public_key = base64.b64encode(raw_pub).decode()
        private_key_pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                             serialization.NoEncryption()).decode()
    api_key, secret = services._issue_credentials(kek, r)
    r.status = "pending"
    req.status = "claimed"
    req.claimed_at = utcnow()
    req.claim_ip = ip
    return {
        "recipient_id": r.id,
        "recipient_name": r.name,
        "api_key": api_key,
        "totp_secret": secret,
        "otpauth_uri": totp.provisioning_uri(secret, r.name, settings.totp_issuer),
        "public_key": r.public_key,
        "private_key_pem": private_key_pem,
        "granted_keys": [{"id": k.id, "name": k.name} for k in r.keys if k.status == "active"],
    }


def activate(db: Session, kek: KeyEncryptionKey, settings: Settings, req: AccessRequest, otp: str) -> Recipient:
    if req.status != "claimed":
        raise ServiceError(409, "Cần nhận thông tin (claim) trước khi kích hoạt")
    r = db.get(Recipient, req.recipient_id)
    if r is None:
        raise ServiceError(410, "Bên nhận không còn tồn tại")
    services.confirm_enrollment(kek, settings, r, otp)
    return r
