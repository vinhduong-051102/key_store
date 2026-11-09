from datetime import datetime

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from . import access
from .config import get_settings
from .crypto import get_kek
from .db import get_db
from .services import ServiceError, audit
from .utils import RateLimiter, client_ip

router = APIRouter(prefix="/api/v1/access-requests", tags=["access-request (public)"])
limiter = RateLimiter()


class AccessRequestIn(BaseModel):
    name: str = Field(min_length=1, max_length=100, description="Tên người/hệ thống xin quyền")
    contact: str = Field(min_length=3, max_length=200, description="Email hoặc số điện thoại")
    organization: str = Field("", max_length=200)
    reason: str = Field(min_length=1, max_length=2000, description="Lý do cần truy cập")
    requested_keys: str = Field("", max_length=1000, description="Key muốn truy cập (mô tả tự do)")
    public_key: str | None = Field(None, max_length=200,
                                   description="Public key X25519 (base64). Bỏ trống để server tự sinh cặp khóa")


class AccessRequestCreated(BaseModel):
    request_id: str
    claim_token: str = Field(description="Bí mật, chỉ trả về một lần. Dùng để xem trạng thái và nhận thông tin")
    status: str
    message: str


class AccessRequestStatus(BaseModel):
    request_id: str
    status: str
    created_at: datetime
    reviewed_at: datetime | None
    review_note: str
    claim_expires_at: datetime | None


class ClaimResponse(BaseModel):
    recipient_id: str
    recipient_name: str
    api_key: str
    totp_secret: str
    otpauth_uri: str
    public_key: str
    private_key_pem: str | None = Field(description="Chỉ có khi server sinh cặp khóa. Server không lưu lại")
    granted_keys: list[dict]


class ActivateIn(BaseModel):
    otp: str = Field(min_length=6, max_length=8)


def _limit(key: str, limit: int) -> None:
    if not limiter.allow(key, limit, 3600):
        raise HTTPException(429, "Quá nhiều yêu cầu, vui lòng thử lại sau")


def _fail(db: Session, actor: str, action: str, target: str, ip: str | None, ex: ServiceError):
    audit(db, "anonymous", actor, action, target, ip, False, ex.message)
    db.commit()
    raise HTTPException(ex.status, ex.message)


@router.post("", response_model=AccessRequestCreated, status_code=201)
def submit(body: AccessRequestIn, request: Request, db: Session = Depends(get_db)):
    ip = client_ip(request)
    _limit(f"submit:{ip}", get_settings().request_rate_limit)
    try:
        req, token = access.submit_request(
            db, get_settings(), name=body.name, contact=body.contact, organization=body.organization,
            reason=body.reason, requested_keys=body.requested_keys, public_key=body.public_key,
            ip=ip, user_agent=request.headers.get("user-agent", ""))
    except ServiceError as ex:
        db.rollback()
        _fail(db, body.name, "access.request", "-", ip, ex)
    audit(db, "anonymous", req.name, "access.request", f"request:{req.id}", ip, True, f"liên hệ={req.contact}")
    db.commit()
    return AccessRequestCreated(request_id=req.id, claim_token=token, status=req.status,
                                message="Đã gửi yêu cầu. Lưu claim token để theo dõi và nhận thông tin khi được duyệt.")


@router.get("/{request_id}", response_model=AccessRequestStatus)
def status(request_id: str, request: Request, x_claim_token: str = Header(default=""),
           db: Session = Depends(get_db)):
    _limit(f"status:{client_ip(request)}", 120)
    try:
        req = access.find_request(db, request_id, x_claim_token)
    except ServiceError as ex:
        raise HTTPException(ex.status, ex.message)
    return AccessRequestStatus(request_id=req.id, status=req.status, created_at=req.created_at,
                               reviewed_at=req.reviewed_at, review_note=req.review_note or "",
                               claim_expires_at=req.claim_expires_at)


@router.post("/{request_id}/claim", response_model=ClaimResponse)
def claim(request_id: str, request: Request, x_claim_token: str = Header(default=""),
          db: Session = Depends(get_db)):
    ip = client_ip(request)
    _limit(f"claim:{ip}", 30)
    try:
        req = access.find_request(db, request_id, x_claim_token)
        result = access.claim(db, get_kek(), get_settings(), req, ip)
    except ServiceError as ex:
        db.rollback()
        _fail(db, "?", "access.claim", f"request:{request_id}", ip, ex)
    audit(db, "anonymous", req.name, "access.claim", f"recipient:{result['recipient_name']}", ip, True,
          "server sinh cặp khóa" if result["private_key_pem"] else "dùng public key người xin cung cấp")
    db.commit()
    return ClaimResponse(**result)


@router.post("/{request_id}/activate")
def activate(request_id: str, body: ActivateIn, request: Request, x_claim_token: str = Header(default=""),
             db: Session = Depends(get_db)):
    ip = client_ip(request)
    _limit(f"activate:{ip}", 30)
    try:
        req = access.find_request(db, request_id, x_claim_token)
        r = access.activate(db, get_kek(), get_settings(), req, body.otp)
    except ServiceError as ex:
        _fail(db, "?", "access.activate", f"request:{request_id}", ip, ex)  # giữ bộ đếm sai OTP
    audit(db, "recipient", r.name, "recipient.activate", f"recipient:{r.name}", ip, True, "tự kích hoạt qua API")
    db.commit()
    return {"status": "active", "recipient_id": r.id}
