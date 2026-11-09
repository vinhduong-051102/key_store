import base64
from datetime import datetime

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from . import services
from .config import get_settings
from .crypto import get_kek
from .db import get_db
from .models import Recipient
from .services import ServiceError, audit
from .utils import client_ip

router = APIRouter(prefix="/api/v1", tags=["recipient"])


class KeyInfo(BaseModel):
    id: str
    name: str
    description: str
    fingerprint: str
    size_bytes: int


class ExportRequest(BaseModel):
    key_id: str = Field(min_length=1, max_length=64)


class ExportCreated(BaseModel):
    export_id: str
    key_id: str
    key_name: str
    recipient_id: str
    ciphertext: str = Field(description="base64(nonce || AES-256-GCM ciphertext) — chỉ giải mã được sau khi unlock")
    aad: str
    expires_at: datetime


class UnlockRequest(BaseModel):
    otp: str = Field(min_length=6, max_length=8)


class UnlockResponse(BaseModel):
    export_id: str
    wrapped_key: str = Field(description="base64(eph_pub(32) || nonce || ciphertext) — X25519-HKDF-SHA256 + AES-256-GCM")
    aad: str
    alg: str = "X25519-HKDF-SHA256/AES-256-GCM"


def api_recipient(request: Request, x_api_key: str = Header(default=""),
                  db: Session = Depends(get_db)) -> Recipient:
    r = services.find_recipient_by_api_key(db, x_api_key)
    if r is None:
        audit(db, "anonymous", "?", "api.auth", None, client_ip(request), False, "API key không hợp lệ")
        db.commit()
        raise HTTPException(401, "API key không hợp lệ")
    if r.status != "active":
        raise HTTPException(403, f"Bên nhận đang ở trạng thái '{r.status}'")
    return r


@router.get("/keys", response_model=list[KeyInfo])
def list_keys(recipient: Recipient = Depends(api_recipient)):
    return [
        KeyInfo(id=k.id, name=k.name, description=k.description, fingerprint=k.fingerprint, size_bytes=k.size_bytes)
        for k in recipient.keys if k.status == "active"
    ]


@router.post("/exports", response_model=ExportCreated, status_code=201)
def create_export(body: ExportRequest, request: Request,
                  recipient: Recipient = Depends(api_recipient), db: Session = Depends(get_db)):
    ip = client_ip(request)
    services.expire_stale_exports(db)
    try:
        e, ciphertext, aad = services.create_export(db, get_kek(), get_settings(), recipient, body.key_id, ip)
    except ServiceError as ex:
        db.rollback()
        audit(db, "recipient", recipient.name, "export.create", f"key:{body.key_id}", ip, False, ex.message)
        db.commit()
        raise HTTPException(ex.status, ex.message)
    audit(db, "recipient", recipient.name, "export.create", f"key:{e.key.name}", ip, True, f"export={e.id}")
    db.commit()
    return ExportCreated(export_id=e.id, key_id=e.key_id, key_name=e.key.name, recipient_id=recipient.id,
                         ciphertext=base64.b64encode(ciphertext).decode(), aad=aad.decode(), expires_at=e.expires_at)


@router.post("/exports/{export_id}/unlock", response_model=UnlockResponse)
def unlock_export(export_id: str, body: UnlockRequest, request: Request,
                  recipient: Recipient = Depends(api_recipient), db: Session = Depends(get_db)):
    ip = client_ip(request)
    try:
        e, wrapped, aad = services.unlock_export(db, get_kek(), get_settings(), recipient, export_id, body.otp, ip)
    except ServiceError as ex:
        # Không rollback: cần lưu lại bộ đếm sai OTP / trạng thái export.
        audit(db, "recipient", recipient.name, "export.unlock", f"export:{export_id}", ip, False, ex.message)
        db.commit()
        raise HTTPException(ex.status, ex.message)
    audit(db, "recipient", recipient.name, "export.unlock", f"key:{e.key.name}", ip, True, f"export={e.id}")
    db.commit()
    return UnlockResponse(export_id=e.id, wrapped_key=base64.b64encode(wrapped).decode(), aad=aad.decode())
