import hmac
import secrets
from datetime import timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload, selectinload

from . import access, services, totp
from .config import get_settings
from .crypto import get_kek
from .db import SessionLocal, get_db
from .models import AccessRequest, Admin, AuditLog, Export, Recipient, SecretKey, utcnow
from .services import ServiceError, audit
from .utils import client_ip

router = APIRouter(prefix="/dashboard", include_in_schema=False)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _fmt_dt(value):
    if not value:
        return "—"
    tz = ZoneInfo(get_settings().display_tz)
    return value.replace(tzinfo=timezone.utc).astimezone(tz).strftime("%d/%m/%Y %H:%M:%S")


templates.env.filters["dt"] = _fmt_dt

STATUS_LABELS = {
    "pending": "Chờ", "consumed": "Đã lấy", "expired": "Hết hạn", "failed": "Thất bại",
    "active": "Hoạt động", "disabled": "Vô hiệu",
    "approved": "Đã duyệt", "rejected": "Từ chối", "claimed": "Đã nhận",
}
templates.env.globals["status_label"] = lambda s: STATUS_LABELS.get(s, s)


class NotAuthenticated(Exception):
    pass


# ---------- helpers ----------

def ensure_csrf(request: Request) -> str:
    tok = request.session.get("csrf")
    if not tok:
        tok = secrets.token_urlsafe(32)
        request.session["csrf"] = tok
    return tok


def verify_csrf(request: Request, token: str) -> None:
    expected = request.session.get("csrf", "")
    if not token or not expected or not hmac.compare_digest(token, expected):
        raise HTTPException(400, "CSRF token không hợp lệ. Hãy tải lại trang.")


def flash(request: Request, message: str, category: str = "ok") -> None:
    items = request.session.get("flashes", [])
    items.append([category, message])
    request.session["flashes"] = items


def render(request: Request, name: str, status_code: int = 200, **ctx):
    ctx.setdefault("admin", getattr(request.state, "admin", None))
    ctx["csrf_token"] = ensure_csrf(request)
    ctx["flashes"] = request.session.pop("flashes", [])
    ctx["nav"] = name.split("_")[0].split(".")[0]
    if ctx.get("admin"):
        with SessionLocal() as s:
            ctx["pending_requests"] = s.scalar(select(func.count()).select_from(AccessRequest)
                                               .where(AccessRequest.status == "pending"))
    return templates.TemplateResponse(request, name, ctx, status_code=status_code)


def redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


def current_admin(request: Request, db: Session = Depends(get_db)) -> Admin:
    admin_id = request.session.get("admin_id")
    admin = db.get(Admin, admin_id) if admin_id else None
    if admin is None:
        raise NotAuthenticated()
    request.state.admin = admin
    return admin


def _get_or_404(db: Session, model, obj_id: str):
    obj = db.get(model, obj_id)
    if obj is None:
        raise HTTPException(404, "Không tìm thấy")
    return obj


def _enroll_page(request: Request, r: Recipient, api_key: str, secret: str):
    uri = totp.provisioning_uri(secret, r.name, get_settings().totp_issuer)
    return render(request, "recipient_enroll.html", recipient=r, api_key=api_key,
                  totp_secret=secret, qr_svg=totp.qr_svg(uri))


# ---------- auth ----------

@router.get("/login")
def login_page(request: Request):
    if request.session.get("admin_id"):
        return redirect("/dashboard")
    return render(request, "login.html")


@router.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...), otp: str = Form(...),
          csrf_token: str = Form(""), db: Session = Depends(get_db)):
    verify_csrf(request, csrf_token)
    ip = client_ip(request)
    try:
        admin = services.admin_login(db, get_kek(), get_settings(), username.strip(), password, otp)
    except ServiceError as ex:
        audit(db, "admin", username.strip()[:64], "admin.login", None, ip, False, ex.message)
        db.commit()
        return render(request, "login.html", status_code=ex.status, error=ex.message, username=username)
    audit(db, "admin", admin.username, "admin.login", None, ip, True)
    db.commit()
    request.session.clear()
    request.session["admin_id"] = admin.id
    request.session["csrf"] = secrets.token_urlsafe(32)
    return redirect("/dashboard")


@router.post("/logout")
def logout(request: Request, csrf_token: str = Form(""), admin: Admin = Depends(current_admin),
           db: Session = Depends(get_db)):
    verify_csrf(request, csrf_token)
    audit(db, "admin", admin.username, "admin.logout", None, client_ip(request), True)
    db.commit()
    request.session.clear()
    return redirect("/dashboard/login")


# ---------- overview ----------

@router.get("")
def overview(request: Request, admin: Admin = Depends(current_admin), db: Session = Depends(get_db)):
    services.expire_stale_exports(db)
    db.commit()
    since = utcnow() - timedelta(hours=24)
    count = lambda stmt: db.scalar(select(func.count()).select_from(stmt.subquery()))  # noqa: E731
    stats = {
        "active_keys": count(select(SecretKey.id).where(SecretKey.status == "active")),
        "recipients": count(select(Recipient.id).where(Recipient.status == "active")),
        "exports_24h": count(select(Export.id).where(Export.status == "consumed", Export.unlocked_at >= since)),
        "failed_24h": count(select(AuditLog.id).where(AuditLog.success.is_(False), AuditLog.ts >= since)),
        "pending": count(select(Export.id).where(Export.status == "pending")),
    }
    recent = db.scalars(
        select(Export).options(joinedload(Export.key), joinedload(Export.recipient))
        .order_by(Export.created_at.desc()).limit(15)
    ).all()
    alerts = db.scalars(
        select(AuditLog).where(AuditLog.success.is_(False)).order_by(AuditLog.ts.desc()).limit(10)
    ).all()
    return render(request, "overview.html", stats=stats, recent=recent, alerts=alerts)


# ---------- keys ----------

def _export_stats(db: Session, column):
    rows = db.execute(
        select(column, func.count(), func.max(Export.unlocked_at))
        .where(Export.status == "consumed").group_by(column)
    ).all()
    return {r[0]: (r[1], r[2]) for r in rows}


@router.get("/keys")
def keys_list(request: Request, admin: Admin = Depends(current_admin), db: Session = Depends(get_db)):
    keys = db.scalars(select(SecretKey).options(selectinload(SecretKey.recipients))
                      .order_by(SecretKey.created_at.desc())).all()
    return render(request, "keys.html", keys=keys, stats=_export_stats(db, Export.key_id))


@router.get("/keys/new")
def key_new(request: Request, admin: Admin = Depends(current_admin)):
    return render(request, "key_new.html", form={"value_format": "text", "random_bytes": "32"})


@router.post("/keys")
def key_create(request: Request, name: str = Form(""), description: str = Form(""),
               value_format: str = Form("text"), value: str = Form(""), random_bytes: str = Form("32"),
               csrf_token: str = Form(""), admin: Admin = Depends(current_admin), db: Session = Depends(get_db)):
    verify_csrf(request, csrf_token)
    settings = get_settings()
    try:
        raw = services.parse_key_value(value_format, value, random_bytes, settings.max_key_bytes)
        key = services.create_key(db, get_kek(), name=name, description=description, value=raw,
                                  value_format=value_format, actor=admin.username)
    except ServiceError as ex:
        form = {"name": name, "description": description, "value_format": value_format, "random_bytes": random_bytes}
        return render(request, "key_new.html", status_code=ex.status, error=ex.message, form=form)
    audit(db, "admin", admin.username, "key.create", f"key:{key.name}", client_ip(request), True,
          f"format={value_format} size={key.size_bytes}")
    db.commit()
    flash(request, f"Đã thêm key '{key.name}'. Hãy cấp quyền cho bên nhận bên dưới.")
    return redirect(f"/dashboard/keys/{key.id}")


@router.get("/keys/{key_id}")
def key_detail(key_id: str, request: Request, admin: Admin = Depends(current_admin), db: Session = Depends(get_db)):
    key = _get_or_404(db, SecretKey, key_id)
    recipients = db.scalars(select(Recipient).where(Recipient.status != "disabled").order_by(Recipient.name)).all()
    exports = db.scalars(
        select(Export).options(joinedload(Export.recipient)).where(Export.key_id == key.id)
        .order_by(Export.created_at.desc()).limit(200)
    ).all()
    granted = {r.id for r in key.recipients}
    return render(request, "key_detail.html", key=key, recipients=recipients, granted=granted, exports=exports)


@router.post("/keys/{key_id}/grants")
def key_grants(key_id: str, request: Request, recipient_ids: list[str] = Form(default=[]),
               csrf_token: str = Form(""), admin: Admin = Depends(current_admin), db: Session = Depends(get_db)):
    verify_csrf(request, csrf_token)
    key = _get_or_404(db, SecretKey, key_id)
    new = db.scalars(select(Recipient).where(Recipient.id.in_(recipient_ids))).all() if recipient_ids else []
    before = {r.name for r in key.recipients}
    after = {r.name for r in new}
    # Giữ nguyên quyền của các bên nhận đang bị vô hiệu (không hiển thị trong form).
    kept = [r for r in key.recipients if r.status == "disabled"]
    key.recipients = list(new) + [r for r in kept if r not in new]
    added, removed = sorted(after - before), sorted(before - after - {r.name for r in kept})
    if added or removed:
        audit(db, "admin", admin.username, "key.grants", f"key:{key.name}", client_ip(request), True,
              f"thêm={','.join(added) or '-'} bỏ={','.join(removed) or '-'}")
    db.commit()
    flash(request, "Đã cập nhật quyền truy cập.")
    return redirect(f"/dashboard/keys/{key.id}")


@router.post("/keys/{key_id}/toggle")
def key_toggle(key_id: str, request: Request, csrf_token: str = Form(""),
               admin: Admin = Depends(current_admin), db: Session = Depends(get_db)):
    verify_csrf(request, csrf_token)
    key = _get_or_404(db, SecretKey, key_id)
    key.status = "disabled" if key.status == "active" else "active"
    audit(db, "admin", admin.username, f"key.{'disable' if key.status == 'disabled' else 'enable'}",
          f"key:{key.name}", client_ip(request), True)
    db.commit()
    flash(request, f"Key '{key.name}' hiện ở trạng thái: {STATUS_LABELS[key.status]}.")
    return redirect(f"/dashboard/keys/{key.id}")


# ---------- recipients ----------

@router.get("/recipients")
def recipients_list(request: Request, admin: Admin = Depends(current_admin), db: Session = Depends(get_db)):
    recipients = db.scalars(select(Recipient).options(selectinload(Recipient.keys))
                            .order_by(Recipient.created_at.desc())).all()
    return render(request, "recipients.html", recipients=recipients,
                  stats=_export_stats(db, Export.recipient_id), now=utcnow())


@router.get("/recipients/new")
def recipient_new(request: Request, admin: Admin = Depends(current_admin)):
    return render(request, "recipient_new.html", form={})


@router.post("/recipients")
def recipient_create(request: Request, name: str = Form(""), description: str = Form(""),
                     public_key: str = Form(""), csrf_token: str = Form(""),
                     admin: Admin = Depends(current_admin), db: Session = Depends(get_db)):
    verify_csrf(request, csrf_token)
    try:
        r, api_key, secret = services.create_recipient(db, get_kek(), name=name, description=description,
                                                        public_key=public_key, actor=admin.username)
    except ServiceError as ex:
        form = {"name": name, "description": description, "public_key": public_key}
        return render(request, "recipient_new.html", status_code=ex.status, error=ex.message, form=form)
    audit(db, "admin", admin.username, "recipient.create", f"recipient:{r.name}", client_ip(request), True)
    db.commit()
    return _enroll_page(request, r, api_key, secret)


@router.get("/recipients/{rid}")
def recipient_detail(rid: str, request: Request, admin: Admin = Depends(current_admin), db: Session = Depends(get_db)):
    r = _get_or_404(db, Recipient, rid)
    exports = db.scalars(
        select(Export).options(joinedload(Export.key)).where(Export.recipient_id == r.id)
        .order_by(Export.created_at.desc()).limit(200)
    ).all()
    locked = bool(r.locked_until and r.locked_until > utcnow())
    return render(request, "recipient_detail.html", r=r, exports=exports, locked=locked)


@router.post("/recipients/{rid}/confirm")
def recipient_confirm(rid: str, request: Request, otp: str = Form(""), csrf_token: str = Form(""),
                      admin: Admin = Depends(current_admin), db: Session = Depends(get_db)):
    verify_csrf(request, csrf_token)
    r = _get_or_404(db, Recipient, rid)
    ip = client_ip(request)
    try:
        services.confirm_enrollment(get_kek(), get_settings(), r, otp)
    except ServiceError as ex:
        audit(db, "admin", admin.username, "recipient.activate", f"recipient:{r.name}", ip, False, ex.message)
        db.commit()
        flash(request, f"{ex.message}. Nhập lại mã mới, hoặc cấp lại thông tin nếu chưa quét được QR.", "error")
        return redirect(f"/dashboard/recipients/{r.id}")
    audit(db, "admin", admin.username, "recipient.activate", f"recipient:{r.name}", ip, True)
    db.commit()
    flash(request, f"Đã kích hoạt bên nhận '{r.name}'.")
    return redirect(f"/dashboard/recipients/{r.id}")


@router.post("/recipients/{rid}/reenroll")
def recipient_reenroll(rid: str, request: Request, csrf_token: str = Form(""),
                       admin: Admin = Depends(current_admin), db: Session = Depends(get_db)):
    verify_csrf(request, csrf_token)
    r = _get_or_404(db, Recipient, rid)
    api_key, secret = services.reenroll_recipient(get_kek(), r)
    audit(db, "admin", admin.username, "recipient.reenroll", f"recipient:{r.name}", client_ip(request), True,
          "Cấp lại API key và TOTP secret")
    db.commit()
    return _enroll_page(request, r, api_key, secret)


@router.post("/recipients/{rid}/toggle")
def recipient_toggle(rid: str, request: Request, csrf_token: str = Form(""),
                     admin: Admin = Depends(current_admin), db: Session = Depends(get_db)):
    verify_csrf(request, csrf_token)
    r = _get_or_404(db, Recipient, rid)
    if r.status == "pending":
        flash(request, "Bên nhận chưa kích hoạt.", "error")
        return redirect(f"/dashboard/recipients/{r.id}")
    r.status = "disabled" if r.status == "active" else "active"
    audit(db, "admin", admin.username, f"recipient.{'disable' if r.status == 'disabled' else 'enable'}",
          f"recipient:{r.name}", client_ip(request), True)
    db.commit()
    flash(request, f"Bên nhận '{r.name}' hiện ở trạng thái: {STATUS_LABELS[r.status]}.")
    return redirect(f"/dashboard/recipients/{r.id}")


@router.post("/recipients/{rid}/unlock")
def recipient_unlock(rid: str, request: Request, csrf_token: str = Form(""),
                     admin: Admin = Depends(current_admin), db: Session = Depends(get_db)):
    verify_csrf(request, csrf_token)
    r = _get_or_404(db, Recipient, rid)
    r.locked_until = None
    r.failed_attempts = 0
    audit(db, "admin", admin.username, "recipient.unlock", f"recipient:{r.name}", client_ip(request), True)
    db.commit()
    flash(request, f"Đã gỡ khóa tạm cho '{r.name}'.")
    return redirect(f"/dashboard/recipients/{r.id}")


# ---------- exports & audit ----------

@router.get("/exports")
def exports_list(request: Request, recipient_id: str = "", key_id: str = "", status: str = "",
                 admin: Admin = Depends(current_admin), db: Session = Depends(get_db)):
    services.expire_stale_exports(db)
    db.commit()
    stmt = select(Export).options(joinedload(Export.key), joinedload(Export.recipient))
    if recipient_id:
        stmt = stmt.where(Export.recipient_id == recipient_id)
    if key_id:
        stmt = stmt.where(Export.key_id == key_id)
    if status:
        stmt = stmt.where(Export.status == status)
    exports = db.scalars(stmt.order_by(Export.created_at.desc()).limit(500)).all()
    return render(request, "exports.html", exports=exports,
                  recipients=db.scalars(select(Recipient).order_by(Recipient.name)).all(),
                  keys=db.scalars(select(SecretKey).order_by(SecretKey.name)).all(),
                  f={"recipient_id": recipient_id, "key_id": key_id, "status": status})


@router.get("/audit")
def audit_list(request: Request, page: int = 1, only_failed: bool = False,
               admin: Admin = Depends(current_admin), db: Session = Depends(get_db)):
    page = max(page, 1)
    per_page = 100
    stmt = select(AuditLog)
    if only_failed:
        stmt = stmt.where(AuditLog.success.is_(False))
    rows = db.scalars(stmt.order_by(AuditLog.id.desc()).offset((page - 1) * per_page).limit(per_page + 1)).all()
    return render(request, "audit.html", rows=rows[:per_page], page=page, has_next=len(rows) > per_page,
                  only_failed=only_failed)


# ---------- access requests ----------

@router.get("/requests")
def requests_list(request: Request, status: str = "pending", admin: Admin = Depends(current_admin),
                  db: Session = Depends(get_db)):
    stmt = select(AccessRequest).options(joinedload(AccessRequest.recipient))
    if status:
        stmt = stmt.where(AccessRequest.status == status)
    rows = db.scalars(stmt.order_by(AccessRequest.created_at.desc()).limit(500)).all()
    return render(request, "requests.html", rows=rows, status=status)


@router.get("/requests/{req_id}")
def request_detail(req_id: str, request: Request, admin: Admin = Depends(current_admin),
                   db: Session = Depends(get_db)):
    req = _get_or_404(db, AccessRequest, req_id)
    keys = db.scalars(select(SecretKey).where(SecretKey.status == "active").order_by(SecretKey.name)).all()
    return render(request, "request_detail.html", req=req, keys=keys, form={"recipient_name": req.name})


@router.post("/requests/{req_id}/approve")
def request_approve(req_id: str, request: Request, recipient_name: str = Form(""),
                    key_ids: list[str] = Form(default=[]), note: str = Form(""), csrf_token: str = Form(""),
                    admin: Admin = Depends(current_admin), db: Session = Depends(get_db)):
    verify_csrf(request, csrf_token)
    req = _get_or_404(db, AccessRequest, req_id)
    try:
        r = access.approve(db, get_kek(), get_settings(), req, recipient_name=recipient_name,
                           key_ids=key_ids, note=note, actor=admin.username)
    except ServiceError as ex:
        db.rollback()
        keys = db.scalars(select(SecretKey).where(SecretKey.status == "active").order_by(SecretKey.name)).all()
        return render(request, "request_detail.html", status_code=ex.status, error=ex.message, req=req, keys=keys,
                      form={"recipient_name": recipient_name, "note": note, "key_ids": key_ids})
    audit(db, "admin", admin.username, "access.approve", f"request:{req.id}", client_ip(request), True,
          f"bên nhận={r.name} keys={','.join(k.name for k in r.keys) or '-'}")
    db.commit()
    flash(request, f"Đã duyệt yêu cầu và tạo bên nhận '{r.name}'. Người xin quyền có thể nhận thông tin bằng claim token.")
    return redirect(f"/dashboard/requests/{req.id}")


@router.post("/requests/{req_id}/reject")
def request_reject(req_id: str, request: Request, note: str = Form(""), csrf_token: str = Form(""),
                   admin: Admin = Depends(current_admin), db: Session = Depends(get_db)):
    verify_csrf(request, csrf_token)
    req = _get_or_404(db, AccessRequest, req_id)
    try:
        access.reject(req, note=note, actor=admin.username)
    except ServiceError as ex:
        flash(request, ex.message, "error")
        return redirect(f"/dashboard/requests/{req.id}")
    audit(db, "admin", admin.username, "access.reject", f"request:{req.id}", client_ip(request), True, note[:200])
    db.commit()
    flash(request, "Đã từ chối yêu cầu.")
    return redirect("/dashboard/requests")
