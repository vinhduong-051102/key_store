import base64
import os
import re
import tempfile
import time

_tmp = tempfile.mkdtemp()
os.environ.update({
    "DATABASE_URL": f"sqlite:///{_tmp}/test.db",
    "KV_MASTER_KEY": base64.b64encode(os.urandom(32)).decode(),
    "KV_SESSION_SECRET": "x" * 48,
    "KV_COOKIE_SECURE": "false",
})

import pyotp  # noqa: E402
import pytest  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import services  # noqa: E402
from app.crypto import aead_decrypt, get_kek, unwrap_with_private_key  # noqa: E402
from app.db import SessionLocal  # noqa: E402
from app.main import app  # noqa: E402

ADMIN_SECRET = pyotp.random_base32(32)
ADMIN_PASSWORD = "correct horse battery staple"


def otp_at(secret: str, offset: int = 0) -> str:
    return pyotp.TOTP(secret).generate_otp(int(time.time() // 30) + offset)


def csrf(html: str) -> str:
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


@pytest.fixture(scope="module")
def client():
    with SessionLocal() as db:
        services.create_admin(db, get_kek(), "admin", ADMIN_PASSWORD, ADMIN_SECRET)
        db.commit()
    return TestClient(app)


def test_end_to_end(client):
    # Chưa đăng nhập -> chuyển về trang login
    r = client.get("/dashboard", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/dashboard/login"

    # Sai OTP -> từ chối
    tok = csrf(client.get("/dashboard/login").text)
    r = client.post("/dashboard/login", data={"username": "admin", "password": ADMIN_PASSWORD,
                                              "otp": "000000", "csrf_token": tok})
    assert r.status_code == 401

    # Thiếu CSRF -> từ chối
    r = client.post("/dashboard/login", data={"username": "admin", "password": ADMIN_PASSWORD,
                                              "otp": otp_at(ADMIN_SECRET)})
    assert r.status_code == 400

    r = client.post("/dashboard/login", data={"username": "admin", "password": ADMIN_PASSWORD,
                                              "otp": otp_at(ADMIN_SECRET), "csrf_token": tok}, follow_redirects=False)
    assert r.status_code == 303
    page = client.get("/dashboard")
    assert "Tổng quan" in page.text
    tok = csrf(page.text)

    # Thêm key qua dashboard
    secret_value = "-----BEGIN KEY-----\nsuper-secret-value\n-----END KEY-----"
    r = client.post("/dashboard/keys", data={"name": "payment-hmac", "description": "test", "value_format": "text",
                                             "value": secret_value, "random_bytes": "32", "csrf_token": tok},
                    follow_redirects=False)
    assert r.status_code == 303
    key_id = r.headers["location"].rsplit("/", 1)[-1]
    assert secret_value not in client.get(f"/dashboard/keys/{key_id}").text

    # Key thứ hai, sinh ngẫu nhiên, không cấp quyền
    r = client.post("/dashboard/keys", data={"name": "other", "value_format": "random", "random_bytes": "32",
                                             "csrf_token": tok}, follow_redirects=False)
    other_key_id = r.headers["location"].rsplit("/", 1)[-1]

    # Thêm bên nhận
    priv = X25519PrivateKey.generate()
    pub_b64 = base64.b64encode(priv.public_key().public_bytes(serialization.Encoding.Raw,
                                                              serialization.PublicFormat.Raw)).decode()
    r = client.post("/dashboard/recipients", data={"name": "billing-service", "public_key": pub_b64, "csrf_token": tok})
    assert r.status_code == 200
    api_key = re.search(r'id="api-key">([^<]+)<', r.text).group(1)
    totp_secret = re.search(r'id="totp-secret">([^<]+)<', r.text).group(1)
    rid = re.search(r'/dashboard/recipients/([0-9a-f]{32})/confirm', r.text).group(1)
    assert "<svg" in r.text

    headers = {"X-API-Key": api_key}
    # Chưa kích hoạt -> 403
    assert client.get("/api/v1/keys", headers=headers).status_code == 403

    r = client.post(f"/dashboard/recipients/{rid}/confirm", data={"otp": otp_at(totp_secret), "csrf_token": tok},
                    follow_redirects=False)
    assert r.status_code == 303
    assert "Đã kích hoạt" in client.get(f"/dashboard/recipients/{rid}").text

    # Chưa cấp quyền -> 404
    assert client.post("/api/v1/exports", json={"key_id": key_id}, headers=headers).status_code == 404

    client.post(f"/dashboard/keys/{key_id}/grants", data={"recipient_ids": [rid], "csrf_token": tok})
    keys = client.get("/api/v1/keys", headers=headers).json()
    assert [k["name"] for k in keys] == ["payment-hmac"]

    # API key sai
    assert client.get("/api/v1/keys", headers={"X-API-Key": "kv_wrong"}).status_code == 401
    # Key không được cấp quyền
    assert client.post("/api/v1/exports", json={"key_id": other_key_id}, headers=headers).status_code == 404

    # Export: nhận ciphertext
    created = client.post("/api/v1/exports", json={"key_id": key_id}, headers=headers).json()
    aad = created["aad"].encode()

    # OTP sai -> 401
    r = client.post(f"/api/v1/exports/{created['export_id']}/unlock", json={"otp": "123456"}, headers=headers)
    assert r.status_code == 401

    # OTP đúng -> giải mã được
    good = otp_at(totp_secret, +1)  # step sau step đã dùng khi kích hoạt
    r = client.post(f"/api/v1/exports/{created['export_id']}/unlock", json={"otp": good}, headers=headers)
    assert r.status_code == 200, r.text
    wrapped = base64.b64decode(r.json()["wrapped_key"])
    dek = unwrap_with_private_key(priv, wrapped, aad)
    assert aead_decrypt(dek, base64.b64decode(created["ciphertext"]), aad).decode() == secret_value

    # Không mở khóa lại được export đã dùng
    r = client.post(f"/api/v1/exports/{created['export_id']}/unlock", json={"otp": good}, headers=headers)
    assert r.status_code == 409

    # Dùng lại cùng mã OTP cho export mới -> bị chặn (chống replay)
    created2 = client.post("/api/v1/exports", json={"key_id": key_id}, headers=headers).json()
    r = client.post(f"/api/v1/exports/{created2['export_id']}/unlock", json={"otp": good}, headers=headers)
    assert r.status_code == 401

    # Private key khác không giải mã được
    with pytest.raises(Exception):
        unwrap_with_private_key(X25519PrivateKey.generate(), wrapped, aad)

    # Dashboard thấy ai đã lấy key nào
    page = client.get("/dashboard/exports").text
    assert "billing-service" in page and "payment-hmac" in page and "Đã lấy" in page
    audit = client.get("/dashboard/audit").text
    assert "export.unlock" in audit and "key.create" in audit

    # Vô hiệu bên nhận -> API bị chặn
    client.post(f"/dashboard/recipients/{rid}/toggle", data={"csrf_token": tok})
    assert client.get("/api/v1/keys", headers=headers).status_code == 403


def test_lockout_after_failed_otps(client):
    with SessionLocal() as db:
        r, api_key, secret = services.create_recipient(
            db, get_kek(), name="locker",
            public_key=base64.b64encode(X25519PrivateKey.generate().public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode(),
            description="", actor="test")
        r.status = "active"
        k = services.create_key(db, get_kek(), name="lock-key", description="", value=b"v",
                                value_format="text", actor="test")
        k.recipients.append(r)
        db.commit()
        key_id = k.id
    headers = {"X-API-Key": api_key}
    codes = []
    for _ in range(5):
        e = client.post("/api/v1/exports", json={"key_id": key_id}, headers=headers).json()
        codes.append(client.post(f"/api/v1/exports/{e['export_id']}/unlock", json={"otp": "000000"},
                                 headers=headers).status_code)
    assert codes == [401] * 5
    e = client.post("/api/v1/exports", json={"key_id": key_id}, headers=headers).json()
    r = client.post(f"/api/v1/exports/{e['export_id']}/unlock", json={"otp": otp_at(secret)}, headers=headers)
    assert r.status_code == 429


def _admin_client():
    c = TestClient(app)
    tok = csrf(c.get("/dashboard/login").text)
    # Mỗi lần đăng nhập dùng step mới để không bị chặn replay
    with SessionLocal() as db:
        from app.models import Admin
        a = db.query(Admin).filter_by(username="admin").one()
        a.last_totp_step = 0
        db.commit()
    r = c.post("/dashboard/login", data={"username": "admin", "password": ADMIN_PASSWORD,
                                         "otp": otp_at(ADMIN_SECRET), "csrf_token": tok})
    assert r.status_code == 200
    return c, csrf(r.text)


@pytest.mark.parametrize("own_key", [False, True])
def test_access_request_flow(client, own_key):
    from app import api_access
    api_access.limiter._hits.clear()
    anon = TestClient(app)
    own_priv = X25519PrivateKey.generate()
    body = {"name": f"partner-{own_key}", "contact": "a@example.com", "reason": "Cần key để tích hợp",
            "requested_keys": "payment-hmac"}
    if own_key:
        body["public_key"] = base64.b64encode(own_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    created = anon.post("/api/v1/access-requests", json=body)
    assert created.status_code == 201, created.text
    rid, token = created.json()["request_id"], created.json()["claim_token"]
    h = {"X-Claim-Token": token}

    assert anon.get(f"/api/v1/access-requests/{rid}", headers={"X-Claim-Token": "kvr_wrong"}).status_code == 404
    assert anon.get(f"/api/v1/access-requests/{rid}", headers=h).json()["status"] == "pending"
    assert anon.post(f"/api/v1/access-requests/{rid}/claim", headers=h).status_code == 409

    admin_c, tok = _admin_client()
    page = admin_c.get("/dashboard/requests").text
    assert f"partner-{own_key}" in page and 'class="count"' in page
    with SessionLocal() as db:
        k = services.create_key(db, get_kek(), name=f"partner-key-{own_key}", description="", value=b"partner-secret",
                                value_format="text", actor="test")
        db.commit()
        key_id = k.id
    r = admin_c.post(f"/dashboard/requests/{rid}/approve",
                     data={"recipient_name": f"partner-{own_key}", "key_ids": [key_id], "note": "OK", "csrf_token": tok})
    assert r.status_code == 200 and "Đã duyệt" in r.text
    assert anon.get(f"/api/v1/access-requests/{rid}", headers=h).json()["status"] == "approved"

    claimed = anon.post(f"/api/v1/access-requests/{rid}/claim", headers=h)
    assert claimed.status_code == 200, claimed.text
    c = claimed.json()
    assert (c["private_key_pem"] is None) == own_key
    assert c["granted_keys"][0]["id"] == key_id
    assert anon.post(f"/api/v1/access-requests/{rid}/claim", headers=h).status_code == 409  # chỉ nhận 1 lần

    priv = own_priv if own_key else serialization.load_pem_private_key(c["private_key_pem"].encode(), None)
    api_h = {"X-API-Key": c["api_key"]}
    assert anon.get("/api/v1/keys", headers=api_h).status_code == 403  # chưa kích hoạt
    assert anon.post(f"/api/v1/access-requests/{rid}/activate", json={"otp": "000000"}, headers=h).status_code == 400
    assert anon.post(f"/api/v1/access-requests/{rid}/activate", json={"otp": otp_at(c["totp_secret"])},
                     headers=h).status_code == 200

    e = anon.post("/api/v1/exports", json={"key_id": key_id}, headers=api_h).json()
    u = anon.post(f"/api/v1/exports/{e['export_id']}/unlock", json={"otp": otp_at(c["totp_secret"], 1)}, headers=api_h)
    assert u.status_code == 200, u.text
    aad = e["aad"].encode()
    dek = unwrap_with_private_key(priv, base64.b64decode(u.json()["wrapped_key"]), aad)
    assert aead_decrypt(dek, base64.b64decode(e["ciphertext"]), aad) == b"partner-secret"


def test_access_request_reject_and_rate_limit(client):
    from app import api_access
    api_access.limiter._hits.clear()
    anon = TestClient(app)
    body = {"name": "spammer", "contact": "x@y.z", "reason": "?"}
    r = anon.post("/api/v1/access-requests", json=body).json()
    admin_c, tok = _admin_client()
    admin_c.post(f"/dashboard/requests/{r['request_id']}/reject", data={"note": "Không xác minh được", "csrf_token": tok})
    h = {"X-Claim-Token": r["claim_token"]}
    st = anon.get(f"/api/v1/access-requests/{r['request_id']}", headers=h).json()
    assert st["status"] == "rejected" and st["review_note"] == "Không xác minh được"
    assert anon.post(f"/api/v1/access-requests/{r['request_id']}/claim", headers=h).status_code == 403
    codes = [anon.post("/api/v1/access-requests", json=body).status_code for _ in range(6)]
    assert codes[-1] == 429
