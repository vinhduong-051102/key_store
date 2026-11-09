#!/usr/bin/env python3
"""kvclient: client dành cho bên nhận key từ KeyVault.

Yêu cầu: Python 3.9+, `pip install cryptography`.

  python kvclient.py keygen --out recipient.key [--encrypt]   # tạo cặp khóa X25519, in public key
  python kvclient.py pubkey --priv recipient.key               # in lại public key
  python kvclient.py keys   --server https://vault.example.com # liệt kê key được cấp quyền
  python kvclient.py fetch  --server https://vault.example.com --key-id <id> --priv recipient.key [--out key.bin]

Xin quyền truy cập (không cần API key):
  python kvclient.py request  --server URL --name "billing" --contact a@b.com --reason "..." [--own-key recipient.key]
  python kvclient.py status   [--state kv-request.json]
  python kvclient.py claim    [--state kv-request.json] [--priv recipient.key]   # khi đã được duyệt

API key đọc từ biến môi trường KV_API_KEY (hoặc --api-key).
"""
import argparse
import base64
import getpass
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

WRAP_INFO = b"keyvault-export-wrap-v1"


# ---------- crypto ----------

def raw_pub(pub: X25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def load_private_key(path: str) -> X25519PrivateKey:
    data = open(path, "rb").read()
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except TypeError:
        pw = getpass.getpass("Passphrase của private key: ").encode()
        key = serialization.load_pem_private_key(data, password=pw)
    if not isinstance(key, X25519PrivateKey):
        sys.exit("Private key không phải X25519")
    return key


def unwrap(priv: X25519PrivateKey, wrapped: bytes, aad: bytes) -> bytes:
    eph_pub = wrapped[:32]
    shared = priv.exchange(X25519PublicKey.from_public_bytes(eph_pub))
    kek = HKDF(hashes.SHA256(), 32, None, WRAP_INFO + eph_pub + raw_pub(priv.public_key())).derive(shared)
    blob = wrapped[32:]
    return AESGCM(kek).decrypt(blob[:12], blob[12:], aad)


def aead_decrypt(key: bytes, blob: bytes, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(blob[:12], blob[12:], aad)


# ---------- HTTP ----------

def call(server: str, api_key: str | None, method: str, path: str, body: dict | None = None, cafile: str | None = None,
         headers: dict | None = None):
    url = server.rstrip("/") + path
    if not url.startswith("https://") and not os.getenv("KV_ALLOW_HTTP"):
        sys.exit("Từ chối kết nối không mã hóa. Dùng https:// (hoặc đặt KV_ALLOW_HTTP=1 khi thử nghiệm local).")
    data = json.dumps(body).encode() if body is not None else None
    hdrs = {"Content-Type": "application/json", "User-Agent": "kvclient/1.0"}
    if api_key:
        hdrs["X-API-Key"] = api_key
    hdrs.update(headers or {})
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    ctx = ssl.create_default_context(cafile=cafile) if url.startswith("https://") else None
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as err:
        try:
            detail = json.loads(err.read()).get("detail")
        except Exception:
            detail = err.reason
        sys.exit(f"Lỗi {err.code}: {detail}")


# ---------- commands ----------

def cmd_keygen(args):
    if os.path.exists(args.out):
        sys.exit(f"{args.out} đã tồn tại, không ghi đè")
    priv = X25519PrivateKey.generate()
    enc = serialization.NoEncryption()
    if args.encrypt:
        pw = getpass.getpass("Đặt passphrase: ")
        if pw != getpass.getpass("Nhập lại passphrase: "):
            sys.exit("Passphrase không khớp")
        enc = serialization.BestAvailableEncryption(pw.encode())
    pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    print(f"Đã lưu private key vào {args.out} (quyền 600). KHÔNG chia sẻ file này.")
    print("Public key (gửi cho quản trị KeyVault):")
    print(base64.b64encode(raw_pub(priv.public_key())).decode())


def cmd_pubkey(args):
    print(base64.b64encode(raw_pub(load_private_key(args.priv).public_key())).decode())


def cmd_keys(args):
    for k in call(args.server, args.api_key, "GET", "/api/v1/keys", cafile=args.cacert):
        print(f"{k['id']}  {k['name']:<30} {k['size_bytes']:>6} B  fp={k['fingerprint']}  {k['description']}")


def cmd_fetch(args):
    priv = load_private_key(args.priv)

    created = call(args.server, args.api_key, "POST", "/api/v1/exports", {"key_id": args.key_id}, args.cacert)
    expected_aad = f"kv-export-v1|{created['export_id']}|{args.key_id}|{created['recipient_id']}"
    if created["aad"] != expected_aad or created["key_id"] != args.key_id:
        sys.exit("Phản hồi từ server không khớp yêu cầu, hủy.")
    print(f"Đã nhận bản mã của key '{created['key_name']}' (hết hạn lúc {created['expires_at']} UTC).", file=sys.stderr)

    otp = args.otp or input("Nhập mã OTP từ Google Authenticator: ").strip()
    unlocked = call(args.server, args.api_key, "POST", f"/api/v1/exports/{created['export_id']}/unlock",
                    {"otp": otp}, args.cacert)
    if unlocked["aad"] != expected_aad:
        sys.exit("AAD không khớp, hủy.")

    aad = expected_aad.encode()
    dek = unwrap(priv, base64.b64decode(unlocked["wrapped_key"]), aad)
    value = aead_decrypt(dek, base64.b64decode(created["ciphertext"]), aad)

    if args.out:
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(value)
        print(f"Đã giải mã và lưu key vào {args.out} ({len(value)} byte).", file=sys.stderr)
    elif args.format == "hex":
        print(value.hex())
    elif args.format == "base64":
        print(base64.b64encode(value).decode())
    else:
        sys.stdout.buffer.write(value)
        sys.stdout.flush()


# ---------- xin quyền truy cập ----------

def _write_private(path: str, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def _load_state(path: str) -> dict:
    try:
        return json.load(open(path))
    except FileNotFoundError:
        sys.exit(f"Không tìm thấy {path}. Hãy chạy lệnh 'request' trước.")


def cmd_request(args):
    if os.path.exists(args.state):
        sys.exit(f"{args.state} đã tồn tại (đã gửi yêu cầu trước đó?). Dùng --state để chọn file khác.")
    body = {"name": args.name, "contact": args.contact, "organization": args.organization or "",
            "reason": args.reason, "requested_keys": args.requested_keys or ""}
    if args.own_key:
        body["public_key"] = base64.b64encode(raw_pub(load_private_key(args.own_key).public_key())).decode()
    res = call(args.server, None, "POST", "/api/v1/access-requests", body, args.cacert)
    _write_private(args.state, json.dumps({"server": args.server, "request_id": res["request_id"],
                                           "claim_token": res["claim_token"], "own_key": args.own_key}).encode())
    print(f"Đã gửi yêu cầu {res['request_id']}. Thông tin theo dõi lưu trong {args.state} (quyền 600, giữ bí mật).")
    print("Chờ quản trị viên duyệt, sau đó chạy:  python kvclient.py claim")


def _req_headers(st: dict) -> dict:
    return {"X-Claim-Token": st["claim_token"]}


def cmd_status(args):
    st = _load_state(args.state)
    res = call(st["server"], None, "GET", f"/api/v1/access-requests/{st['request_id']}", cafile=args.cacert,
               headers=_req_headers(st))
    labels = {"pending": "Đang chờ duyệt", "approved": "ĐÃ DUYỆT - chạy lệnh 'claim' để nhận thông tin",
              "rejected": "Bị từ chối", "claimed": "Đã nhận thông tin"}
    print(f"Trạng thái: {labels.get(res['status'], res['status'])}")
    if res.get("review_note"):
        print(f"Ghi chú của quản trị viên: {res['review_note']}")
    if res["status"] == "approved" and res.get("claim_expires_at"):
        print(f"Hạn nhận thông tin: {res['claim_expires_at']} UTC")


def cmd_claim(args):
    st = _load_state(args.state)
    if not st.get("own_key") and os.path.exists(args.priv):
        sys.exit(f"{args.priv} đã tồn tại, không ghi đè. Dùng --priv để chọn file khác.")
    res = call(st["server"], None, "POST", f"/api/v1/access-requests/{st['request_id']}/claim", {},
               args.cacert, headers=_req_headers(st))

    if res.get("private_key_pem"):
        _write_private(args.priv, res["private_key_pem"].encode())
        priv_path = args.priv
        print(f"Server đã sinh cặp khóa. Private key lưu tại {priv_path} (quyền 600). Server KHÔNG giữ bản sao.")
    else:
        priv_path = st["own_key"]
        mine = base64.b64encode(raw_pub(load_private_key(priv_path).public_key())).decode()
        if mine != res["public_key"]:
            sys.exit("Public key trên server không khớp private key của bạn, hủy.")

    st.update({"api_key": res["api_key"], "recipient_id": res["recipient_id"], "priv": priv_path})
    with open(args.state, "w") as f:
        json.dump(st, f)

    print("\n=== Thêm vào Google Authenticator ===")
    try:
        import qrcode  # tùy chọn: pip install qrcode
        qr = qrcode.QRCode(border=1)
        qr.add_data(res["otpauth_uri"])
        qr.print_ascii(invert=True)
    except ImportError:
        print("(Cài 'pip install qrcode' để hiện mã QR trong terminal)")
    print(f"Hoặc nhập thủ công secret: {res['totp_secret']}")
    print(f"\nAPI key (đã lưu vào {args.state}): {res['api_key']}")
    print("Key được cấp quyền:", ", ".join(f"{k['name']} ({k['id']})" for k in res["granted_keys"]) or "chưa có")

    for _ in range(3):
        otp = input("\nNhập mã OTP hiện trên Google Authenticator để kích hoạt: ").strip()
        try:
            call(st["server"], None, "POST", f"/api/v1/access-requests/{st['request_id']}/activate",
                 {"otp": otp}, args.cacert, headers=_req_headers(st))
            print("Đã kích hoạt! Lấy key bằng:")
            print(f"  KV_API_KEY=... python kvclient.py fetch --server {st['server']} --key-id <id> --priv {priv_path}")
            return
        except SystemExit as e:
            print(e)
    print("Kích hoạt chưa thành công. Chạy lại:  python kvclient.py activate")


def cmd_activate(args):
    st = _load_state(args.state)
    otp = args.otp or input("Nhập mã OTP: ").strip()
    call(st["server"], None, "POST", f"/api/v1/access-requests/{st['request_id']}/activate", {"otp": otp},
         args.cacert, headers=_req_headers(st))
    print("Đã kích hoạt.")


def main():
    p = argparse.ArgumentParser(description="KeyVault recipient client")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("keygen", help="tạo cặp khóa X25519")
    s.add_argument("--out", default="recipient.key")
    s.add_argument("--encrypt", action="store_true", help="mã hóa private key bằng passphrase")
    s.set_defaults(fn=cmd_keygen)

    s = sub.add_parser("pubkey", help="in public key từ private key")
    s.add_argument("--priv", default="recipient.key")
    s.set_defaults(fn=cmd_pubkey)

    for name, fn in (("keys", cmd_keys), ("fetch", cmd_fetch)):
        s = sub.add_parser(name)
        s.add_argument("--server", default=os.getenv("KV_SERVER"), required=not os.getenv("KV_SERVER"))
        s.add_argument("--api-key", default=os.getenv("KV_API_KEY"))
        s.add_argument("--cacert", help="CA bundle tùy chỉnh (PEM)")
        s.set_defaults(fn=fn)
        if name == "fetch":
            s.add_argument("--key-id", required=True)
            s.add_argument("--priv", default="recipient.key")
            s.add_argument("--otp", help="mã OTP (nếu bỏ trống sẽ hỏi khi chạy)")
            s.add_argument("--out", help="ghi key ra file (quyền 600) thay vì stdout")
            s.add_argument("--format", choices=["raw", "hex", "base64"], default="raw")

    s = sub.add_parser("request", help="gửi yêu cầu cấp quyền truy cập (không cần API key)")
    s.add_argument("--server", default=os.getenv("KV_SERVER"), required=not os.getenv("KV_SERVER"))
    s.add_argument("--name", required=True)
    s.add_argument("--contact", required=True, help="email / số điện thoại")
    s.add_argument("--organization")
    s.add_argument("--reason", required=True)
    s.add_argument("--requested-keys", help="key muốn truy cập")
    s.add_argument("--own-key", help="dùng private key có sẵn (tạo bằng keygen) thay vì để server sinh")
    s.add_argument("--state", default="kv-request.json", help="file lưu request_id + claim token")
    s.set_defaults(fn=cmd_request)
    for name, fn in (("status", cmd_status), ("claim", cmd_claim), ("activate", cmd_activate)):
        s = sub.add_parser(name)
        s.add_argument("--state", default="kv-request.json")
        if name == "claim":
            s.add_argument("--priv", default="recipient.key", help="nơi lưu private key do server sinh")
        if name == "activate":
            s.add_argument("--otp")
        s.set_defaults(fn=fn)
    for sp in sub.choices.values():
        if not any(a.dest == "cacert" for a in sp._actions):
            sp.add_argument("--cacert", help="CA bundle tùy chỉnh (PEM)")

    args = p.parse_args()
    if getattr(args, "api_key", "x") is None:
        sys.exit("Thiếu API key: đặt KV_API_KEY hoặc dùng --api-key")
    args.fn(args)


if __name__ == "__main__":
    main()
