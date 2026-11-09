"""Công cụ quản trị dòng lệnh.

    python -m app.manage gen-secrets          # sinh KV_MASTER_KEY và KV_SESSION_SECRET
    python -m app.manage create-admin <user>  # tạo admin (mật khẩu + Google Authenticator)
"""
import argparse
import base64
import getpass
import secrets
import sys


def gen_secrets() -> None:
    print(f"KV_MASTER_KEY={base64.b64encode(secrets.token_bytes(32)).decode()}")
    print(f"KV_SESSION_SECRET={secrets.token_urlsafe(48)}")


def create_admin(username: str) -> None:
    import qrcode

    from . import services, totp
    from .config import get_settings
    from .crypto import get_kek
    from .db import SessionLocal, init_db

    init_db()
    password = getpass.getpass("Mật khẩu (tối thiểu 12 ký tự): ")
    if len(password) < 12:
        sys.exit("Mật khẩu quá ngắn")
    if getpass.getpass("Nhập lại mật khẩu: ") != password:
        sys.exit("Mật khẩu không khớp")

    secret = totp.new_secret()
    uri = totp.provisioning_uri(secret, f"admin:{username}", get_settings().totp_issuer)
    qr = qrcode.QRCode(border=1)
    qr.add_data(uri)
    qr.print_ascii(invert=True)
    print(f"\nQuét QR bằng Google Authenticator, hoặc nhập thủ công secret: {secret}\n")

    for _ in range(3):
        code = input("Nhập mã OTP 6 số để xác nhận: ").strip()
        step = totp.match_step(secret, code, 0)
        if step is not None:
            break
        print("Mã không đúng, thử lại.")
    else:
        sys.exit("Xác nhận OTP thất bại, admin chưa được tạo")

    with SessionLocal() as db:
        try:
            admin = services.create_admin(db, get_kek(), username, password, secret)
        except services.ServiceError as ex:
            sys.exit(ex.message)
        admin.last_totp_step = step
        services.audit(db, "admin", "cli", "admin.create", f"admin:{username}", None, True)
        db.commit()
    print(f"Đã tạo admin '{username}'. Lưu ý: chờ mã OTP kế tiếp (30 giây) để đăng nhập dashboard.")


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m app.manage")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("gen-secrets")
    p = sub.add_parser("create-admin")
    p.add_argument("username")
    args = parser.parse_args()
    if args.cmd == "gen-secrets":
        gen_secrets()
    elif args.cmd == "create-admin":
        create_admin(args.username)


if __name__ == "__main__":
    main()
