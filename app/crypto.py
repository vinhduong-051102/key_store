"""Primitive mật mã dùng trong KeyVault.

- AES-256-GCM cho mọi dữ liệu được mã hóa.
- Envelope encryption: mỗi key có DEK riêng, DEK được wrap bằng KEK (master key).
- Wrap DEK export cho bên nhận: X25519 ECDH + HKDF-SHA256 + AES-256-GCM.
"""
import base64
import hashlib
import hmac
import os
import secrets
from functools import lru_cache

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .config import get_settings

NONCE_SIZE = 12
WRAP_INFO = b"keyvault-export-wrap-v1"


def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(NONCE_SIZE)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def aead_decrypt(key: bytes, blob: bytes, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(blob[:NONCE_SIZE], blob[NONCE_SIZE:], aad)


class KeyEncryptionKey:
    """KEK cục bộ từ KV_MASTER_KEY.

    Production: thay bằng adapter KMS/HSM (AWS KMS, GCP KMS, Vault Transit...)
    với cùng interface wrap/unwrap/fingerprint.
    """

    VERSION = b"\x01"

    def __init__(self, master_key: bytes) -> None:
        if len(master_key) != 32:
            raise ValueError("master key phải 32 byte")
        self._enc_key = HKDF(hashes.SHA256(), 32, None, b"keyvault-kek-enc").derive(master_key)
        self._fp_key = HKDF(hashes.SHA256(), 32, None, b"keyvault-fingerprint").derive(master_key)

    def wrap(self, data: bytes, context: str) -> bytes:
        return self.VERSION + aead_encrypt(self._enc_key, data, b"kek|" + context.encode())

    def unwrap(self, blob: bytes, context: str) -> bytes:
        if blob[:1] != self.VERSION:
            raise ValueError("Phiên bản KEK blob không được hỗ trợ")
        return aead_decrypt(self._enc_key, blob[1:], b"kek|" + context.encode())

    def fingerprint(self, value: bytes) -> str:
        # HMAC thay vì hash thường để fingerprint không làm lộ giá trị có entropy thấp.
        return hmac.new(self._fp_key, value, hashlib.sha256).hexdigest()[:16]


@lru_cache
def get_kek() -> KeyEncryptionKey:
    return KeyEncryptionKey(get_settings().master_key)


# ---------- Wrap cho bên nhận (X25519) ----------

def _raw_pub(pub: X25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _derive_wrap_key(shared: bytes, eph_pub: bytes, recipient_pub: bytes) -> bytes:
    return HKDF(hashes.SHA256(), 32, None, WRAP_INFO + eph_pub + recipient_pub).derive(shared)


def wrap_for_recipient(secret: bytes, recipient_pub_raw: bytes, aad: bytes) -> bytes:
    """Kết quả: eph_pub(32) || nonce(12) || ciphertext+tag."""
    rpub = X25519PublicKey.from_public_bytes(recipient_pub_raw)
    eph = X25519PrivateKey.generate()
    eph_pub = _raw_pub(eph.public_key())
    key = _derive_wrap_key(eph.exchange(rpub), eph_pub, recipient_pub_raw)
    return eph_pub + aead_encrypt(key, secret, aad)


def unwrap_with_private_key(priv: X25519PrivateKey, wrapped: bytes, aad: bytes) -> bytes:
    eph_pub = wrapped[:32]
    rpub = _raw_pub(priv.public_key())
    key = _derive_wrap_key(priv.exchange(X25519PublicKey.from_public_bytes(eph_pub)), eph_pub, rpub)
    return aead_decrypt(key, wrapped[32:], aad)


def parse_public_key(text: str) -> bytes:
    """Nhận public key X25519 dạng base64 (32 byte raw) hoặc PEM. Trả về raw 32 byte."""
    text = (text or "").strip()
    if not text:
        raise ValueError("Public key trống")
    if text.startswith("-----BEGIN"):
        pub = serialization.load_pem_public_key(text.encode())
        if not isinstance(pub, X25519PublicKey):
            raise ValueError("Public key phải là X25519")
        return _raw_pub(pub)
    try:
        raw = base64.b64decode("".join(text.split()), validate=True)
    except Exception as exc:
        raise ValueError("Public key không phải base64 hợp lệ") from exc
    if len(raw) != 32:
        raise ValueError("Public key X25519 phải dài 32 byte")
    X25519PublicKey.from_public_bytes(raw)
    return raw


# ---------- API key & mật khẩu ----------

def new_api_key() -> str:
    return "kv_" + secrets.token_urlsafe(32)


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**15, r=8, p=1, maxmem=64 * 1024 * 1024)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(digest).decode()


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, salt_b64, digest_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        digest = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt_b64),
                                n=2**15, r=8, p=1, maxmem=64 * 1024 * 1024)
        return hmac.compare_digest(digest, base64.b64decode(digest_b64))
    except Exception:
        return False


# Dùng để chạy scrypt giả khi username không tồn tại (chống dò username qua thời gian phản hồi).
DUMMY_PASSWORD_HASH = hash_password(secrets.token_urlsafe(16))
