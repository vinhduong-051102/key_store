import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, LargeBinary, String, Table, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def new_id() -> str:
    return uuid.uuid4().hex


class Base(DeclarativeBase):
    pass


key_grants = Table(
    "key_grants",
    Base.metadata,
    Column("key_id", String(32), ForeignKey("keys.id", ondelete="CASCADE"), primary_key=True),
    Column("recipient_id", String(32), ForeignKey("recipients.id", ondelete="CASCADE"), primary_key=True),
)


class OtpSubjectMixin:
    totp_secret_enc: Mapped[bytes] = mapped_column(LargeBinary)
    last_totp_step: Mapped[int] = mapped_column(Integer, default=0)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Admin(OtpSubjectMixin, Base):
    __tablename__ = "admins"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Recipient(OtpSubjectMixin, Base):
    __tablename__ = "recipients"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    public_key: Mapped[str] = mapped_column(String(64))  # base64 raw X25519
    api_key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    api_key_prefix: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending|active|disabled
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    created_by: Mapped[str] = mapped_column(String(64))
    activated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    keys: Mapped[list["SecretKey"]] = relationship(secondary=key_grants, back_populates="recipients")


class SecretKey(Base):
    __tablename__ = "keys"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    dek_wrapped: Mapped[bytes] = mapped_column(LargeBinary)
    fingerprint: Mapped[str] = mapped_column(String(32))
    size_bytes: Mapped[int] = mapped_column(Integer)
    value_format: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), default="active")  # active|disabled
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    created_by: Mapped[str] = mapped_column(String(64))

    recipients: Mapped[list[Recipient]] = relationship(secondary=key_grants, back_populates="keys")


class Export(Base):
    __tablename__ = "exports"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    key_id: Mapped[str] = mapped_column(String(32), ForeignKey("keys.id"), index=True)
    recipient_id: Mapped[str] = mapped_column(String(32), ForeignKey("recipients.id"), index=True)
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)  # pending|consumed|expired|failed
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    dek_e_wrapped: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    unlocked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    request_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    unlock_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)

    key: Mapped[SecretKey] = relationship()
    recipient: Mapped[Recipient] = relationship()


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    actor_type: Mapped[str] = mapped_column(String(16))  # admin|recipient|anonymous
    actor: Mapped[str] = mapped_column(String(100))
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str | None] = mapped_column(String(200), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    details: Mapped[str] = mapped_column(Text, default="")


class AccessRequest(Base):
    __tablename__ = "access_requests"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(100))
    contact: Mapped[str] = mapped_column(String(200))
    organization: Mapped[str] = mapped_column(String(200), default="")
    reason: Mapped[str] = mapped_column(Text)
    requested_keys: Mapped[str] = mapped_column(Text, default="")
    public_key: Mapped[str | None] = mapped_column(String(64), nullable=True)  # None => server sinh cặp khóa khi claim
    claim_token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)  # pending|approved|rejected|claimed
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    request_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str] = mapped_column(String(300), default="")
    reviewed_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    review_note: Mapped[str] = mapped_column(Text, default="")
    recipient_id: Mapped[str | None] = mapped_column(String(32), ForeignKey("recipients.id"), nullable=True)
    claim_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    claim_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)

    recipient: Mapped[Recipient | None] = relationship()
