# ============================================================
#  models.py — SQLAlchemy ORM Models (Table Definitions)
# ============================================================
#
#  WHAT ARE ORM MODELS?
#  Each class here represents a database table.
#  Each instance of a class represents a row in that table.
#  SQLAlchemy translates between Python objects and SQL automatically.
#
#  Example:
#    Python:  user = UserModel(username="alice", email="alice@test.com")
#             db.add(user)
#             db.commit()
#    SQL:     INSERT INTO users (username, email, ...) VALUES ('alice', 'alice@test.com', ...)
#
#  TABLES:
#    users              — Registered user accounts
#    sessions           — Active login sessions (JWT tracking)
#    devices            — Registered device profiles (posture data)
#    audit_events       — Immutable audit log entries
#    blacklisted_tokens — Revoked JWT tokens (logout/security)
#
#  RELATIONSHIP TO DATACLASSES:
#  The existing dataclasses (User, Session, DeviceProfile, AuditEvent)
#  remain as DTOs (Data Transfer Objects). These ORM models handle
#  persistence; the dataclasses handle business logic.
# ============================================================

from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, Text, DateTime,
    ForeignKey, JSON
)
from database import Base


class UserModel(Base):
    """
    Persists user accounts to the 'users' table.

    Maps to the identity.auth_services.User dataclass.
    Stores hashed passwords — NEVER plain text.
    """
    __tablename__ = "users"

    user_id         = Column(String, primary_key=True)
    username        = Column(String, unique=True, nullable=False, index=True)
    email           = Column(String, nullable=False)
    hashed_password = Column(String, nullable=False)
    role            = Column(String, default="user")
    is_active       = Column(Boolean, default=True)
    failed_attempts = Column(Integer, default=0)
    mfa_enabled     = Column(Boolean, default=False)
    created_at      = Column(String, default=lambda: datetime.now(timezone.utc).isoformat())
    last_login      = Column(String, nullable=True)


class SessionModel(Base):
    """
    Persists login sessions to the 'sessions' table.

    Each login creates a new session with access + refresh tokens.
    Logout sets is_active=False. Token refresh updates the access_token.
    """
    __tablename__ = "sessions"

    session_id    = Column(String, primary_key=True)
    user_id       = Column(String, ForeignKey("users.user_id"), nullable=False, index=True)
    access_token  = Column(Text, nullable=False)
    refresh_token = Column(Text, nullable=False)
    created_at    = Column(String, default=lambda: datetime.now(timezone.utc).isoformat())
    last_active   = Column(String, default=lambda: datetime.now(timezone.utc).isoformat())
    ip_address    = Column(String, default="")
    user_agent    = Column(String, default="")
    is_active     = Column(Boolean, default=True)


class DeviceModel(Base):
    """
    Persists device profiles to the 'devices' table.

    Tracks the security posture of each device that connects
    to the system (OS, encryption, antivirus, patch status, etc.).
    """
    __tablename__ = "devices"

    device_id        = Column(String, primary_key=True)
    fingerprint      = Column(String, unique=True, nullable=False, index=True)
    owner_user_id    = Column(String, nullable=False)
    os_type          = Column(String, default="unknown")
    os_version       = Column(String, default="unknown")
    is_managed       = Column(Boolean, default=False)
    last_patch_date  = Column(String, nullable=True)
    is_encrypted     = Column(Boolean, default=False)
    has_antivirus    = Column(Boolean, default=False)
    is_jailbroken    = Column(Boolean, default=False)
    compliance_score = Column(Float, default=0.0)
    trust_level      = Column(String, default="UNTRUSTED")
    last_seen        = Column(String, default=lambda: datetime.now(timezone.utc).isoformat())
    registered_at    = Column(String, default=lambda: datetime.now(timezone.utc).isoformat())


class AuditEventModel(Base):
    """
    Persists audit log entries to the 'audit_events' table.

    Every access request, login attempt, and security alert
    is recorded here for forensic analysis and compliance.
    """
    __tablename__ = "audit_events"

    event_id          = Column(String, primary_key=True)
    event_type        = Column(String, default="", index=True)
    timestamp         = Column(String, default=lambda: datetime.now(timezone.utc).isoformat(), index=True)

    # Who
    user_id           = Column(String, default="", index=True)
    username          = Column(String, default="")
    session_id        = Column(String, default="")

    # What
    resource          = Column(String, default="")
    action            = Column(String, default="")

    # Where
    ip_address        = Column(String, default="")
    device_fingerprint = Column(String, default="")
    location          = Column(String, default="")

    # Decision
    risk_score        = Column(Float, default=0.0)
    risk_level        = Column(String, default="")
    policy_decision   = Column(String, default="", index=True)
    access_level      = Column(String, default="")

    # Extra context (stored as JSON)
    details           = Column(JSON, default=dict)
    risk_factors      = Column(JSON, default=list)


class BlacklistedTokenModel(Base):
    """
    Tracks revoked JWT tokens.

    When a user logs out, the token's JTI (unique ID) is added here.
    On every request, we check this table to reject revoked tokens.
    This replaces the need for Redis in a single-node deployment.
    """
    __tablename__ = "blacklisted_tokens"

    jti             = Column(String, primary_key=True)
    blacklisted_at  = Column(String, default=lambda: datetime.now(timezone.utc).isoformat())
