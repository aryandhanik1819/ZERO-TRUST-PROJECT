# ============================================================
#  config/settings.py — Central Configuration
# ============================================================
#
#  WHY THIS EXISTS:
#  Every part of the system reads config from ONE place.
#  If you need to change a secret key, timeout, or weight —
#  you change it here, and the whole system updates.
#  This is called the "Single Source of Truth" principle.
# ============================================================

import os
from dataclasses import dataclass, field


@dataclass
class RiskWeights:
    """
    Weights used by the Risk Engine to compute the final risk score.
    All weights must add up to 1.0 (100%).

    Think of it like a weighted exam score:
      - Identity risk counts for 35%
      - Device risk counts for 30%
      - Behavioral risk counts for 20%
      - Context risk counts for 15%
    """
    identity: float = 0.35    # Who is the user? Are credentials valid?
    device: float = 0.30      # Is the device trusted, patched, healthy?
    behavioral: float = 0.20  # Is behavior normal vs suspicious?
    context: float = 0.15     # Where/when is the request from?


@dataclass
class JWTConfig:
    """
    JWT = JSON Web Token — the digital "pass" given after login.
    SECRET_KEY signs the token so it cannot be faked.

    In production: always load secrets from environment variables,
    never hardcode them in source code.
    """
    secret_key: str = os.getenv("JWT_SECRET", "zero-trust-secret-change-in-production")
    algorithm: str = "HS256"                    # HMAC-SHA256 signing
    access_token_expire_minutes: int = 30       # Token lives 30 minutes
    refresh_token_expire_hours: int = 24        # Refresh token lives 24 hours


@dataclass
class PolicyThresholds:
    """
    Risk score ranges → access decisions:

    0–24   → ALLOW              (trusted, normal request)
    25–49  → ALLOW_WITH_MON    (allowed but watched closely)
    50–74  → STEP_UP_AUTH      (requires extra verification / 2FA)
    75–89  → RESTRICT          (limited/read-only access)
    90–100 → DENY              (blocked completely)
    """
    allow_max: int = 24
    monitor_max: int = 49
    step_up_max: int = 74
    restrict_max: int = 89


@dataclass
class AppConfig:
    """
    Master config object — the whole app imports this one object.
    """
    app_name: str = "Zero Trust Security Framework"
    version: str = "1.0.0"
    debug: bool = os.getenv("DEBUG", "false").lower() == "true"
    host: str = os.getenv("HOST", "0.0.0.0")
    port: int = int(os.getenv("PORT", "8000"))

    risk_weights: RiskWeights = field(default_factory=RiskWeights)
    jwt: JWTConfig = field(default_factory=JWTConfig)
    policy: PolicyThresholds = field(default_factory=PolicyThresholds)

    # Database
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///data/zerotrust.db")

    audit_log_path: str = "audit/audit.log"
    max_sessions_per_user: int = 3
    session_timeout_minutes: int = 60


# Single global instance — import this everywhere
config = AppConfig()