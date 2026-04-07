# ============================================================
#  audit/audit_logger.py — Immutable Audit Logging
# ============================================================
#
#  WHY IS AUDIT LOGGING CRITICAL IN ZERO TRUST?
#  Zero Trust principle: "Assume breach."
#  When a breach happens, you NEED to know:
#    - Who accessed what, when, from where
#    - What decisions were made and why
#    - What was the risk score at the time
#    - What actions were taken
#
#  Without audit logs, you can't:
#    - Detect attacks in progress
#    - Do forensic analysis after an incident
#    - Meet compliance requirements (SOC2, ISO 27001, GDPR)
#    - Prove what happened in court/audit
#
#  IMMUTABILITY:
#  Audit logs must be append-only — nothing can be deleted or changed.
#  In real systems: write to WORM storage, blockchain, or a SIEM like
#  Splunk/ELK/Azure Sentinel.
#
#  LOG WHAT:
#  Every access request (allowed AND denied), every authentication
#  event, every policy decision, every anomaly.
#  "Log everything, store securely, review regularly."
# ============================================================

import json
import uuid
import os
from datetime import datetime, timezone
from dataclasses import dataclass, asdict, field
from typing import Optional
from config.settings import config


@dataclass
class AuditEvent:
    """
    A single audit log entry.

    Every event that matters in the system creates one of these.
    The fields provide a complete picture of what happened.
    """
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = ""         # "ACCESS_REQUEST", "LOGIN", "POLICY_DECISION", etc.
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # Who
    user_id: str = ""
    username: str = ""
    session_id: str = ""

    # What
    resource: str = ""
    action: str = ""             # "GET", "POST", "DELETE", etc.

    # Where
    ip_address: str = ""
    device_fingerprint: str = ""
    location: str = ""

    # Decision
    risk_score: float = 0.0
    risk_level: str = ""
    policy_decision: str = ""    # ALLOW, DENY, STEP_UP_AUTH, etc.
    access_level: str = ""

    # Extra context
    details: dict = field(default_factory=dict)
    risk_factors: list = field(default_factory=list)


class AuditLogger:
    """
    Writes audit events to a structured log file and in-memory store.

    FORMAT:
    Each log entry is one JSON object per line (JSONL format).
    This is standard in security logging — easy to parse, stream,
    and ingest into SIEM tools.

    IN PRODUCTION:
    - Send to SIEM (Splunk, Elastic/ELK, Azure Sentinel)
    - Write to WORM (Write-Once-Read-Many) storage
    - Encrypt logs at rest
    - Set up log retention policies
    - Configure real-time alerting on high-risk events
    """

    def __init__(self):
        self.log_path = config.audit_log_path
        self._ensure_log_directory()
        self._in_memory_log = []    # Also keep in memory for quick queries

    def _ensure_log_directory(self):
        """Create the audit directory if it doesn't exist."""
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)

    def log(self, event: AuditEvent):
        """
        Write an audit event to log file and in-memory store.

        We use JSONL (one JSON per line) for the file format.
        This makes it easy to:
        - Append without reading the whole file
        - Parse line by line for analysis
        - Stream to external systems
        """
        self._in_memory_log.append(event)

        # Write to file
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(asdict(event)) + "\n")
        except Exception as e:
            # Logging errors should never crash the application
            print(f"[AUDIT WARNING] Failed to write audit log: {e}")

    def log_access_request(
        self,
        user_id: str,
        username: str,
        resource: str,
        action: str,
        risk_score: float,
        risk_level: str,
        policy_decision: str,
        access_level: str,
        ip_address: str = "",
        device_fingerprint: str = "",
        session_id: str = "",
        risk_factors: list = None
    ):
        """Convenience method to log an access control decision."""
        event = AuditEvent(
            event_type="ACCESS_REQUEST",
            user_id=user_id,
            username=username,
            session_id=session_id,
            resource=resource,
            action=action,
            ip_address=ip_address,
            device_fingerprint=device_fingerprint,
            risk_score=risk_score,
            risk_level=risk_level,
            policy_decision=policy_decision,
            access_level=access_level,
            risk_factors=risk_factors or []
        )
        self.log(event)

    def log_login(self, user_id: str, username: str, success: bool, ip_address: str = "", details: dict = None):
        """Log a login attempt (success or failure)."""
        event = AuditEvent(
            event_type="LOGIN_SUCCESS" if success else "LOGIN_FAILURE",
            user_id=user_id,
            username=username,
            action="LOGIN",
            ip_address=ip_address,
            details=details or {}
        )
        self.log(event)

    def log_security_alert(self, user_id: str, username: str, alert_type: str, details: dict = None):
        """Log a security alert (anomaly detected, policy violation, etc.)."""
        event = AuditEvent(
            event_type="SECURITY_ALERT",
            user_id=user_id,
            username=username,
            details={"alert_type": alert_type, **(details or {})}
        )
        self.log(event)

    def get_recent_events(self, limit: int = 50) -> list:
        """Get the most recent audit events from memory."""
        return [
            {k: v for k, v in vars(e).items()} if hasattr(e, '__dict__')
            else e.__dict__ if hasattr(e, '__dict__')
            else vars(e)
            for e in self._in_memory_log[-limit:]
        ]

    def get_events_for_user(self, user_id: str, limit: int = 20) -> list:
        """Get audit events for a specific user."""
        user_events = [e for e in self._in_memory_log if e.user_id == user_id]
        return user_events[-limit:]

    def get_denied_requests(self, limit: int = 20) -> list:
        """Get recently denied access requests — useful for security monitoring."""
        denied = [e for e in self._in_memory_log if e.policy_decision == "DENY"]
        return denied[-limit:]


# Global audit logger instance — used across the whole application
audit_logger = AuditLogger()