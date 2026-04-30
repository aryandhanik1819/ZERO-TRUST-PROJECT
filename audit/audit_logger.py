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
#
#  PERSISTENCE:
#  Events are stored in SQLite via SQLAlchemy AND written to a
#  JSONL file for backward compatibility and SIEM export.
# ============================================================

import json
import uuid
import os
from datetime import datetime, timezone
from dataclasses import dataclass, asdict, field
from typing import Optional
from config.settings import config
from database import SessionLocal
from models import AuditEventModel


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
    Writes audit events to the database AND a structured log file.

    FORMAT:
    Each log entry is one JSON object per line (JSONL format).
    This is standard in security logging — easy to parse, stream,
    and ingest into SIEM tools.

    DUAL STORAGE:
    - SQLite database: for fast queries (recent events, user events, etc.)
    - JSONL file: for backward compatibility and SIEM export

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

    def _ensure_log_directory(self):
        """Create the audit directory if it doesn't exist."""
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)

    def log(self, event: AuditEvent):
        """
        Write an audit event to database and log file.

        We use JSONL (one JSON per line) for the file format.
        This makes it easy to:
        - Append without reading the whole file
        - Parse line by line for analysis
        - Stream to external systems
        """
        # Write to database
        db = SessionLocal()
        try:
            db_event = AuditEventModel(
                event_id=event.event_id,
                event_type=event.event_type,
                timestamp=event.timestamp,
                user_id=event.user_id,
                username=event.username,
                session_id=event.session_id,
                resource=event.resource,
                action=event.action,
                ip_address=event.ip_address,
                device_fingerprint=event.device_fingerprint,
                location=event.location,
                risk_score=event.risk_score,
                risk_level=event.risk_level,
                policy_decision=event.policy_decision,
                access_level=event.access_level,
                details=event.details,
                risk_factors=event.risk_factors,
            )
            db.add(db_event)
            db.commit()
        except Exception as e:
            db.rollback()
            print(f"[AUDIT WARNING] Failed to write audit event to DB: {e}")
        finally:
            db.close()

        # Also write to JSONL file for backward compatibility
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(asdict(event)) + "\n")
        except Exception as e:
            # Logging errors should never crash the application
            print(f"[AUDIT WARNING] Failed to write audit log file: {e}")

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
        """Get the most recent audit events from database."""
        db = SessionLocal()
        try:
            rows = db.query(AuditEventModel).order_by(
                AuditEventModel.timestamp.desc()
            ).limit(limit).all()
            return [self._row_to_dict(r) for r in rows]
        finally:
            db.close()

    def get_events_for_user(self, user_id: str, limit: int = 20) -> list:
        """Get audit events for a specific user."""
        db = SessionLocal()
        try:
            rows = db.query(AuditEventModel).filter(
                AuditEventModel.user_id == user_id
            ).order_by(
                AuditEventModel.timestamp.desc()
            ).limit(limit).all()
            return [self._row_to_dict(r) for r in rows]
        finally:
            db.close()

    def get_denied_requests(self, limit: int = 20) -> list:
        """Get recently denied access requests — useful for security monitoring."""
        db = SessionLocal()
        try:
            rows = db.query(AuditEventModel).filter(
                AuditEventModel.policy_decision == "DENY"
            ).order_by(
                AuditEventModel.timestamp.desc()
            ).limit(limit).all()
            return [self._row_to_dict(r) for r in rows]
        finally:
            db.close()

    def get_event_count(self) -> int:
        """Get total number of audit events in the database."""
        db = SessionLocal()
        try:
            return db.query(AuditEventModel).count()
        finally:
            db.close()

    def get_dashboard_stats(self) -> dict:
        """Aggregates metrics for the frontend dashboard overview."""
        from sqlalchemy import func
        db = SessionLocal()
        try:
            total_requests = db.query(AuditEventModel).filter(AuditEventModel.event_type == "ACCESS_REQUEST").count()
            
            # Group by policy decision
            decision_counts = db.query(
                AuditEventModel.policy_decision, 
                func.count(AuditEventModel.event_id)
            ).filter(
                AuditEventModel.event_type == "ACCESS_REQUEST"
            ).group_by(AuditEventModel.policy_decision).all()
            
            allowed = sum(count for decision, count in decision_counts if decision in ["ALLOW", "ALLOW_WITH_MONITORING"])
            denied = sum(count for decision, count in decision_counts if decision == "DENY")
            step_up = sum(count for decision, count in decision_counts if decision == "STEP_UP_AUTH")
            restrict = sum(count for decision, count in decision_counts if decision == "RESTRICT")
            
            # Average risk score
            avg_risk = db.query(func.avg(AuditEventModel.risk_score)).filter(
                AuditEventModel.event_type == "ACCESS_REQUEST"
            ).scalar() or 0.0

            return {
                "total_requests": total_requests,
                "allowed": allowed,
                "denied": denied,
                "step_up": step_up,
                "restrict": restrict,
                "avg_risk_score": round(avg_risk, 1)
            }
        finally:
            db.close()

    @staticmethod
    def _row_to_dict(row: AuditEventModel) -> dict:
        """Convert an ORM row to a plain dictionary."""
        return {
            "event_id": row.event_id,
            "event_type": row.event_type,
            "timestamp": row.timestamp,
            "user_id": row.user_id,
            "username": row.username,
            "session_id": row.session_id,
            "resource": row.resource,
            "action": row.action,
            "ip_address": row.ip_address,
            "device_fingerprint": row.device_fingerprint,
            "location": row.location,
            "risk_score": row.risk_score,
            "risk_level": row.risk_level,
            "policy_decision": row.policy_decision,
            "access_level": row.access_level,
            "details": row.details or {},
            "risk_factors": row.risk_factors or [],
        }


# Global audit logger instance — used across the whole application
audit_logger = AuditLogger()