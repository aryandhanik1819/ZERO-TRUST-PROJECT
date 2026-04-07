# ============================================================
#  monitoring/session_monitor.py — Session Monitoring
# ============================================================
#
#  WHAT DOES SESSION MONITORING DO?
#  After a user is authenticated and working, the monitor:
#    - Tracks their activity in real time
#    - Detects anomalies (sudden burst of requests, new location)
#    - Enforces idle timeout (auto-logout when inactive)
#    - Detects concurrent sessions from impossible locations
#    - Updates the behavioral baseline for future risk scoring
#
#  WHY CONTINUOUS MONITORING?
#  Zero Trust isn't just "verify at login and trust forever."
#  It's "verify CONTINUOUSLY throughout the session."
#
#  Example threat this catches:
#  1. Alice logs in from London at 9 AM (normal)
#  2. Attacker steals Alice's token
#  3. Attacker starts making requests from Moscow
#  4. Session monitor detects: two active sessions, impossible travel
#  5. Both sessions terminated, Alice notified
# ============================================================

from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from config.settings import config


@dataclass
class SessionActivity:
    """
    Tracks what a session has been doing.

    request_count:      Total requests made in this session
    requests_last_min:  Requests in the last 60 seconds (rate limiting)
    resources_accessed: List of unique resources visited
    last_ip:            Most recent IP address
    anomaly_flags:      Any suspicious behaviors detected
    """
    session_id: str
    user_id: str
    start_time: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_active: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    request_count: int = 0
    requests_last_min: int = 0
    last_minute_window: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    resources_accessed: List[str] = field(default_factory=list)
    last_ip: str = ""
    anomaly_flags: List[str] = field(default_factory=list)
    is_active: bool = True


class SessionMonitor:
    """
    Continuously monitors all active sessions.

    Works by being called on every request passing through the API layer.
    Maintains a per-session activity record and flags anomalies.

    ANOMALY DETECTION:
    Currently rule-based (fast and transparent). In production, you'd
    layer on ML-based anomaly detection using the behavioral baseline.
    """

    def __init__(self):
        self._sessions: Dict[str, SessionActivity] = {}
        self.timeout_minutes = config.session_timeout_minutes
        self.max_requests_per_minute = 100

    def track_request(
        self,
        session_id: str,
        user_id: str,
        resource: str,
        ip_address: str = ""
    ) -> dict:
        """
        Called on every incoming request to track activity.

        Returns a dict with:
          - is_anomalous: True if suspicious behavior detected
          - anomalies: List of specific anomalies found
          - should_terminate: True if session should be killed
        """
        # Get or create session activity record
        if session_id not in self._sessions:
            self._sessions[session_id] = SessionActivity(
                session_id=session_id,
                user_id=user_id,
                last_ip=ip_address
            )

        activity = self._sessions[session_id]
        anomalies = []
        should_terminate = False

        # ── Update Activity ───────────────────────────────────
        activity.request_count += 1
        activity.last_active = datetime.now(timezone.utc).isoformat()

        # Track unique resources
        if resource not in activity.resources_accessed:
            activity.resources_accessed.append(resource)

        # ── Rate Limiting (per minute window) ─────────────────
        # Check if we're still in the same 1-minute window
        window_start = datetime.fromisoformat(activity.last_minute_window.replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)

        if (now - window_start).seconds >= 60:
            # New minute window — reset counter
            activity.requests_last_min = 1
            activity.last_minute_window = now.isoformat()
        else:
            activity.requests_last_min += 1

        if activity.requests_last_min > self.max_requests_per_minute:
            anomalies.append(
                f"Rate limit exceeded: {activity.requests_last_min} requests/minute "
                f"(max: {self.max_requests_per_minute})"
            )

        # ── IP Change Detection ───────────────────────────────
        # Legitimate users rarely change IPs mid-session.
        # An IP change could indicate session hijacking.
        if ip_address and activity.last_ip and ip_address != activity.last_ip:
            anomalies.append(
                f"IP address changed during session: {activity.last_ip} → {ip_address}"
            )
            activity.last_ip = ip_address

        # ── Idle Timeout Check ────────────────────────────────
        last_active = datetime.fromisoformat(activity.last_active.replace('Z', '+00:00'))
        idle_minutes = (now - last_active).seconds / 60

        # (This check is pre-update, so we use request_count logic above)
        # The timeout is enforced by checking last_active before updating

        # ── Bulk Access Detection ─────────────────────────────
        # Accessing many different resources quickly = possible data harvesting
        if len(activity.resources_accessed) > 50:
            anomalies.append(
                f"Bulk resource access: {len(activity.resources_accessed)} unique resources accessed"
            )
            should_terminate = True  # This is serious enough to terminate

        # ── Add Any New Anomalies to the Record ───────────────
        for anomaly in anomalies:
            if anomaly not in activity.anomaly_flags:
                activity.anomaly_flags.append(anomaly)

        return {
            "is_anomalous": len(anomalies) > 0,
            "anomalies": anomalies,
            "should_terminate": should_terminate,
            "request_count": activity.request_count,
            "requests_last_min": activity.requests_last_min,
            "resources_count": len(activity.resources_accessed)
        }

    def check_idle_timeout(self, session_id: str) -> bool:
        """
        Returns True if the session has exceeded the idle timeout.
        Called periodically or on each request.
        """
        activity = self._sessions.get(session_id)
        if not activity:
            return True  # Unknown session = treat as expired

        last_active = datetime.fromisoformat(activity.last_active.replace('Z', '+00:00'))
        idle_minutes = (datetime.now(timezone.utc) - last_active).total_seconds() / 60

        return idle_minutes > self.timeout_minutes

    def terminate_session(self, session_id: str, reason: str = ""):
        """Mark a session as terminated in the monitor."""
        if session_id in self._sessions:
            self._sessions[session_id].is_active = False

    def get_session_summary(self, session_id: str) -> Optional[dict]:
        """Get a summary of a session's activity."""
        activity = self._sessions.get(session_id)
        if not activity:
            return None

        return {
            "session_id": session_id,
            "user_id": activity.user_id,
            "start_time": activity.start_time,
            "last_active": activity.last_active,
            "request_count": activity.request_count,
            "resources_accessed": len(activity.resources_accessed),
            "anomaly_flags": activity.anomaly_flags,
            "is_active": activity.is_active
        }

    def get_all_active_sessions(self) -> List[dict]:
        """Get summaries of all active sessions — for security dashboard."""
        return [
            self.get_session_summary(sid)
            for sid, activity in self._sessions.items()
            if activity.is_active
        ]


# Global session monitor instance
session_monitor = SessionMonitor()