# ============================================================
#  policy/policy_engine.py — Policy Decision Engine
# ============================================================
#
#  WHAT IS THE POLICY ENGINE?
#  After the risk engine says "this request scores 67/100",
#  the policy engine answers: "so what do we DO about it?"
#
#  This is the enforcement brain. It takes a risk score and
#  outputs a concrete access decision with instructions.
#
#  Zero Trust principle: "Never trust, always verify."
#  Every single request — even from inside the network —
#  gets evaluated before access is granted.
#
#  DECISION FLOW:
#    Risk Score → Decision → Access Level → Required Actions
# ============================================================

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional
from datetime import datetime
from config.settings import config
from policy.rules.risk_scorer import RiskAssessment


# ── Decision Types ────────────────────────────────────────────

class AccessDecision(str, Enum):
    """
    The 5 possible outcomes from the policy engine.

    Using an Enum (not plain strings) means:
    - No typos ("ALOW" won't compile)
    - IDE autocomplete works
    - You can compare with == safely
    """
    ALLOW = "ALLOW"
    ALLOW_WITH_MONITORING = "ALLOW_WITH_MONITORING"
    STEP_UP_AUTH = "STEP_UP_AUTH"
    RESTRICT = "RESTRICT"
    DENY = "DENY"


class AccessLevel(str, Enum):
    """
    What the user is actually allowed to do once a decision is made.

    FULL         → Can read, write, delete, admin
    STANDARD     → Can read and write, no admin
    READ_ONLY    → Can only view, not modify
    AUDIT_ONLY   → Can only view audit/log data
    NONE         → No access at all
    """
    FULL = "FULL"
    STANDARD = "STANDARD"
    READ_ONLY = "READ_ONLY"
    AUDIT_ONLY = "AUDIT_ONLY"
    NONE = "NONE"


# ── Output Structure ──────────────────────────────────────────

@dataclass
class PolicyResult:
    """
    The complete output from the policy engine for one request.

    decision         → What we decided (ALLOW, DENY, etc.)
    access_level     → What they're allowed to do
    risk_score       → The score that triggered this decision
    required_actions → Steps the system must take (e.g., "log this", "require 2FA")
    session_limits   → Constraints on the session (shorter timeout, etc.)
    message          → Human-readable explanation for the user/log
    timestamp        → When the decision was made (for audit trail)
    """
    decision: AccessDecision
    access_level: AccessLevel
    risk_score: float
    risk_level: str
    required_actions: List[str] = field(default_factory=list)
    session_limits: dict = field(default_factory=dict)
    message: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    resource: str = ""
    user_id: str = ""


# ── Policy Engine ─────────────────────────────────────────────

class PolicyEngine:
    """
    The decision-maker of the Zero Trust framework.

    HOW IT WORKS:
    1. Receive a RiskAssessment from RiskScorer
    2. Look at the final_score
    3. Apply the correct policy rule
    4. Return a PolicyResult with full details

    DESIGN PRINCIPLE — Policy Separation:
    The policy rules (thresholds, actions) live in config/settings.py.
    The engine just applies them. This means you can tighten or loosen
    security policy WITHOUT changing any code — just change config.
    """

    def __init__(self):
        self.thresholds = config.policy

    def evaluate(
        self,
        assessment: RiskAssessment,
        user_id: str = "",
        resource: str = "",
        resource_tags: List[str] = None,
        device_is_managed: bool = False
    ) -> PolicyResult:
        """
        Core evaluation method.

        Takes a completed risk assessment and returns a policy decision.

        Parameters:
            assessment: Output from RiskScorer.compute_risk()
            user_id:    The user making the request (for logging)
            resource:   What resource they're trying to access
            resource_tags: Tags on the resource (e.g., ["Confidential"])
            device_is_managed: Whether the device is corporate-managed
        """
        score = assessment.final_score

        # ── Decision Routing ──────────────────────────────────
        # We check thresholds from lowest risk to highest.
        # The first matching threshold wins.

        if score <= self.thresholds.allow_max:
            result = self._allow(score, assessment.risk_level)

        elif score <= self.thresholds.monitor_max:
            result = self._allow_with_monitoring(score, assessment.risk_level)

        elif score <= self.thresholds.step_up_max:
            result = self._step_up_auth(score, assessment.risk_level)

        elif score <= self.thresholds.restrict_max:
            result = self._restrict(score, assessment.risk_level)

        else:
            result = self._deny(score, assessment.risk_level)

        # ── Secondary Gate: Attribute-Based Access Control (ABAC) ──
        # Even if the risk score is low, strict rules apply to sensitive data
        if resource_tags and "Confidential" in resource_tags:
            if not device_is_managed:
                # Override the risk-based decision to DENY
                result = self._deny(score, assessment.risk_level)
                result.message = "ABAC Block: Confidential resources require a managed device."
                result.required_actions.append("abac_policy_violation")

        # Attach metadata for audit trail
        result.user_id = user_id
        result.resource = resource
        return result

    # ── Individual Decision Handlers ──────────────────────────
    # Each handler builds the complete PolicyResult for its case.
    # This keeps the logic clean and makes each case easy to modify.

    def _allow(self, score: float, risk_level: str) -> PolicyResult:
        """
        Score 0–24: ALLOW
        User is trusted. No restrictions. Normal session.
        Still logged (Zero Trust logs EVERYTHING).
        """
        return PolicyResult(
            decision=AccessDecision.ALLOW,
            access_level=AccessLevel.FULL,
            risk_score=score,
            risk_level=risk_level,
            required_actions=[
                "log_access_event",          # Always log, even clean requests
                "update_behavioral_baseline"  # Keep learning user's normal pattern
            ],
            session_limits={
                "timeout_minutes": config.session_timeout_minutes,
                "max_requests_per_minute": 100
            },
            message=f"Access granted. Risk score {score}/100 is within safe threshold."
        )

    def _allow_with_monitoring(self, score: float, risk_level: str) -> PolicyResult:
        """
        Score 25–49: ALLOW WITH MONITORING
        Request is allowed but watched closely.
        Enhanced logging is activated. Session is shorter.
        Security team may receive an alert.
        """
        return PolicyResult(
            decision=AccessDecision.ALLOW_WITH_MONITORING,
            access_level=AccessLevel.STANDARD,
            risk_score=score,
            risk_level=risk_level,
            required_actions=[
                "log_access_event",
                "enable_enhanced_logging",    # Record every API call in detail
                "notify_security_team",       # Alert SOC team
                "track_resource_access"       # Record which resources are touched
            ],
            session_limits={
                "timeout_minutes": 20,         # Shorter session — re-auth sooner
                "max_requests_per_minute": 50
            },
            message=f"Access granted with enhanced monitoring. Risk score {score}/100 is elevated."
        )

    def _step_up_auth(self, score: float, risk_level: str) -> PolicyResult:
        """
        Score 50–74: STEP-UP AUTHENTICATION
        Cannot proceed without additional verification.
        User must complete MFA challenge (OTP, push notification, etc.)
        before access is granted.

        This is a powerful Zero Trust tool: even if an attacker has
        the password, they're blocked without the second factor.
        """
        return PolicyResult(
            decision=AccessDecision.STEP_UP_AUTH,
            access_level=AccessLevel.READ_ONLY,  # Read-only until re-verified
            risk_score=score,
            risk_level=risk_level,
            required_actions=[
                "require_mfa_challenge",       # Force MFA (TOTP, push, biometric)
                "suspend_current_session",     # Pause existing session
                "log_step_up_trigger",         # Log that step-up was required
                "alert_user_via_email"         # Notify user of unusual activity
            ],
            session_limits={
                "timeout_minutes": 15,
                "max_requests_per_minute": 20,
                "mfa_timeout_seconds": 120     # User has 2 minutes to complete MFA
            },
            message=f"Additional verification required. Risk score {score}/100 exceeds threshold. Please complete MFA challenge."
        )

    def _restrict(self, score: float, risk_level: str) -> PolicyResult:
        """
        Score 75–89: RESTRICT
        Very high risk. Severely limited access.
        Only read-only, and security team is alerted immediately.
        Further analysis happens in the background.
        """
        return PolicyResult(
            decision=AccessDecision.RESTRICT,
            access_level=AccessLevel.READ_ONLY,
            risk_score=score,
            risk_level=risk_level,
            required_actions=[
                "log_high_risk_event",
                "alert_security_team_urgent",  # Immediate SOC alert
                "capture_full_session_log",    # Record everything in this session
                "initiate_risk_review",        # Trigger security review workflow
                "notify_user_account_at_risk"
            ],
            session_limits={
                "timeout_minutes": 10,
                "max_requests_per_minute": 10,
                "allowed_operations": ["read"],  # Only reads allowed
                "blocked_endpoints": ["/admin", "/export", "/delete"]
            },
            message=f"Access severely restricted. Risk score {score}/100. Security team has been alerted."
        )

    def _deny(self, score: float, risk_level: str) -> PolicyResult:
        """
        Score 90–100: DENY
        Critical risk. Request is blocked entirely.
        The connection is terminated. Full incident logged.
        This is often triggered by: known-bad IP, jailbroken device,
        impossible travel, or privilege escalation attempt.
        """
        return PolicyResult(
            decision=AccessDecision.DENY,
            access_level=AccessLevel.NONE,
            risk_score=score,
            risk_level=risk_level,
            required_actions=[
                "block_request_immediately",   # Return HTTP 403
                "terminate_session",           # Kill any active session
                "log_critical_security_event", # Full forensic log
                "alert_security_team_critical", # Immediate escalation
                "flag_account_for_review",     # Mark account for manual review
                "trigger_incident_response"    # May start IR process
            ],
            session_limits={
                "timeout_minutes": 0,
                "cooldown_minutes": 30         # Account locked for 30 minutes
            },
            message=f"Access DENIED. Risk score {score}/100 is critical. All access has been blocked."
        )

    def get_decision_summary(self, result: PolicyResult) -> dict:
        """
        Returns a clean summary dict — useful for API responses
        and dashboard displays.
        """
        return {
            "decision": result.decision.value,
            "access_level": result.access_level.value,
            "risk_score": result.risk_score,
            "risk_level": result.risk_level,
            "message": result.message,
            "required_actions": result.required_actions,
            "user_id": result.user_id,
            "resource": result.resource,
            "timestamp": result.timestamp
        }