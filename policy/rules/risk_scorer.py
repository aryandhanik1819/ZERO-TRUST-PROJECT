# ============================================================
#  policy/risk_scorer.py — Risk Scoring Engine
# ============================================================
#
#  WHAT IS RISK SCORING?
#  Before allowing any access, Zero Trust asks: "How risky is
#  this request RIGHT NOW?" The risk engine scores every request
#  from 0 (totally safe) to 100 (extremely dangerous).
#
#  It does this by examining 4 dimensions:
#    1. Identity  — Is the user who they claim to be?
#    2. Device    — Is the device safe and trusted?
#    3. Behavior  — Is the user acting normally?
#    4. Context   — Is the location/time suspicious?
#
#  Each dimension gets a raw score 0–100, then they are combined
#  using weighted average:
#    Final = W1*Identity + W2*Device + W3*Behavior + W4*Context
# ============================================================

from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime
from config.settings import config


# ── Data Classes ──────────────────────────────────────────────
# These are structured containers for passing data between modules.
# Using dataclasses means we get validation and clean repr for free.

@dataclass
class IdentityRiskFactors:
    """
    Factors about the USER's identity.

    failed_login_attempts: How many times they failed to log in recently.
      More failures = more suspicious = higher risk.

    is_mfa_enabled: Did they use multi-factor auth?
      MFA = much harder to fake, so MFA users get lower risk.

    account_age_days: Brand-new accounts are riskier than old ones.

    is_privileged_account: Admins are higher-value targets.
      Their requests should be scrutinized more.

    unusual_login_time: Logging in at 3 AM when you always log in at 9 AM
      is suspicious.
    """
    failed_login_attempts: int = 0
    is_mfa_enabled: bool = True
    account_age_days: int = 365
    is_privileged_account: bool = False
    unusual_login_time: bool = False


@dataclass
class DeviceRiskFactors:
    """
    Factors about the DEVICE making the request.

    is_managed: Is this a company-issued, managed device?
      Unmanaged personal devices are riskier.

    os_patch_days: How many days since the last OS security patch?
      Unpatched devices have known vulnerabilities.

    has_antivirus: Does the device have active antivirus?

    is_encrypted: Is the disk encrypted?
      If the device is stolen, encrypted disks protect data.

    jailbroken_or_rooted: Has OS security been bypassed?
      This is a major red flag.
    """
    is_managed: bool = True
    os_patch_days: int = 0
    has_antivirus: bool = True
    is_encrypted: bool = True
    jailbroken_or_rooted: bool = False


@dataclass
class BehaviorRiskFactors:
    """
    Factors about WHAT the user is doing — their behavior pattern.

    requests_per_minute: Normal users make a few requests. Bots/attackers
      flood with hundreds per minute.

    accessing_sensitive_data: Accessing HR/financial/secret data = higher risk.

    bulk_download_detected: Downloading thousands of files at once is a
      data exfiltration red flag.

    privilege_escalation_attempt: Trying to gain higher access than allowed.

    anomaly_score: A separate ML-based anomaly detection score (0–100).
      Detects deviations from the user's normal behavior baseline.
    """
    requests_per_minute: int = 5
    accessing_sensitive_data: bool = False
    bulk_download_detected: bool = False
    privilege_escalation_attempt: bool = False
    anomaly_score: float = 0.0


@dataclass
class ContextRiskFactors:
    """
    Factors about WHERE and WHEN the request is coming from.

    ip_reputation_score: Known bad IPs (Tor exits, botnets, attackers)
      get high scores here (0=clean, 100=known-bad).

    geolocation_anomaly: Did the user just log in from India and now
      they're requesting from Russia 5 minutes later? (impossible travel)

    vpn_or_proxy: Legitimate users sometimes use VPNs, but attackers
      also use them to hide their real location.

    time_of_day_risk: Requests at very unusual hours for this user.

    new_device_fingerprint: First time we've ever seen this device.
    """
    ip_reputation_score: float = 0.0
    geolocation_anomaly: bool = False
    vpn_or_proxy: bool = False
    time_of_day_risk: float = 0.0
    new_device_fingerprint: bool = False


@dataclass
class RiskAssessment:
    """
    The complete output of the risk engine.
    Contains all dimension scores, the final score, and the timestamp.
    """
    identity_score: float = 0.0
    device_score: float = 0.0
    behavioral_score: float = 0.0
    context_score: float = 0.0
    final_score: float = 0.0
    risk_level: str = "LOW"          # LOW | MEDIUM | HIGH | CRITICAL
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    explanation: list = field(default_factory=list)  # Human-readable reasons


# ── Main Risk Scorer Class ────────────────────────────────────

class RiskScorer:
    """
    The core risk computation engine.

    HOW IT WORKS:
    1. Call score_identity()  → raw score 0–100
    2. Call score_device()    → raw score 0–100
    3. Call score_behavior()  → raw score 0–100
    4. Call score_context()   → raw score 0–100
    5. Combine with weights   → final score 0–100
    6. Map to risk level (LOW / MEDIUM / HIGH / CRITICAL)

    Each scoring method adds "explanation" strings — these tell
    the policy engine and security team EXACTLY why the score
    is what it is. This is called "explainable AI" in security.
    """

    def __init__(self):
        self.weights = config.risk_weights

    def score_identity(self, factors: IdentityRiskFactors) -> tuple[float, list]:
        """
        Compute identity risk from 0–100.

        Logic breakdown:
        - Failed logins add 15 points each (capped at 60)
        - No MFA adds 25 points (MFA is critical security control)
        - New accounts (< 30 days) add 15 points
        - Privileged accounts add 10 points baseline
        - Unusual login time adds 20 points
        """
        score = 0.0
        reasons = []

        # Failed login attempts: each failure adds 15, max 60
        if factors.failed_login_attempts > 0:
            penalty = min(factors.failed_login_attempts * 15, 60)
            score += penalty
            reasons.append(f"Failed login attempts: {factors.failed_login_attempts} (+{penalty})")

        # No MFA is a big risk — attackers just need a stolen password
        if not factors.is_mfa_enabled:
            score += 25
            reasons.append("MFA not enabled (+25) — password alone is insufficient")

        # Brand new accounts haven't built trust yet
        if factors.account_age_days < 30:
            score += 15
            reasons.append(f"New account ({factors.account_age_days} days old) (+15)")

        # Admin/privileged accounts are high-value attack targets
        if factors.is_privileged_account:
            score += 10
            reasons.append("Privileged account — higher scrutiny applied (+10)")

        # Login at unusual hours for this user
        if factors.unusual_login_time:
            score += 20
            reasons.append("Login at unusual time for this user (+20)")

        return min(score, 100.0), reasons

    def score_device(self, factors: DeviceRiskFactors) -> tuple[float, list]:
        """
        Compute device risk from 0–100.

        Jailbroken/rooted devices are an immediate critical risk —
        they bypass OS-level security controls entirely.
        Unmanaged devices haven't been assessed for compliance.
        Old patches mean known vulnerabilities exist on the device.
        """
        score = 0.0
        reasons = []

        # Jailbroken = OS security bypassed = critical red flag
        if factors.jailbroken_or_rooted:
            score += 50
            reasons.append("Device is jailbroken/rooted — OS security bypassed (+50)")

        # Unmanaged devices haven't been assessed or secured by IT
        if not factors.is_managed:
            score += 20
            reasons.append("Unmanaged device — no IT security baseline (+20)")

        # Unpatched OS: every day without patches = more known CVEs
        if factors.os_patch_days > 90:
            score += 25
            reasons.append(f"OS unpatched for {factors.os_patch_days} days — critical (+25)")
        elif factors.os_patch_days > 30:
            score += 10
            reasons.append(f"OS unpatched for {factors.os_patch_days} days (+10)")

        # No antivirus = no malware protection
        if not factors.has_antivirus:
            score += 15
            reasons.append("No antivirus detected (+15)")

        # Unencrypted disk = stolen device → stolen data
        if not factors.is_encrypted:
            score += 10
            reasons.append("Disk not encrypted (+10)")

        return min(score, 100.0), reasons

    def score_behavior(self, factors: BehaviorRiskFactors) -> tuple[float, list]:
        """
        Compute behavioral risk from 0–100.

        Behavioral analysis catches attackers who have valid credentials
        but are acting differently from the real user — e.g., an attacker
        using stolen creds will often access different resources, download
        more data, or make requests at much higher rates.
        """
        score = 0.0
        reasons = []

        # Flood of requests = bot/automation/attack
        if factors.requests_per_minute > 100:
            score += 40
            reasons.append(f"Very high request rate: {factors.requests_per_minute}/min (+40)")
        elif factors.requests_per_minute > 30:
            score += 20
            reasons.append(f"Elevated request rate: {factors.requests_per_minute}/min (+20)")

        # Bulk download = data exfiltration warning
        if factors.bulk_download_detected:
            score += 30
            reasons.append("Bulk download detected — possible data exfiltration (+30)")

        # Trying to gain higher access = classic attack pattern
        if factors.privilege_escalation_attempt:
            score += 35
            reasons.append("Privilege escalation attempt detected (+35)")

        # Accessing sensitive resources increases inherent risk
        if factors.accessing_sensitive_data:
            score += 10
            reasons.append("Accessing sensitive/classified data (+10)")

        # ML anomaly score maps directly into the behavior score
        if factors.anomaly_score > 0:
            score += factors.anomaly_score * 0.3   # Anomaly contributes up to 30 points
            reasons.append(f"Behavioral anomaly score: {factors.anomaly_score:.1f} (+{factors.anomaly_score * 0.3:.1f})")

        return min(score, 100.0), reasons

    def score_context(self, factors: ContextRiskFactors) -> tuple[float, list]:
        """
        Compute contextual risk from 0–100.

        Context is about WHERE and HOW the request arrives.
        A valid user on a trusted network at normal hours is low risk.
        The same user via Tor from a new country at 3 AM is high risk.
        """
        score = 0.0
        reasons = []

        # IP reputation: known-bad IP = likely attacker
        if factors.ip_reputation_score > 70:
            score += 40
            reasons.append(f"High-risk IP (reputation score: {factors.ip_reputation_score}) (+40)")
        elif factors.ip_reputation_score > 40:
            score += 20
            reasons.append(f"Suspicious IP (reputation score: {factors.ip_reputation_score}) (+20)")

        # Impossible travel: user can't be in two places at once
        if factors.geolocation_anomaly:
            score += 35
            reasons.append("Geolocation anomaly — possible account takeover (+35)")

        # VPN/proxy: hides real location, common in attacks
        if factors.vpn_or_proxy:
            score += 15
            reasons.append("Request via VPN/proxy (+15)")

        # Unusual time for this user's baseline
        score += factors.time_of_day_risk * 0.2
        if factors.time_of_day_risk > 0:
            reasons.append(f"Time-of-day risk: {factors.time_of_day_risk:.1f} (+{factors.time_of_day_risk * 0.2:.1f})")

        # First time we've ever seen this device from this user
        if factors.new_device_fingerprint:
            score += 15
            reasons.append("New/unrecognized device fingerprint (+15)")

        return min(score, 100.0), reasons

    def compute_risk(
        self,
        identity: IdentityRiskFactors,
        device: DeviceRiskFactors,
        behavior: BehaviorRiskFactors,
        context: ContextRiskFactors
    ) -> RiskAssessment:
        """
        MAIN METHOD — combines all dimension scores into one assessment.

        Formula:
          final = (W_id * identity) + (W_dev * device)
                + (W_beh * behavior) + (W_ctx * context)

        Where weights come from config (sum = 1.0).
        """
        id_score, id_reasons = self.score_identity(identity)
        dev_score, dev_reasons = self.score_device(device)
        beh_score, beh_reasons = self.score_behavior(behavior)
        ctx_score, ctx_reasons = self.score_context(context)

        # Weighted combination
        final = (
            self.weights.identity   * id_score  +
            self.weights.device     * dev_score +
            self.weights.behavioral * beh_score +
            self.weights.context    * ctx_score
        )
        final = round(min(final, 100.0), 2)

        # Map final score to human-readable risk level
        risk_level = self._classify_risk(final)

        all_reasons = id_reasons + dev_reasons + beh_reasons + ctx_reasons

        return RiskAssessment(
            identity_score=round(id_score, 2),
            device_score=round(dev_score, 2),
            behavioral_score=round(beh_score, 2),
            context_score=round(ctx_score, 2),
            final_score=final,
            risk_level=risk_level,
            explanation=all_reasons if all_reasons else ["No risk factors detected — clean request"]
        )

    def _classify_risk(self, score: float) -> str:
        """Map numeric score to a named risk level."""
        if score <= 24:
            return "LOW"
        elif score <= 49:
            return "MEDIUM"
        elif score <= 74:
            return "HIGH"
        elif score <= 89:
            return "VERY HIGH"
        else:
            return "CRITICAL"