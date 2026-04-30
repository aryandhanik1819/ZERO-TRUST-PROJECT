# ============================================================
#  device/device_trust.py — Device Trust & Posture Engine
# ============================================================
#
#  WHAT IS DEVICE TRUST?
#  Zero Trust says: "Don't trust the network, don't trust the device
#  just because it's on your network — verify it EXPLICITLY."
#
#  Device posture = the security health state of a device.
#  Before granting access, we check:
#    - Is this device registered/managed by IT?
#    - Is the OS patched and up to date?
#    - Is disk encrypted?
#    - Is antivirus running and updated?
#    - Has the device been jailbroken/rooted?
#    - Is the device compliant with our security policy?
#
#  In real enterprise deployments, this data comes from:
#    - MDM (Mobile Device Management): Jamf, Intune, MobileIron
#    - EDR (Endpoint Detection & Response): CrowdStrike, SentinelOne
#    - The device agent reporting its own health
#
#  PERSISTENCE:
#  Devices are stored in SQLite via SQLAlchemy.
#  Demo devices are seeded only if the table is empty.
# ============================================================

import uuid
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
from typing import Optional, Dict
from enum import Enum

from database import SessionLocal
from models import DeviceModel


class DeviceTrustLevel(str, Enum):
    """
    The four trust levels we assign to devices.

    FULLY_TRUSTED:   Managed, compliant, patched — full access
    CONDITIONALLY_TRUSTED: Some minor issues — limited access
    LOW_TRUST:       Significant issues — restricted access
    UNTRUSTED:       Unknown or non-compliant — access denied
    """
    FULLY_TRUSTED = "FULLY_TRUSTED"
    CONDITIONALLY_TRUSTED = "CONDITIONALLY_TRUSTED"
    LOW_TRUST = "LOW_TRUST"
    UNTRUSTED = "UNTRUSTED"


class DeviceOS(str, Enum):
    WINDOWS = "windows"
    MACOS = "macos"
    LINUX = "linux"
    IOS = "ios"
    ANDROID = "android"
    UNKNOWN = "unknown"


@dataclass
class DeviceProfile:
    """
    A registered device's profile in our system (DTO).

    device_id:       Unique ID we assign
    fingerprint:     Hardware/browser fingerprint (unique device identifier)
    owner_user_id:   Which user this device belongs to
    os_type:         Operating system
    os_version:      Specific version (e.g., "Windows 11 23H2")
    is_managed:      True = IT-managed device, False = personal device
    last_patch_date: Last time OS security updates were applied
    is_encrypted:    Full-disk encryption enabled?
    has_antivirus:   Antivirus software running?
    is_jailbroken:   Has OS security been bypassed?
    compliance_score: 0–100 overall compliance score
    trust_level:     Computed trust classification
    last_seen:       Last time this device made a request
    registered_at:   When this device was first registered
    """
    device_id: str
    fingerprint: str
    owner_user_id: str
    os_type: DeviceOS = DeviceOS.UNKNOWN
    os_version: str = "unknown"
    is_managed: bool = False
    last_patch_date: Optional[str] = None
    is_encrypted: bool = False
    has_antivirus: bool = False
    is_jailbroken: bool = False
    compliance_score: float = 0.0
    trust_level: DeviceTrustLevel = DeviceTrustLevel.UNTRUSTED
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    registered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class PostureReport:
    """
    The output of a device posture assessment.

    Contains the trust level, compliance score, specific findings,
    and remediation recommendations.
    """
    device_id: str
    trust_level: DeviceTrustLevel
    compliance_score: float
    findings: list = field(default_factory=list)      # Issues found
    recommendations: list = field(default_factory=list)  # How to fix them
    risk_contribution: float = 0.0  # How much this device adds to total risk score
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ── Helper: Convert ORM model ↔ DTO ──────────────────────────

def _profile_from_model(m: DeviceModel) -> DeviceProfile:
    """Convert a SQLAlchemy DeviceModel row to a DeviceProfile dataclass."""
    return DeviceProfile(
        device_id=m.device_id,
        fingerprint=m.fingerprint,
        owner_user_id=m.owner_user_id,
        os_type=DeviceOS(m.os_type) if m.os_type in [e.value for e in DeviceOS] else DeviceOS.UNKNOWN,
        os_version=m.os_version,
        is_managed=m.is_managed,
        last_patch_date=m.last_patch_date,
        is_encrypted=m.is_encrypted,
        has_antivirus=m.has_antivirus,
        is_jailbroken=m.is_jailbroken,
        compliance_score=m.compliance_score,
        trust_level=DeviceTrustLevel(m.trust_level) if m.trust_level in [e.value for e in DeviceTrustLevel] else DeviceTrustLevel.UNTRUSTED,
        last_seen=m.last_seen,
        registered_at=m.registered_at,
    )


class DeviceTrustEngine:
    """
    Manages device registration, posture checking, and trust scoring.

    POSTURE ASSESSMENT LOGIC:
    We check each device attribute and accumulate a compliance score.
    Issues are weighted by severity:
      - Jailbroken:     -50 (critical — OS security is gone)
      - Not managed:    -20 (no IT oversight)
      - Not patched:    -25 (known vulnerabilities exist)
      - No antivirus:   -15 (no malware protection)
      - Not encrypted:  -10 (physical theft risk)

    Trust levels map to compliance scores:
      90–100  → FULLY_TRUSTED
      70–89   → CONDITIONALLY_TRUSTED
      50–69   → LOW_TRUST
      0–49    → UNTRUSTED
    """

    def __init__(self):
        self._seed_demo_devices()

    def _seed_demo_devices(self):
        """Pre-register some demo devices — only if table is empty."""
        db = SessionLocal()
        try:
            existing = db.query(DeviceModel).first()
            if existing is not None:
                return  # Already seeded
        finally:
            db.close()

        # Alice's trusted managed laptop
        self.register_device(
            fingerprint="alice-laptop-001",
            owner_user_id="demo-alice",
            os_type=DeviceOS.MACOS,
            os_version="macOS 14.3",
            is_managed=True,
            last_patch_date=(datetime.now(timezone.utc) - timedelta(days=5)).isoformat(),
            is_encrypted=True,
            has_antivirus=True,
            is_jailbroken=False
        )
        # Bob's unmanaged personal device
        self.register_device(
            fingerprint="bob-phone-001",
            owner_user_id="demo-bob",
            os_type=DeviceOS.ANDROID,
            os_version="Android 12",
            is_managed=False,
            last_patch_date=(datetime.now(timezone.utc) - timedelta(days=120)).isoformat(),
            is_encrypted=True,
            has_antivirus=False,
            is_jailbroken=False
        )

    def register_device(
        self,
        fingerprint: str,
        owner_user_id: str,
        os_type: DeviceOS = DeviceOS.UNKNOWN,
        os_version: str = "unknown",
        is_managed: bool = False,
        last_patch_date: Optional[str] = None,
        is_encrypted: bool = False,
        has_antivirus: bool = False,
        is_jailbroken: bool = False
    ) -> DeviceProfile:
        """
        Register a new device in the system.
        Immediately runs posture assessment to compute trust level.
        """
        device_id = str(uuid.uuid4())

        # Build a temporary DTO for posture assessment
        device = DeviceProfile(
            device_id=device_id,
            fingerprint=fingerprint,
            owner_user_id=owner_user_id,
            os_type=os_type,
            os_version=os_version,
            is_managed=is_managed,
            last_patch_date=last_patch_date,
            is_encrypted=is_encrypted,
            has_antivirus=has_antivirus,
            is_jailbroken=is_jailbroken,
        )

        # Run posture assessment immediately on registration
        report = self.assess_posture(device)
        device.compliance_score = report.compliance_score
        device.trust_level = report.trust_level

        # Persist to database (upsert — update if fingerprint already exists)
        db = SessionLocal()
        try:
            existing = db.query(DeviceModel).filter(DeviceModel.fingerprint == fingerprint).first()
            if existing:
                # Update existing device record
                existing.owner_user_id = owner_user_id
                existing.os_type = os_type.value if isinstance(os_type, DeviceOS) else os_type
                existing.os_version = os_version
                existing.is_managed = is_managed
                existing.last_patch_date = last_patch_date
                existing.is_encrypted = is_encrypted
                existing.has_antivirus = has_antivirus
                existing.is_jailbroken = is_jailbroken
                existing.compliance_score = device.compliance_score
                existing.trust_level = device.trust_level.value if isinstance(device.trust_level, DeviceTrustLevel) else device.trust_level
                device.device_id = existing.device_id  # Keep the original ID
            else:
                db_device = DeviceModel(
                    device_id=device_id,
                    fingerprint=fingerprint,
                    owner_user_id=owner_user_id,
                    os_type=os_type.value if isinstance(os_type, DeviceOS) else os_type,
                    os_version=os_version,
                    is_managed=is_managed,
                    last_patch_date=last_patch_date,
                    is_encrypted=is_encrypted,
                    has_antivirus=has_antivirus,
                    is_jailbroken=is_jailbroken,
                    compliance_score=device.compliance_score,
                    trust_level=device.trust_level.value if isinstance(device.trust_level, DeviceTrustLevel) else device.trust_level,
                )
                db.add(db_device)
            db.commit()
        finally:
            db.close()

        return device

    def get_device(self, fingerprint: str) -> Optional[DeviceProfile]:
        """Look up a device by its fingerprint."""
        db = SessionLocal()
        try:
            db_device = db.query(DeviceModel).filter(DeviceModel.fingerprint == fingerprint).first()
            if not db_device:
                return None
            db_device.last_seen = datetime.now(timezone.utc).isoformat()
            db.commit()
            return _profile_from_model(db_device)
        finally:
            db.close()

    def get_all_devices(self, limit: int = 50) -> list[DeviceProfile]:
        """Get a list of all registered devices for the dashboard."""
        db = SessionLocal()
        try:
            devices = db.query(DeviceModel).order_by(DeviceModel.last_seen.desc()).limit(limit).all()
            return [_profile_from_model(d) for d in devices]
        finally:
            db.close()

    def assess_posture(self, device: DeviceProfile) -> PostureReport:
        """
        Run a full posture assessment on a device.

        Starts with a perfect score of 100 and deducts points for each issue.
        Records findings and recommendations for each problem found.
        """
        score = 100.0
        findings = []
        recommendations = []

        # ── Check 1: Jailbroken/Rooted ─────────────────────
        # This is the most severe issue — the device's security model is broken
        if device.is_jailbroken:
            score -= 50
            findings.append("CRITICAL: Device is jailbroken/rooted — OS security bypassed")
            recommendations.append("Restore device to factory settings to remove jailbreak")

        # ── Check 2: Device Management ──────────────────────
        # IT-managed devices have security policies enforced automatically
        if not device.is_managed:
            score -= 20
            findings.append("Device is unmanaged (personal device, no IT oversight)")
            recommendations.append("Enroll device in MDM (Intune/Jamf) to enable management")

        # ── Check 3: OS Patches ─────────────────────────────
        # Unpatched OS = known CVEs = exploitable vulnerabilities
        if device.last_patch_date:
            try:
                patch_date = datetime.fromisoformat(device.last_patch_date.replace('Z', '+00:00'))
                days_since_patch = (datetime.now(timezone.utc) - patch_date).days

                if days_since_patch > 90:
                    score -= 25
                    findings.append(f"OS unpatched for {days_since_patch} days — critical vulnerabilities may exist")
                    recommendations.append("Apply all pending OS security updates immediately")
                elif days_since_patch > 30:
                    score -= 10
                    findings.append(f"OS unpatched for {days_since_patch} days")
                    recommendations.append("Apply pending OS security updates soon")
                else:
                    findings.append(f"OS up to date (patched {days_since_patch} days ago) ✓")
            except Exception:
                score -= 15
                findings.append("Cannot verify patch status — treating as unpatched")
        else:
            score -= 15
            findings.append("No patch date recorded — patch status unknown")
            recommendations.append("Configure device to report OS update status")

        # ── Check 4: Antivirus ──────────────────────────────
        if not device.has_antivirus:
            score -= 15
            findings.append("No antivirus/EDR software detected")
            recommendations.append("Install and enable antivirus or EDR solution")
        else:
            findings.append("Antivirus/EDR active ✓")

        # ── Check 5: Disk Encryption ────────────────────────
        if not device.is_encrypted:
            score -= 10
            findings.append("Disk encryption not enabled — stolen device = stolen data")
            recommendations.append("Enable BitLocker (Windows) or FileVault (macOS)")
        else:
            findings.append("Disk encryption enabled ✓")

        # Clamp to 0–100
        score = max(0.0, min(100.0, score))

        # Map score to trust level
        trust_level = self._classify_trust(score)

        # Compute risk contribution (inverse of compliance)
        risk_contribution = 100.0 - score

        return PostureReport(
            device_id=device.device_id,
            trust_level=trust_level,
            compliance_score=round(score, 2),
            findings=findings,
            recommendations=recommendations,
            risk_contribution=round(risk_contribution, 2)
        )

    def _classify_trust(self, compliance_score: float) -> DeviceTrustLevel:
        """Map compliance score to trust level."""
        if compliance_score >= 90:
            return DeviceTrustLevel.FULLY_TRUSTED
        elif compliance_score >= 70:
            return DeviceTrustLevel.CONDITIONALLY_TRUSTED
        elif compliance_score >= 50:
            return DeviceTrustLevel.LOW_TRUST
        else:
            return DeviceTrustLevel.UNTRUSTED

    def is_device_trusted(self, fingerprint: str) -> bool:
        """Quick check — is this device trusted enough to proceed?"""
        device = self.get_device(fingerprint)
        if not device:
            return False
        return device.trust_level in [
            DeviceTrustLevel.FULLY_TRUSTED,
            DeviceTrustLevel.CONDITIONALLY_TRUSTED
        ]