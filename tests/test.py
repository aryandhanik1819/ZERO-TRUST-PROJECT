# ============================================================
#  tests/test_all.py — Complete Test Suite
# ============================================================
#
#  WHY WRITE TESTS?
#  Tests are your safety net. They:
#    1. Prove each module works correctly
#    2. Catch bugs before they reach production
#    3. Document expected behavior (tests = living docs)
#    4. Let you refactor confidently (tests fail = you broke something)
#
#  HOW TO RUN:
#    cd zero_trust
#    python tests/test_all.py
#
#  TEST STRUCTURE:
#  Each test class tests one module.
#  Each test method tests one specific behavior.
#  We use Python's built-in unittest framework (no extra install needed).
#
#  NAMING CONVENTION:
#  test_<what_we_test>_<expected_result>
#  e.g., test_risk_score_with_jailbroken_device_returns_high_score
# ============================================================

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from datetime import datetime, timezone

# Import all modules
from config.settings import config, RiskWeights, PolicyThresholds
from policy.rules.risk_scorer import (
    RiskScorer, IdentityRiskFactors, DeviceRiskFactors,
    BehaviorRiskFactors, ContextRiskFactors
)
from policy.rules.policy_engine import PolicyEngine, AccessDecision, AccessLevel
from identity.token_manager import TokenManager
from identity.auth_services import AuthService
from device.device_trust import DeviceTrustEngine, DeviceOS, DeviceTrustLevel
from monitoring.session_monitor import SessionMonitor
from audit.audit_logger import AuditLogger, AuditEvent

# Initialize database tables before any tests run
from database import init_db
init_db()


# ══════════════════════════════════════════════════════════════
#  CONFIG TESTS
# ══════════════════════════════════════════════════════════════

class TestConfig(unittest.TestCase):

    def test_risk_weights_sum_to_one(self):
        """
        Critical: weights must sum to 1.0 for the formula to work.
        If they don't, the final score will be wrong.
        """
        weights = config.risk_weights
        total = weights.identity + weights.device + weights.behavioral + weights.context
        self.assertAlmostEqual(total, 1.0, places=5,
            msg=f"Weights sum to {total}, must be 1.0")

    def test_policy_thresholds_are_ascending(self):
        """Thresholds must be in order: allow < monitor < step_up < restrict."""
        p = config.policy
        self.assertLess(p.allow_max, p.monitor_max)
        self.assertLess(p.monitor_max, p.step_up_max)
        self.assertLess(p.step_up_max, p.restrict_max)
        self.assertLess(p.restrict_max, 100)

    def test_jwt_config_has_secret(self):
        """JWT secret key must not be empty."""
        self.assertTrue(len(config.jwt.secret_key) > 0)

    def test_access_token_expires_before_refresh(self):
        """Access tokens should be shorter-lived than refresh tokens."""
        access_minutes = config.jwt.access_token_expire_minutes
        refresh_minutes = config.jwt.refresh_token_expire_hours * 60
        self.assertLess(access_minutes, refresh_minutes)


# ══════════════════════════════════════════════════════════════
#  RISK SCORER TESTS
# ══════════════════════════════════════════════════════════════

class TestRiskScorer(unittest.TestCase):

    def setUp(self):
        """Called before each test. Creates a fresh scorer."""
        self.scorer = RiskScorer()
        # Default "clean" factors — no risk factors present
        self.clean_identity = IdentityRiskFactors(
            failed_login_attempts=0, is_mfa_enabled=True,
            account_age_days=365, is_privileged_account=False, unusual_login_time=False
        )
        self.clean_device = DeviceRiskFactors(
            is_managed=True, os_patch_days=0, has_antivirus=True,
            is_encrypted=True, jailbroken_or_rooted=False
        )
        self.clean_behavior = BehaviorRiskFactors(
            requests_per_minute=5, accessing_sensitive_data=False,
            bulk_download_detected=False, privilege_escalation_attempt=False, anomaly_score=0.0
        )
        self.clean_context = ContextRiskFactors(
            ip_reputation_score=0.0, geolocation_anomaly=False,
            vpn_or_proxy=False, time_of_day_risk=0.0, new_device_fingerprint=False
        )

    def test_clean_request_scores_zero(self):
        """A completely clean request should score 0."""
        assessment = self.scorer.compute_risk(
            self.clean_identity, self.clean_device,
            self.clean_behavior, self.clean_context
        )
        self.assertEqual(assessment.final_score, 0.0,
            f"Clean request scored {assessment.final_score}, expected 0")

    def test_no_mfa_increases_identity_risk(self):
        """Removing MFA should significantly increase the identity score."""
        no_mfa = IdentityRiskFactors(is_mfa_enabled=False)
        score, reasons = self.scorer.score_identity(no_mfa)
        self.assertGreater(score, 0, "No MFA should add risk")
        self.assertTrue(any("MFA" in r for r in reasons), "Should mention MFA in reasons")

    def test_failed_logins_increase_risk(self):
        """3 failed login attempts should add 45 points to identity risk."""
        risky_identity = IdentityRiskFactors(failed_login_attempts=3, is_mfa_enabled=True)
        score, reasons = self.scorer.score_identity(risky_identity)
        self.assertGreaterEqual(score, 45,
            f"3 failed attempts should give ≥45 risk, got {score}")

    def test_jailbroken_device_critical_risk(self):
        """Jailbroken device should add 50 points — critical severity."""
        jailbroken = DeviceRiskFactors(jailbroken_or_rooted=True)
        score, reasons = self.scorer.score_device(jailbroken)
        self.assertGreaterEqual(score, 50,
            f"Jailbroken device should give ≥50 risk, got {score}")

    def test_unpatched_device_adds_risk(self):
        """Device unpatched for 91 days should add significant device risk."""
        stale_device = DeviceRiskFactors(os_patch_days=91)
        score, reasons = self.scorer.score_device(stale_device)
        self.assertGreater(score, 0, "Old patches should add risk")

    def test_privilege_escalation_critical_behavior(self):
        """Privilege escalation attempt should add 35 points."""
        risky_behavior = BehaviorRiskFactors(privilege_escalation_attempt=True)
        score, reasons = self.scorer.score_behavior(risky_behavior)
        self.assertGreaterEqual(score, 35,
            f"Priv escalation should give ≥35, got {score}")

    def test_high_request_rate_adds_risk(self):
        """150 requests/minute should add significant behavioral risk."""
        burst = BehaviorRiskFactors(requests_per_minute=150)
        score, reasons = self.scorer.score_behavior(burst)
        self.assertGreater(score, 0, "High request rate should add risk")

    def test_bad_ip_increases_context_risk(self):
        """IP with 90/100 reputation score should add 40 context points."""
        bad_context = ContextRiskFactors(ip_reputation_score=90.0)
        score, reasons = self.scorer.score_context(bad_context)
        self.assertGreaterEqual(score, 40,
            f"Bad IP should give ≥40, got {score}")

    def test_geolocation_anomaly_adds_risk(self):
        """Impossible travel (geolocation anomaly) should add 35 context points."""
        anomalous_context = ContextRiskFactors(geolocation_anomaly=True)
        score, reasons = self.scorer.score_context(anomalous_context)
        self.assertGreaterEqual(score, 35)

    def test_final_score_capped_at_100(self):
        """No matter how many risk factors, score should never exceed 100."""
        worst_identity = IdentityRiskFactors(
            failed_login_attempts=10, is_mfa_enabled=False,
            account_age_days=1, is_privileged_account=True, unusual_login_time=True
        )
        worst_device = DeviceRiskFactors(
            jailbroken_or_rooted=True, is_managed=False,
            os_patch_days=365, has_antivirus=False, is_encrypted=False
        )
        worst_behavior = BehaviorRiskFactors(
            requests_per_minute=500, accessing_sensitive_data=True,
            bulk_download_detected=True, privilege_escalation_attempt=True, anomaly_score=100
        )
        worst_context = ContextRiskFactors(
            ip_reputation_score=100, geolocation_anomaly=True,
            vpn_or_proxy=True, time_of_day_risk=100, new_device_fingerprint=True
        )
        assessment = self.scorer.compute_risk(worst_identity, worst_device, worst_behavior, worst_context)
        self.assertLessEqual(assessment.final_score, 100.0,
            f"Score exceeded 100: {assessment.final_score}")

    def test_risk_level_classification(self):
        """Test that risk levels are classified correctly."""
        low = self.scorer._classify_risk(10)
        medium = self.scorer._classify_risk(35)
        high = self.scorer._classify_risk(60)
        very_high = self.scorer._classify_risk(80)
        critical = self.scorer._classify_risk(95)

        self.assertEqual(low, "LOW")
        self.assertEqual(medium, "MEDIUM")
        self.assertEqual(high, "HIGH")
        self.assertEqual(very_high, "VERY HIGH")
        self.assertEqual(critical, "CRITICAL")

    def test_explanation_is_populated(self):
        """Risk assessment should always explain why the score is what it is."""
        risky_identity = IdentityRiskFactors(is_mfa_enabled=False, failed_login_attempts=2)
        assessment = self.scorer.compute_risk(
            risky_identity, self.clean_device, self.clean_behavior, self.clean_context
        )
        self.assertGreater(len(assessment.explanation), 0,
            "Explanation should not be empty for risky request")


# ══════════════════════════════════════════════════════════════
#  POLICY ENGINE TESTS
# ══════════════════════════════════════════════════════════════

class TestPolicyEngine(unittest.TestCase):

    def setUp(self):
        self.engine = PolicyEngine()
        self.scorer = RiskScorer()

    def _make_assessment_with_score(self, target_score: float):
        """Helper: create an assessment approximately hitting a target score."""
        from policy.rules.risk_scorer import RiskAssessment
        return RiskAssessment(
            identity_score=target_score,
            device_score=target_score,
            behavioral_score=target_score,
            context_score=target_score,
            final_score=target_score,
            risk_level="TEST"
        )

    def test_score_0_gets_allow(self):
        """Score 0 should get ALLOW decision."""
        assessment = self._make_assessment_with_score(0.0)
        result = self.engine.evaluate(assessment)
        self.assertEqual(result.decision, AccessDecision.ALLOW)
        self.assertEqual(result.access_level, AccessLevel.FULL)

    def test_score_24_gets_allow(self):
        """Score exactly at the allow threshold should still be ALLOW."""
        assessment = self._make_assessment_with_score(24.0)
        result = self.engine.evaluate(assessment)
        self.assertEqual(result.decision, AccessDecision.ALLOW)

    def test_score_25_gets_monitoring(self):
        """Score just above allow threshold should trigger monitoring."""
        assessment = self._make_assessment_with_score(25.0)
        result = self.engine.evaluate(assessment)
        self.assertEqual(result.decision, AccessDecision.ALLOW_WITH_MONITORING)

    def test_score_50_gets_step_up(self):
        """Score at 50 should require step-up authentication."""
        assessment = self._make_assessment_with_score(50.0)
        result = self.engine.evaluate(assessment)
        self.assertEqual(result.decision, AccessDecision.STEP_UP_AUTH)
        self.assertIn("require_mfa_challenge", result.required_actions)

    def test_score_75_gets_restrict(self):
        """Score at 75 should restrict access."""
        assessment = self._make_assessment_with_score(75.0)
        result = self.engine.evaluate(assessment)
        self.assertEqual(result.decision, AccessDecision.RESTRICT)
        self.assertEqual(result.access_level, AccessLevel.READ_ONLY)

    def test_score_90_gets_deny(self):
        """Score at or above 90 should result in full DENY."""
        assessment = self._make_assessment_with_score(90.0)
        result = self.engine.evaluate(assessment)
        self.assertEqual(result.decision, AccessDecision.DENY)
        self.assertEqual(result.access_level, AccessLevel.NONE)
        self.assertIn("block_request_immediately", result.required_actions)

    def test_score_100_gets_deny(self):
        """Maximum score (100) must always be denied."""
        assessment = self._make_assessment_with_score(100.0)
        result = self.engine.evaluate(assessment)
        self.assertEqual(result.decision, AccessDecision.DENY)

    def test_deny_has_session_timeout_zero(self):
        """Denied sessions should have zero timeout (no session created)."""
        assessment = self._make_assessment_with_score(95.0)
        result = self.engine.evaluate(assessment)
        self.assertEqual(result.session_limits.get("timeout_minutes"), 0)

    def test_result_includes_timestamp(self):
        """Every policy result must have a timestamp for audit trail."""
        assessment = self._make_assessment_with_score(10.0)
        result = self.engine.evaluate(assessment)
        self.assertTrue(len(result.timestamp) > 0)


# ══════════════════════════════════════════════════════════════
#  TOKEN MANAGER TESTS
# ══════════════════════════════════════════════════════════════

class TestTokenManager(unittest.TestCase):

    def setUp(self):
        self.manager = TokenManager()
        self.test_user = {
            "user_id": "test-123",
            "username": "testuser",
            "role": "user",
            "session_id": "session-abc"
        }

    def test_create_and_verify_access_token(self):
        """Create a token, verify it, and check payload matches."""
        token = self.manager.create_access_token(**self.test_user)
        payload = self.manager.verify_token(token, expected_type="access")

        self.assertIsNotNone(payload, "Token should be valid")
        self.assertEqual(payload.user_id, "test-123")
        self.assertEqual(payload.username, "testuser")
        self.assertEqual(payload.role, "user")
        self.assertEqual(payload.token_type, "access")

    def test_create_and_verify_refresh_token(self):
        """Refresh tokens should be verifiable with expected_type='refresh'."""
        token = self.manager.create_refresh_token(**self.test_user)
        payload = self.manager.verify_token(token, expected_type="refresh")

        self.assertIsNotNone(payload)
        self.assertEqual(payload.token_type, "refresh")

    def test_access_token_rejected_as_refresh(self):
        """An access token should be rejected when expected_type='refresh'."""
        access_token = self.manager.create_access_token(**self.test_user)
        payload = self.manager.verify_token(access_token, expected_type="refresh")
        self.assertIsNone(payload, "Access token should not verify as refresh token")

    def test_tampered_token_rejected(self):
        """A modified token should fail signature verification."""
        token = self.manager.create_access_token(**self.test_user)
        # Modify the last character to simulate tampering
        tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
        payload = self.manager.verify_token(tampered)
        self.assertIsNone(payload, "Tampered token should be rejected")

    def test_invalid_token_rejected(self):
        """A random string should not verify as a valid token."""
        payload = self.manager.verify_token("this.is.not.a.real.token")
        self.assertIsNone(payload)

    def test_token_has_jti(self):
        """Each token should have a unique JWT ID (prevents replay attacks)."""
        token1 = self.manager.create_access_token(**self.test_user)
        token2 = self.manager.create_access_token(**self.test_user)

        payload1 = self.manager.verify_token(token1)
        payload2 = self.manager.verify_token(token2)

        self.assertNotEqual(payload1.jti, payload2.jti,
            "Each token should have a unique jti")


# ══════════════════════════════════════════════════════════════
#  AUTH SERVICE TESTS
# ══════════════════════════════════════════════════════════════

class TestAuthService(unittest.TestCase):

    def setUp(self):
        self.auth = AuthService()

    def test_login_with_valid_credentials(self):
        """Demo user 'alice' should be able to log in successfully."""
        result = self.auth.login("alice", "Alice@123")
        self.assertTrue(result.success, f"Login failed: {result.message}")
        self.assertIsNotNone(result.access_token)
        self.assertIsNotNone(result.refresh_token)
        self.assertIsNotNone(result.session_id)

    def test_login_with_wrong_password(self):
        """Wrong password should fail login."""
        result = self.auth.login("alice", "wrongpassword")
        self.assertFalse(result.success)
        self.assertIsNone(result.access_token)

    def test_login_with_nonexistent_user(self):
        """Unknown username should fail gracefully (same message as wrong password)."""
        result = self.auth.login("nobody_here", "anypassword")
        self.assertFalse(result.success)

    def test_register_and_login_new_user(self):
        """Register a new user, then verify they can log in."""
        import uuid
        unique_name = f"newuser_{uuid.uuid4().hex[:8]}"
        reg = self.auth.register(unique_name, f"{unique_name}@test.com", "NewUser@123")
        self.assertTrue(reg["success"])

        login = self.auth.login(unique_name, "NewUser@123")
        self.assertTrue(login.success)

    def test_duplicate_registration_fails(self):
        """Registering the same username twice should fail."""
        import uuid
        dup_name = f"dupuser_{uuid.uuid4().hex[:8]}"
        self.auth.register(dup_name, "dup@test.com", "Dup@12345")
        result = self.auth.register(dup_name, "dup2@test.com", "Dup@12345")
        self.assertFalse(result["success"])

    def test_verify_valid_token(self):
        """Token from login should verify successfully."""
        login = self.auth.login("alice", "Alice@123")
        payload = self.auth.verify_token(login.access_token)
        self.assertIsNotNone(payload)
        self.assertEqual(payload.username, "alice")

    def test_verify_invalid_token(self):
        """Garbage token should return None."""
        payload = self.auth.verify_token("garbage.token.here")
        self.assertIsNone(payload)

    def test_logout_invalidates_session(self):
        """After logout, the access token should no longer be valid."""
        login = self.auth.login("bob", "Bob@123")
        self.assertTrue(login.success)

        # Log out
        logout = self.auth.logout(login.session_id)
        self.assertTrue(logout["success"])

        # Token should now be invalid
        payload = self.auth.verify_token(login.access_token)
        self.assertIsNone(payload, "Token should be invalid after logout")

    def test_account_lockout_after_5_failures(self):
        """Account should lock after 5 failed login attempts."""
        import uuid
        lock_name = f"locktest_{uuid.uuid4().hex[:8]}"
        self.auth.register(lock_name, f"{lock_name}@test.com", "Lock@123")
        for _ in range(5):
            self.auth.login(lock_name, "wrongpassword")

        result = self.auth.login(lock_name, "Lock@123")  # Correct password
        self.assertFalse(result.success)
        self.assertIn("locked", result.message.lower())

    def test_refresh_token_flow(self):
        """Refresh token should produce a new valid access token."""
        login = self.auth.login("alice", "Alice@123")
        result = self.auth.refresh_access_token(login.refresh_token)

        self.assertTrue(result.success)
        self.assertIsNotNone(result.access_token)
        # New access token should be verifiable
        payload = self.auth.verify_token(result.access_token)
        self.assertIsNotNone(payload)


# ══════════════════════════════════════════════════════════════
#  DEVICE TRUST TESTS
# ══════════════════════════════════════════════════════════════

class TestDeviceTrust(unittest.TestCase):

    def setUp(self):
        self.engine = DeviceTrustEngine()

    def test_fully_compliant_device_is_trusted(self):
        """A managed, patched, encrypted device should be fully trusted."""
        from datetime import timedelta
        device = self.engine.register_device(
            fingerprint="test-trusted-001",
            owner_user_id="user-1",
            os_type=DeviceOS.MACOS,
            is_managed=True,
            last_patch_date=(datetime.now(timezone.utc) - timedelta(days=3)).isoformat(),
            is_encrypted=True,
            has_antivirus=True,
            is_jailbroken=False
        )
        report = self.engine.assess_posture(device)
        self.assertEqual(report.trust_level, DeviceTrustLevel.FULLY_TRUSTED,
            f"Compliant device got {report.trust_level}, expected FULLY_TRUSTED")

    def test_jailbroken_device_is_untrusted(self):
        """Jailbroken device should never be fully trusted."""
        device = self.engine.register_device(
            fingerprint="test-jailbroken-001",
            owner_user_id="user-2",
            is_jailbroken=True,
            is_managed=True,
            is_encrypted=True,
            has_antivirus=True
        )
        report = self.engine.assess_posture(device)
        self.assertIn(report.trust_level, [
            DeviceTrustLevel.LOW_TRUST,
            DeviceTrustLevel.UNTRUSTED
        ])

    def test_unmanaged_device_has_reduced_score(self):
        """Unmanaged device should score lower than managed."""
        from datetime import timedelta
        managed = self.engine.register_device(
            "fp-managed", "u1", is_managed=True,
            last_patch_date=(datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
            is_encrypted=True, has_antivirus=True
        )
        unmanaged = self.engine.register_device(
            "fp-unmanaged", "u1", is_managed=False,
            last_patch_date=(datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
            is_encrypted=True, has_antivirus=True
        )
        m_report = self.engine.assess_posture(managed)
        u_report = self.engine.assess_posture(unmanaged)
        self.assertGreater(m_report.compliance_score, u_report.compliance_score)

    def test_unknown_device_returns_none(self):
        """Looking up a fingerprint we've never seen should return None."""
        device = self.engine.get_device("completely-unknown-fingerprint-xyz")
        self.assertIsNone(device)


# ══════════════════════════════════════════════════════════════
#  SESSION MONITOR TESTS
# ══════════════════════════════════════════════════════════════

class TestSessionMonitor(unittest.TestCase):

    def setUp(self):
        self.monitor = SessionMonitor()

    def test_new_session_created_on_first_request(self):
        """First request for a session should create activity record."""
        result = self.monitor.track_request("sess-1", "user-1", "/api/data", "10.0.0.1")
        self.assertEqual(result["request_count"], 1)
        self.assertFalse(result["is_anomalous"])

    def test_rate_limit_detected(self):
        """Sending 150 rapid requests should trigger rate limit anomaly."""
        self.monitor.max_requests_per_minute = 10  # Lower threshold for test
        for _ in range(15):
            result = self.monitor.track_request("sess-rate", "user-2", "/api/data", "10.0.0.2")
        self.assertTrue(result["is_anomalous"], "Rate limit should trigger anomaly")

    def test_ip_change_detected(self):
        """Changing IP mid-session should be flagged as anomalous."""
        self.monitor.track_request("sess-ip", "user-3", "/api/data", "10.0.0.1")
        result = self.monitor.track_request("sess-ip", "user-3", "/api/data", "192.168.1.100")
        self.assertTrue(result["is_anomalous"], "IP change should be flagged")

    def test_session_summary_returns_data(self):
        """After activity, session summary should have correct data."""
        self.monitor.track_request("sess-sum", "user-4", "/api/resource1", "10.0.0.1")
        self.monitor.track_request("sess-sum", "user-4", "/api/resource2", "10.0.0.1")

        summary = self.monitor.get_session_summary("sess-sum")
        self.assertIsNotNone(summary)
        self.assertEqual(summary["request_count"], 2)
        self.assertEqual(summary["resources_accessed"], 2)

    def test_terminate_session(self):
        """Terminated session should show as inactive."""
        self.monitor.track_request("sess-term", "user-5", "/api/data", "10.0.0.1")
        self.monitor.terminate_session("sess-term", "test")

        summary = self.monitor.get_session_summary("sess-term")
        self.assertFalse(summary["is_active"])


# ══════════════════════════════════════════════════════════════
#  INTEGRATION TEST — FULL PIPELINE
# ══════════════════════════════════════════════════════════════

class TestFullPipeline(unittest.TestCase):
    """
    Integration tests that exercise the complete Zero Trust pipeline:
    login → risk scoring → policy decision → audit log
    """

    def setUp(self):
        self.auth = AuthService()
        self.scorer = RiskScorer()
        self.engine = PolicyEngine()
        self.logger = AuditLogger()

    def _run_pipeline(self, identity, device, behavior, context):
        """Helper: run the complete pipeline and return the policy result."""
        assessment = self.scorer.compute_risk(identity, device, behavior, context)
        result = self.engine.evaluate(assessment, user_id="test", resource="/api/data")
        self.logger.log_access_request(
            user_id="test", username="testuser", resource="/api/data",
            action="GET", risk_score=assessment.final_score,
            risk_level=assessment.risk_level,
            policy_decision=result.decision.value,
            access_level=result.access_level.value
        )
        return result, assessment

    def test_trusted_employee_gets_full_access(self):
        """Scenario: Trusted employee on managed device should get ALLOW."""
        from datetime import timedelta
        result, assessment = self._run_pipeline(
            identity=IdentityRiskFactors(is_mfa_enabled=True, failed_login_attempts=0),
            device=DeviceRiskFactors(is_managed=True, os_patch_days=5, has_antivirus=True, is_encrypted=True),
            behavior=BehaviorRiskFactors(requests_per_minute=5),
            context=ContextRiskFactors(ip_reputation_score=0.0)
        )
        self.assertEqual(result.decision, AccessDecision.ALLOW)
        self.assertLessEqual(assessment.final_score, 24)

    def test_attacker_gets_denied(self):
        """Scenario: Maximum risk factors across all dimensions = DENY."""
        # To guarantee DENY (score ≥ 90), all 4 dimensions need to max out
        result, assessment = self._run_pipeline(
            identity=IdentityRiskFactors(
                is_mfa_enabled=False, failed_login_attempts=5,
                is_privileged_account=True, unusual_login_time=True, account_age_days=1
            ),
            device=DeviceRiskFactors(
                jailbroken_or_rooted=True, is_managed=False,
                has_antivirus=False, is_encrypted=False, os_patch_days=365
            ),
            behavior=BehaviorRiskFactors(
                privilege_escalation_attempt=True, requests_per_minute=200,
                bulk_download_detected=True, accessing_sensitive_data=True, anomaly_score=100
            ),
            context=ContextRiskFactors(
                ip_reputation_score=95.0, geolocation_anomaly=True,
                vpn_or_proxy=True, new_device_fingerprint=True, time_of_day_risk=100
            )
        )
        self.assertEqual(result.decision, AccessDecision.DENY,
            f"Max-risk attacker scored {assessment.final_score}, expected DENY")
        self.assertGreaterEqual(assessment.final_score, 90)

    def test_audit_log_records_decisions(self):
        """Every decision should appear in the audit log."""
        initial_count = self.logger.get_event_count()
        self._run_pipeline(
            IdentityRiskFactors(), DeviceRiskFactors(),
            BehaviorRiskFactors(), ContextRiskFactors()
        )
        self.assertEqual(self.logger.get_event_count(), initial_count + 1)

    def test_login_then_verify_token(self):
        """Login → get token → verify token → check user identity."""
        login = self.auth.login("admin", "Admin@123")
        self.assertTrue(login.success)

        payload = self.auth.verify_token(login.access_token)
        self.assertIsNotNone(payload)
        self.assertEqual(payload.username, "admin")
        self.assertEqual(payload.role, "admin")


# ══════════════════════════════════════════════════════════════
#  TEST RUNNER
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Create a test runner with verbose output
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    test_classes = [
        TestConfig,
        TestRiskScorer,
        TestPolicyEngine,
        TestTokenManager,
        TestAuthService,
        TestDeviceTrust,
        TestSessionMonitor,
        TestFullPipeline
    ]

    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)

    # Run with verbosity=2 to see each test name and result
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Summary
    total = result.testsRun
    failures = len(result.failures)
    errors = len(result.errors)
    passed = total - failures - errors

    print(f"\n{'='*60}")
    print(f"  ZERO TRUST TEST SUITE RESULTS")
    print(f"{'='*60}")
    print(f"  Total Tests : {total}")
    print(f"  Passed      : {passed} ✓")
    print(f"  Failed      : {failures} ✗")
    print(f"  Errors      : {errors} ⚠")
    print(f"{'='*60}")

    if failures == 0 and errors == 0:
        print("  ALL TESTS PASSED — System is operational ✓")
    else:
        print("  SOME TESTS FAILED — Review output above")
    print(f"{'='*60}")

    sys.exit(0 if failures == 0 and errors == 0 else 1)