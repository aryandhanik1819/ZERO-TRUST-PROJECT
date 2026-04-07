# ============================================================
#  api/main.py — FastAPI REST API Server
# ============================================================
#
#  WHAT IS THIS?
#  This is the front door of the Zero Trust system.
#  Every request from the outside world comes through here.
#
#  It wires together ALL the modules:
#    1. Request arrives
#    2. Identity module verifies the token
#    3. Risk engine scores the request
#    4. Policy engine makes a decision
#    5. Session monitor tracks activity
#    6. Audit logger records everything
#    7. Response returned to client
#
#  WHY FASTAPI?
#  - Automatic API docs (Swagger UI at /docs)
#  - Built-in request validation with Pydantic
#  - Async support for high throughput
#  - Type hints = fewer bugs
#
#  ENDPOINTS:
#    POST /auth/login      → Log in, get JWT tokens
#    POST /auth/logout     → Invalidate session
#    POST /auth/refresh    → Get new access token
#    POST /auth/register   → Create new user
#    GET  /access/check    → Zero Trust access decision
#    GET  /audit/events    → View audit log
#    GET  /monitor/sessions → View active sessions
#    GET  /health          → System health check
# ============================================================

from fastapi import FastAPI, HTTPException, Depends, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional
import time

from config.settings import config
from identity.auth_services import AuthService
from policy.rules.risk_scorer import (
    RiskScorer,
    IdentityRiskFactors,
    DeviceRiskFactors,
    BehaviorRiskFactors,
    ContextRiskFactors
)
from policy.rules.policy_engine import PolicyEngine
from device.device_trust import DeviceTrustEngine
from monitoring.session_monitor import session_monitor
from audit.audit_logger import audit_logger


# ── App Initialization ────────────────────────────────────────

app = FastAPI(
    title=config.app_name,
    version=config.version,
    description="""
    ## Zero Trust Network Security Framework

    This API implements the Zero Trust security model:
    **"Never trust, always verify."**

    Every request is scored for risk across 4 dimensions:
    - 🔐 Identity (who are you?)
    - 💻 Device (is your device trusted?)
    - 🧠 Behavior (are you acting normally?)
    - 🌍 Context (where/when is this request?)

    The risk score determines your access level.
    """,
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Middleware — allows browser-based frontends to call the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],       # In production: specify exact allowed domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Module Instances ──────────────────────────────────────────
# Each module is instantiated once and shared across all requests
auth_service = AuthService()
risk_scorer = RiskScorer()
policy_engine = PolicyEngine()
device_engine = DeviceTrustEngine()


# ── Request/Response Models (Pydantic) ────────────────────────
# Pydantic validates that incoming request data has the right shape.
# If required fields are missing or have wrong types, FastAPI
# automatically returns a 422 error with a clear message.

class LoginRequest(BaseModel):
    username: str = Field(..., example="alice", description="Your username")
    password: str = Field(..., example="Alice@123", description="Your password")

class RegisterRequest(BaseModel):
    username: str = Field(..., example="charlie")
    email: str = Field(..., example="charlie@example.com")
    password: str = Field(..., min_length=8, example="Charlie@123")
    role: str = Field(default="user", example="user")

class AccessCheckRequest(BaseModel):
    """
    The Zero Trust access check request.
    The client tells us about itself so we can compute a risk score.
    """
    resource: str = Field(..., example="/api/financial-data", description="What are you trying to access?")
    action: str = Field(default="GET", example="GET")

    # Identity context
    failed_login_attempts: int = Field(default=0, example=0)
    is_mfa_enabled: bool = Field(default=True, example=True)

    # Device context
    device_fingerprint: str = Field(default="", example="my-laptop-001")
    is_managed_device: bool = Field(default=False, example=True)
    os_patch_days: int = Field(default=0, example=0, description="Days since last OS patch")
    has_antivirus: bool = Field(default=True, example=True)
    is_encrypted: bool = Field(default=True, example=True)
    is_jailbroken: bool = Field(default=False, example=False)

    # Behavioral context
    requests_per_minute: int = Field(default=5, example=5)
    accessing_sensitive_data: bool = Field(default=False, example=False)

    # Context
    ip_reputation_score: float = Field(default=0.0, example=0.0, ge=0, le=100)
    vpn_or_proxy: bool = Field(default=False, example=False)
    geolocation_anomaly: bool = Field(default=False, example=False)


# ── Authentication Helper ─────────────────────────────────────

async def get_current_user(authorization: Optional[str] = Header(None)):
    """
    FastAPI dependency — extracts and verifies the bearer token.

    Usage: add `current_user = Depends(get_current_user)` to any
    endpoint that requires authentication.

    The client sends: Authorization: Bearer <access_token>
    We extract the token, verify it, and return the user payload.
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header missing")

    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization format. Use: Bearer <token>")

    token = authorization.split(" ", 1)[1]
    payload = auth_service.verify_token(token)

    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token. Please log in again.")

    return payload


# ── Middleware: Request Timing ────────────────────────────────

@app.middleware("http")
async def add_timing_header(request: Request, call_next):
    """
    Middleware runs on EVERY request, before and after the handler.
    This one measures how long each request takes and adds it to
    the response header — useful for performance monitoring.
    """
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = f"{process_time:.4f}s"
    return response


# ── Routes ────────────────────────────────────────────────────

# ── Health Check ─────────────────────────────────────────────
@app.get("/health", tags=["System"])
async def health_check():
    """
    Returns system health status.
    Used by load balancers and monitoring tools to verify the API is up.
    """
    return {
        "status": "healthy",
        "app": config.app_name,
        "version": config.version,
        "modules": {
            "identity": "operational",
            "risk_engine": "operational",
            "policy_engine": "operational",
            "device_trust": "operational",
            "session_monitor": "operational",
            "audit_logger": "operational"
        }
    }


# ── Authentication Routes ─────────────────────────────────────

@app.post("/auth/register", tags=["Authentication"])
async def register(body: RegisterRequest):
    """Register a new user account."""
    result = auth_service.register(
        username=body.username,
        email=body.email,
        password=body.password,
        role=body.role
    )
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["message"])
    return result


@app.post("/auth/login", tags=["Authentication"])
async def login(body: LoginRequest, request: Request):
    """
    Authenticate and receive JWT tokens.

    Returns:
    - access_token:  Use in Authorization header for API calls
    - refresh_token: Use to get a new access token when it expires
    """
    ip = request.client.host if request.client else ""
    user_agent = request.headers.get("user-agent", "")

    result = auth_service.login(
        username=body.username,
        password=body.password,
        ip_address=ip,
        user_agent=user_agent
    )

    # Log the login attempt
    audit_logger.log_login(
        user_id=result.user_info.get("user_id", "") if result.user_info else "",
        username=body.username,
        success=result.success,
        ip_address=ip
    )

    if not result.success:
        raise HTTPException(status_code=401, detail=result.message)

    return {
        "access_token": result.access_token,
        "refresh_token": result.refresh_token,
        "token_type": "bearer",
        "session_id": result.session_id,
        "user": result.user_info,
        "message": result.message
    }


@app.post("/auth/logout", tags=["Authentication"])
async def logout(current_user=Depends(get_current_user)):
    """Log out — invalidates the current session."""
    result = auth_service.logout(current_user.session_id)
    session_monitor.terminate_session(current_user.session_id, reason="User logged out")
    return result


@app.post("/auth/refresh", tags=["Authentication"])
async def refresh_token(authorization: Optional[str] = Header(None)):
    """
    Get a new access token using your refresh token.
    Send the refresh token in the Authorization header.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Refresh token required")

    refresh_token = authorization.split(" ", 1)[1]
    result = auth_service.refresh_access_token(refresh_token)

    if not result.success:
        raise HTTPException(status_code=401, detail=result.message)

    return {
        "access_token": result.access_token,
        "refresh_token": result.refresh_token,
        "token_type": "bearer"
    }


# ── Zero Trust Access Check ───────────────────────────────────

@app.post("/access/check", tags=["Zero Trust"])
async def check_access(
    body: AccessCheckRequest,
    request: Request,
    current_user=Depends(get_current_user)
):
    """
    ## The Core Zero Trust Access Decision

    This endpoint runs the complete Zero Trust pipeline:
    1. Identifies the user (from JWT)
    2. Computes risk score across 4 dimensions
    3. Makes policy decision (ALLOW/DENY/STEP_UP/etc.)
    4. Tracks the activity in session monitor
    5. Logs the complete decision to audit trail
    6. Returns the decision with full explanation

    Try it with different risk factors to see how the score changes!
    """
    ip = request.client.host if request.client else ""

    # ── Step 1: Get user details for risk computation ─────────
    user = auth_service.get_user_by_id(current_user.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # ── Step 2: Build risk factor objects ─────────────────────
    identity_factors = IdentityRiskFactors(
        failed_login_attempts=user.failed_attempts,
        is_mfa_enabled=user.mfa_enabled,
        account_age_days=365,                       # Simplified for demo
        is_privileged_account=(user.role == "admin"),
        unusual_login_time=False                    # Simplified — real: compare to baseline
    )

    device_factors = DeviceRiskFactors(
        is_managed=body.is_managed_device,
        os_patch_days=body.os_patch_days,
        has_antivirus=body.has_antivirus,
        is_encrypted=body.is_encrypted,
        jailbroken_or_rooted=body.is_jailbroken
    )

    behavior_factors = BehaviorRiskFactors(
        requests_per_minute=body.requests_per_minute,
        accessing_sensitive_data=body.accessing_sensitive_data,
        bulk_download_detected=False,
        privilege_escalation_attempt=False,
        anomaly_score=0.0
    )

    context_factors = ContextRiskFactors(
        ip_reputation_score=body.ip_reputation_score,
        geolocation_anomaly=body.geolocation_anomaly,
        vpn_or_proxy=body.vpn_or_proxy,
        time_of_day_risk=0.0,
        new_device_fingerprint=(body.device_fingerprint == "")
    )

    # ── Step 3: Compute risk score ────────────────────────────
    assessment = risk_scorer.compute_risk(
        identity=identity_factors,
        device=device_factors,
        behavior=behavior_factors,
        context=context_factors
    )

    # ── Step 4: Policy decision ───────────────────────────────
    policy_result = policy_engine.evaluate(
        assessment=assessment,
        user_id=current_user.user_id,
        resource=body.resource
    )

    # ── Step 5: Track in session monitor ─────────────────────
    monitoring_result = session_monitor.track_request(
        session_id=current_user.session_id,
        user_id=current_user.user_id,
        resource=body.resource,
        ip_address=ip
    )

    # ── Step 6: Audit log ─────────────────────────────────────
    audit_logger.log_access_request(
        user_id=current_user.user_id,
        username=current_user.username,
        resource=body.resource,
        action=body.action,
        risk_score=assessment.final_score,
        risk_level=assessment.risk_level,
        policy_decision=policy_result.decision.value,
        access_level=policy_result.access_level.value,
        ip_address=ip,
        device_fingerprint=body.device_fingerprint,
        session_id=current_user.session_id,
        risk_factors=assessment.explanation
    )

    # ── Step 7: Return the complete decision ──────────────────
    return {
        "decision": policy_result.decision.value,
        "access_level": policy_result.access_level.value,
        "message": policy_result.message,
        "risk_assessment": {
            "final_score": assessment.final_score,
            "risk_level": assessment.risk_level,
            "breakdown": {
                "identity": assessment.identity_score,
                "device": assessment.device_score,
                "behavioral": assessment.behavioral_score,
                "context": assessment.context_score
            },
            "explanation": assessment.explanation
        },
        "required_actions": policy_result.required_actions,
        "session_limits": policy_result.session_limits,
        "monitoring": {
            "anomalies_detected": monitoring_result["is_anomalous"],
            "anomalies": monitoring_result["anomalies"],
            "session_request_count": monitoring_result["request_count"]
        },
        "timestamp": policy_result.timestamp
    }


@app.get("/access/simulate", tags=["Zero Trust"])
async def simulate_scenarios():
    """
    Run all 5 predefined scenarios to demonstrate the system.
    No authentication required — great for exploring the system.
    """
    scenarios = [
        {
            "name": "Trusted Employee (Normal Access)",
            "description": "Managed device, MFA enabled, normal behavior",
            "identity": IdentityRiskFactors(is_mfa_enabled=True, failed_login_attempts=0),
            "device": DeviceRiskFactors(is_managed=True, os_patch_days=5, has_antivirus=True, is_encrypted=True),
            "behavior": BehaviorRiskFactors(requests_per_minute=5),
            "context": ContextRiskFactors(ip_reputation_score=0.0)
        },
        {
            "name": "Remote Worker (Elevated Risk)",
            "description": "VPN, personal unmanaged device",
            "identity": IdentityRiskFactors(is_mfa_enabled=True),
            "device": DeviceRiskFactors(is_managed=False, os_patch_days=45, has_antivirus=True),
            "behavior": BehaviorRiskFactors(requests_per_minute=10),
            "context": ContextRiskFactors(vpn_or_proxy=True, new_device_fingerprint=True)
        },
        {
            "name": "Suspicious Activity (Step-Up Required)",
            "description": "No MFA, old patches, suspicious IP",
            "identity": IdentityRiskFactors(is_mfa_enabled=False, failed_login_attempts=2),
            "device": DeviceRiskFactors(is_managed=False, os_patch_days=95),
            "behavior": BehaviorRiskFactors(requests_per_minute=80, accessing_sensitive_data=True),
            "context": ContextRiskFactors(ip_reputation_score=55, vpn_or_proxy=True)
        },
        {
            "name": "Compromised Account (Restrict)",
            "description": "Geolocation anomaly, bulk download, suspicious IP",
            "identity": IdentityRiskFactors(is_mfa_enabled=False, failed_login_attempts=3),
            "device": DeviceRiskFactors(is_managed=False, os_patch_days=120, has_antivirus=False),
            "behavior": BehaviorRiskFactors(bulk_download_detected=True, accessing_sensitive_data=True, anomaly_score=70),
            "context": ContextRiskFactors(geolocation_anomaly=True, ip_reputation_score=75)
        },
        {
            "name": "Active Attack (DENY)",
            "description": "Jailbroken device, privilege escalation, known-bad IP",
            "identity": IdentityRiskFactors(is_mfa_enabled=False, failed_login_attempts=5),
            "device": DeviceRiskFactors(jailbroken_or_rooted=True, is_managed=False, has_antivirus=False),
            "behavior": BehaviorRiskFactors(privilege_escalation_attempt=True, requests_per_minute=200, anomaly_score=90),
            "context": ContextRiskFactors(ip_reputation_score=95, geolocation_anomaly=True)
        }
    ]

    results = []
    for scenario in scenarios:
        assessment = risk_scorer.compute_risk(
            identity=scenario["identity"],
            device=scenario["device"],
            behavior=scenario["behavior"],
            context=scenario["context"]
        )
        policy_result = policy_engine.evaluate(assessment)

        results.append({
            "scenario": scenario["name"],
            "description": scenario["description"],
            "risk_score": assessment.final_score,
            "risk_level": assessment.risk_level,
            "decision": policy_result.decision.value,
            "access_level": policy_result.access_level.value,
            "top_risk_factors": assessment.explanation[:3]
        })

    return {"scenarios": results}


# ── Audit & Monitoring Routes ─────────────────────────────────

@app.get("/audit/events", tags=["Audit & Monitoring"])
async def get_audit_events(limit: int = 20, current_user=Depends(get_current_user)):
    """
    Get recent audit events.
    Admins see all events; regular users see only their own.
    """
    if current_user.role == "admin":
        events = audit_logger.get_recent_events(limit=limit)
    else:
        events = audit_logger.get_events_for_user(current_user.user_id, limit=limit)

    # Convert dataclass objects to dicts for JSON serialization
    from dataclasses import asdict
    return {
        "events": [asdict(e) if hasattr(e, '__dataclass_fields__') else e for e in events],
        "count": len(events)
    }


@app.get("/audit/denied", tags=["Audit & Monitoring"])
async def get_denied_requests(current_user=Depends(get_current_user)):
    """Get recently denied access requests — security monitoring view."""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    from dataclasses import asdict
    denied = audit_logger.get_denied_requests(limit=50)
    return {
        "denied_requests": [asdict(e) if hasattr(e, '__dataclass_fields__') else e for e in denied],
        "count": len(denied)
    }


@app.get("/monitor/sessions", tags=["Audit & Monitoring"])
async def get_active_sessions(current_user=Depends(get_current_user)):
    """Get all active sessions. Admin-only."""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    return {
        "active_sessions": session_monitor.get_all_active_sessions()
    }


@app.get("/monitor/my-session", tags=["Audit & Monitoring"])
async def get_my_session(current_user=Depends(get_current_user)):
    """Get your own session activity summary."""
    summary = session_monitor.get_session_summary(current_user.session_id)
    return summary or {"message": "No session data found"}