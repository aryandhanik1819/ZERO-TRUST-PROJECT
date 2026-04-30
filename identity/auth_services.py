# ============================================================
#  identity/auth_service.py — Authentication Service
# ============================================================
#
#  WHAT IS AUTHENTICATION?
#  Authentication = "Prove who you are."
#  (Authorization = "What are you allowed to do?" — that's the policy engine)
#
#  This module handles:
#  - Storing users (persisted in SQLite via SQLAlchemy)
#  - Hashing passwords securely with bcrypt
#  - Verifying login credentials
#  - Creating sessions with JWT tokens
#  - Logout / session invalidation
#
#  PASSWORD HASHING EXPLAINED:
#  We NEVER store plain passwords. If the database is breached,
#  the attacker gets hashes, not passwords.
#
#  bcrypt is special because:
#  1. It's intentionally slow (makes brute-force attacks take forever)
#  2. It adds a "salt" (random data) so identical passwords get different hashes
#  3. It has a "work factor" — as computers get faster, increase the factor
#
#  Example:
#    Password: "hunter2"
#    Salt:     "$2b$12$randomsalthere"
#    Hash:     "$2b$12$randomsalthere...longhashstring"
#
#  PERSISTENCE:
#  Users and sessions are stored in SQLite via SQLAlchemy.
#  This means data survives server restarts.
#  To switch to PostgreSQL, just change DATABASE_URL in config.
# ============================================================

import bcrypt
import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, List
from dataclasses import dataclass, field
from identity.token_manager import TokenManager, TokenPayload
from config.settings import config
from database import SessionLocal
from models import UserModel, SessionModel, BlacklistedTokenModel


# ── User Model ────────────────────────────────────────────────

@dataclass
class User:
    """
    Represents a user account in the system (DTO — Data Transfer Object).

    hashed_password: We store the bcrypt hash, NEVER the plain password.
    role:            "user", "admin", or "readonly"
    is_active:       Disabled accounts cannot log in.
    failed_attempts: Track failed logins for risk scoring + lockout.
    mfa_enabled:     Whether this user has 2FA set up.
    """
    user_id: str
    username: str
    email: str
    hashed_password: str
    role: str = "user"
    is_active: bool = True
    failed_attempts: int = 0
    mfa_enabled: bool = False
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_login: Optional[str] = None


@dataclass
class Session:
    """
    Represents one active login session (DTO).

    A user can have multiple sessions (laptop + phone + tablet).
    Each session has its own access and refresh tokens.
    Sessions can be individually invalidated (e.g., "log out of all devices").
    """
    session_id: str
    user_id: str
    access_token: str
    refresh_token: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_active: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    ip_address: str = ""
    user_agent: str = ""
    is_active: bool = True


@dataclass
class LoginResult:
    """
    The response from a login attempt.

    success:       True if login worked
    access_token:  Short-lived token for API calls
    refresh_token: Long-lived token to get new access tokens
    user_info:     Safe user info (no password hash!)
    message:       Success or error message
    """
    success: bool
    message: str
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    user_info: Optional[dict] = None
    session_id: Optional[str] = None


# ── Helper: Convert ORM model ↔ DTO ──────────────────────────

def _user_from_model(m: UserModel) -> User:
    """Convert a SQLAlchemy UserModel row to a User dataclass (DTO)."""
    return User(
        user_id=m.user_id,
        username=m.username,
        email=m.email,
        hashed_password=m.hashed_password,
        role=m.role,
        is_active=m.is_active,
        failed_attempts=m.failed_attempts,
        mfa_enabled=m.mfa_enabled,
        created_at=m.created_at,
        last_login=m.last_login,
    )


# ── Authentication Service ────────────────────────────────────

class AuthService:
    """
    The central authentication authority.

    Users and sessions are stored in SQLite via SQLAlchemy.
    Each method opens its own short-lived DB session (unit of work)
    so the service is safe to use from async FastAPI endpoints.

    FLOW:
    register() → create user with hashed password
    login()    → verify password → create session → return tokens
    verify()   → check access token → return user identity
    logout()   → invalidate session
    refresh()  → exchange refresh token for new access token
    """

    def __init__(self):
        self.token_manager = TokenManager()

        # Seed demo users if the database is empty (idempotent)
        self._seed_demo_users()

    def _seed_demo_users(self):
        """
        Creates default demo users for testing — only if no users exist yet.
        In production, users would register via signup or LDAP/SSO.
        """
        db = SessionLocal()
        try:
            existing = db.query(UserModel).first()
            if existing is not None:
                return  # DB already has users — skip seeding
        finally:
            db.close()

        self.register("admin", "admin@zerotrust.local", "Admin@123", role="admin", mfa_enabled=True)
        self.register("alice", "alice@zerotrust.local", "Alice@123", role="user", mfa_enabled=True)
        self.register("bob", "bob@zerotrust.local", "Bob@123", role="readonly")

    def _hash_password(self, plain_password: str) -> str:
        """
        Hash a plain password using bcrypt.

        bcrypt.hashpw() takes:
        - The password as bytes
        - A salt generated by bcrypt.gensalt(rounds=12)
          rounds=12 means 2^12 = 4096 iterations (very slow for attackers)

        Returns the hash as a string.
        """
        password_bytes = plain_password.encode("utf-8")
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password_bytes, salt)
        return hashed.decode("utf-8")

    def _verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Check if a plain password matches a stored hash.

        bcrypt.checkpw() recomputes the hash with the embedded salt
        and compares in constant time (prevents timing attacks).
        """
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8")
        )

    def register(
        self,
        username: str,
        email: str,
        password: str,
        role: str = "user",
        mfa_enabled: bool = False
    ) -> dict:
        """
        Create a new user account.

        Returns a dict with success status and message.
        Password is hashed immediately — never stored in plain form.
        """
        db = SessionLocal()
        try:
            # Check username isn't already taken
            existing = db.query(UserModel).filter(UserModel.username == username).first()
            if existing is not None:
                return {"success": False, "message": f"Username '{username}' already exists"}

            user_id = str(uuid.uuid4())
            db_user = UserModel(
                user_id=user_id,
                username=username,
                email=email,
                hashed_password=self._hash_password(password),
                role=role,
                mfa_enabled=mfa_enabled,
            )
            db.add(db_user)
            db.commit()
            return {"success": True, "message": f"User '{username}' registered successfully", "user_id": user_id}
        finally:
            db.close()

    def login(
        self,
        username: str,
        password: str,
        ip_address: str = "",
        user_agent: str = ""
    ) -> LoginResult:
        """
        Authenticate a user and create a session.

        STEP BY STEP:
        1. Check if user exists
        2. Check if account is active (not disabled)
        3. Check if account is locked (too many failed attempts)
        4. Verify password with bcrypt
        5. Reset failed attempt counter on success
        6. Create a session (access + refresh tokens)
        7. Return tokens to the caller
        """
        db = SessionLocal()
        try:
            # Step 1: Find the user
            db_user = db.query(UserModel).filter(UserModel.username == username).first()
            if not db_user:
                return LoginResult(success=False, message="Invalid username or password")
                # NOTE: We give the same error for "user not found" and "wrong password"
                # This prevents "username enumeration" — attackers can't tell which is wrong

            # Step 2: Account must be active
            if not db_user.is_active:
                return LoginResult(success=False, message="Account is disabled. Contact administrator.")

            # Step 3: Account lockout after too many failures
            if db_user.failed_attempts >= 5:
                return LoginResult(success=False, message="Account temporarily locked due to failed login attempts.")

            # Step 4: Password verification
            if not self._verify_password(password, db_user.hashed_password):
                db_user.failed_attempts += 1
                db.commit()
                return LoginResult(
                    success=False,
                    message=f"Invalid username or password. Attempt {db_user.failed_attempts}/5"
                )

            # Step 5: Successful login — reset failure counter
            db_user.failed_attempts = 0
            db_user.last_login = datetime.now(timezone.utc).isoformat()

            # Step 6: Create session
            session_id = str(uuid.uuid4())

            access_token = self.token_manager.create_access_token(
                user_id=db_user.user_id,
                username=db_user.username,
                role=db_user.role,
                session_id=session_id
            )
            refresh_token = self.token_manager.create_refresh_token(
                user_id=db_user.user_id,
                username=db_user.username,
                role=db_user.role,
                session_id=session_id
            )

            db_session = SessionModel(
                session_id=session_id,
                user_id=db_user.user_id,
                access_token=access_token,
                refresh_token=refresh_token,
                ip_address=ip_address,
                user_agent=user_agent,
            )
            db.add(db_session)
            db.commit()

            # Step 7: Return result
            return LoginResult(
                success=True,
                message="Login successful",
                access_token=access_token,
                refresh_token=refresh_token,
                session_id=session_id,
                user_info={
                    "user_id": db_user.user_id,
                    "username": db_user.username,
                    "email": db_user.email,
                    "role": db_user.role,
                    "mfa_enabled": db_user.mfa_enabled
                }
            )
        finally:
            db.close()

    def verify_token(self, access_token: str) -> Optional[TokenPayload]:
        """
        Verify an access token from an API request.

        Returns the token payload (user identity) if valid.
        Returns None if invalid or expired.

        This is called on EVERY protected API request.
        """
        payload = self.token_manager.verify_token(access_token, expected_type="access")
        if not payload:
            return None

        db = SessionLocal()
        try:
            # Check the session is still active
            db_session = db.query(SessionModel).filter(
                SessionModel.session_id == payload.session_id,
                SessionModel.is_active == True  # noqa: E712
            ).first()
            if not db_session:
                return None

            # Check the token hasn't been blacklisted
            blacklisted = db.query(BlacklistedTokenModel).filter(
                BlacklistedTokenModel.jti == payload.jti
            ).first()
            if blacklisted:
                return None

            # Update last active time
            db_session.last_active = datetime.now(timezone.utc).isoformat()
            db.commit()
            return payload
        finally:
            db.close()

    def refresh_access_token(self, refresh_token: str) -> LoginResult:
        """
        Use a refresh token to get a new access token.

        Called when the access token expires (every 30 minutes).
        The user doesn't need to log in again — the refresh token
        handles it silently.
        """
        payload = self.token_manager.verify_token(refresh_token, expected_type="refresh")
        if not payload:
            return LoginResult(success=False, message="Invalid or expired refresh token")

        db = SessionLocal()
        try:
            # Check the session is still valid
            db_session = db.query(SessionModel).filter(
                SessionModel.session_id == payload.session_id,
                SessionModel.is_active == True  # noqa: E712
            ).first()
            if not db_session:
                return LoginResult(success=False, message="Session has been invalidated")

            # Issue a new access token with the same session
            new_access_token = self.token_manager.create_access_token(
                user_id=payload.user_id,
                username=payload.username,
                role=payload.role,
                session_id=payload.session_id
            )
            db_session.access_token = new_access_token
            db.commit()

            return LoginResult(
                success=True,
                message="Token refreshed successfully",
                access_token=new_access_token,
                refresh_token=refresh_token,  # Return the same refresh token
                session_id=payload.session_id
            )
        finally:
            db.close()

    def logout(self, session_id: str) -> dict:
        """
        Invalidate a specific session (logout from this device).
        Also blacklists the session's tokens to prevent reuse.
        """
        db = SessionLocal()
        try:
            db_session = db.query(SessionModel).filter(
                SessionModel.session_id == session_id
            ).first()
            if db_session:
                db_session.is_active = False

                # Blacklist the access token's JTI so it can't be reused
                access_payload = self.token_manager.decode_without_verify(db_session.access_token)
                if access_payload and "jti" in access_payload:
                    blacklist_entry = BlacklistedTokenModel(jti=access_payload["jti"])
                    db.merge(blacklist_entry)  # merge to avoid duplicate key errors

                db.commit()
                return {"success": True, "message": "Logged out successfully"}
            return {"success": False, "message": "Session not found"}
        finally:
            db.close()

    def get_user_by_id(self, user_id: str) -> Optional[User]:
        """Look up a user by their user_id (not username)."""
        db = SessionLocal()
        try:
            db_user = db.query(UserModel).filter(UserModel.user_id == user_id).first()
            if db_user:
                return _user_from_model(db_user)
            return None
        finally:
            db.close()

    def get_active_sessions(self, user_id: str) -> List[Session]:
        """Get all active sessions for a user (for monitoring dashboard)."""
        db = SessionLocal()
        try:
            rows = db.query(SessionModel).filter(
                SessionModel.user_id == user_id,
                SessionModel.is_active == True  # noqa: E712
            ).all()
            return [
                Session(
                    session_id=r.session_id,
                    user_id=r.user_id,
                    access_token=r.access_token,
                    refresh_token=r.refresh_token,
                    created_at=r.created_at,
                    last_active=r.last_active,
                    ip_address=r.ip_address,
                    user_agent=r.user_agent,
                    is_active=r.is_active,
                )
                for r in rows
            ]
        finally:
            db.close()