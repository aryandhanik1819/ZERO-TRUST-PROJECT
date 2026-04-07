# ============================================================
#  identity/auth_service.py — Authentication Service
# ============================================================
#
#  WHAT IS AUTHENTICATION?
#  Authentication = "Prove who you are."
#  (Authorization = "What are you allowed to do?" — that's the policy engine)
#
#  This module handles:
#  - Storing users (in-memory for this project, DB in production)
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
# ============================================================

import bcrypt
import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, List
from dataclasses import dataclass, field
from identity.token_manager import TokenManager, TokenPayload
from config.settings import config


# ── User Model ────────────────────────────────────────────────

@dataclass
class User:
    """
    Represents a user account in the system.

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
    Represents one active login session.

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


# ── Authentication Service ────────────────────────────────────

class AuthService:
    """
    The central authentication authority.

    In a real system, users would be stored in a database (PostgreSQL,
    MongoDB, etc.) and sessions in Redis for fast lookup and expiry.

    For this project, we use in-memory dicts so you can run and
    understand it without setting up a database.

    FLOW:
    register() → create user with hashed password
    login()    → verify password → create session → return tokens
    verify()   → check access token → return user identity
    logout()   → invalidate session
    refresh()  → exchange refresh token for new access token
    """

    def __init__(self):
        self.token_manager = TokenManager()

        # In-memory "database" — replace with real DB in production
        self._users: Dict[str, User] = {}          # username → User
        self._sessions: Dict[str, Session] = {}    # session_id → Session

        # Seed with demo users so you can test immediately
        self._seed_demo_users()

    def _seed_demo_users(self):
        """
        Creates default demo users for testing.
        In production, users would register via signup or LDAP/SSO.
        """
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
        # Check username isn't already taken
        if username in self._users:
            return {"success": False, "message": f"Username '{username}' already exists"}

        user = User(
            user_id=str(uuid.uuid4()),
            username=username,
            email=email,
            hashed_password=self._hash_password(password),
            role=role,
            mfa_enabled=mfa_enabled
        )
        self._users[username] = user
        return {"success": True, "message": f"User '{username}' registered successfully", "user_id": user.user_id}

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
        # Step 1: Find the user
        user = self._users.get(username)
        if not user:
            return LoginResult(success=False, message="Invalid username or password")
            # NOTE: We give the same error for "user not found" and "wrong password"
            # This prevents "username enumeration" — attackers can't tell which is wrong

        # Step 2: Account must be active
        if not user.is_active:
            return LoginResult(success=False, message="Account is disabled. Contact administrator.")

        # Step 3: Account lockout after too many failures
        if user.failed_attempts >= 5:
            return LoginResult(success=False, message="Account temporarily locked due to failed login attempts.")

        # Step 4: Password verification
        if not self._verify_password(password, user.hashed_password):
            user.failed_attempts += 1
            return LoginResult(
                success=False,
                message=f"Invalid username or password. Attempt {user.failed_attempts}/5"
            )

        # Step 5: Successful login — reset failure counter
        user.failed_attempts = 0
        user.last_login = datetime.now(timezone.utc).isoformat()

        # Step 6: Create session
        session_id = str(uuid.uuid4())

        access_token = self.token_manager.create_access_token(
            user_id=user.user_id,
            username=user.username,
            role=user.role,
            session_id=session_id
        )
        refresh_token = self.token_manager.create_refresh_token(
            user_id=user.user_id,
            username=user.username,
            role=user.role,
            session_id=session_id
        )

        session = Session(
            session_id=session_id,
            user_id=user.user_id,
            access_token=access_token,
            refresh_token=refresh_token,
            ip_address=ip_address,
            user_agent=user_agent
        )
        self._sessions[session_id] = session

        # Step 7: Return result
        return LoginResult(
            success=True,
            message="Login successful",
            access_token=access_token,
            refresh_token=refresh_token,
            session_id=session_id,
            user_info={
                "user_id": user.user_id,
                "username": user.username,
                "email": user.email,
                "role": user.role,
                "mfa_enabled": user.mfa_enabled
            }
        )

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

        # Also check the session is still active
        session = self._sessions.get(payload.session_id)
        if not session or not session.is_active:
            return None

        # Update last active time
        session.last_active = datetime.now(timezone.utc).isoformat()
        return payload

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

        # Check the session is still valid
        session = self._sessions.get(payload.session_id)
        if not session or not session.is_active:
            return LoginResult(success=False, message="Session has been invalidated")

        # Issue a new access token with the same session
        new_access_token = self.token_manager.create_access_token(
            user_id=payload.user_id,
            username=payload.username,
            role=payload.role,
            session_id=payload.session_id
        )
        session.access_token = new_access_token

        return LoginResult(
            success=True,
            message="Token refreshed successfully",
            access_token=new_access_token,
            refresh_token=refresh_token,  # Return the same refresh token
            session_id=payload.session_id
        )

    def logout(self, session_id: str) -> dict:
        """
        Invalidate a specific session (logout from this device).
        """
        session = self._sessions.get(session_id)
        if session:
            session.is_active = False
            return {"success": True, "message": "Logged out successfully"}
        return {"success": False, "message": "Session not found"}

    def get_user_by_id(self, user_id: str) -> Optional[User]:
        """Look up a user by their user_id (not username)."""
        for user in self._users.values():
            if user.user_id == user_id:
                return user
        return None

    def get_active_sessions(self, user_id: str) -> List[Session]:
        """Get all active sessions for a user (for monitoring dashboard)."""
        return [s for s in self._sessions.values() if s.user_id == user_id and s.is_active]