# ============================================================
#  identity/token_manager.py — JWT Token Manager
# ============================================================
#
#  WHAT IS A JWT?
#  JWT = JSON Web Token. It's a compact, signed "passport"
#  the server gives you after login.
#
#  Structure: HEADER.PAYLOAD.SIGNATURE
#    Header:    Algorithm used (HS256)
#    Payload:   Claims (user_id, role, expiry, etc.)
#    Signature: HMAC hash — proves nobody tampered with the token
#
#  How it works:
#  1. User logs in → server creates JWT with their info
#  2. Server signs it with SECRET_KEY
#  3. User sends JWT in every request header
#  4. Server verifies signature — if valid, user is authenticated
#  5. Server NEVER stores the token — it's stateless!
#
#  WHY STATELESS?
#  No database lookup on every request. The token IS the proof.
#  Any server in the cluster can verify it independently.
#  This scales to millions of requests.
#
#  ACCESS vs REFRESH TOKENS:
#  Access token:  Short-lived (30 min). Used for API calls.
#  Refresh token: Long-lived (24 hrs). Used to get a new access token.
#  This limits damage if an access token is stolen.
# ============================================================

import jwt
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from dataclasses import dataclass
from config.settings import config


@dataclass
class TokenPayload:
    """
    The data we embed inside each JWT token.

    user_id:    Unique identifier of the user
    username:   Display name (for convenience)
    role:       Their permission level (user/admin/readonly)
    token_type: "access" or "refresh"
    session_id: Unique ID for this login session
    issued_at:  When was this token created
    expires_at: When does this token expire
    jti:        JWT ID — unique per token (prevents replay attacks)
    """
    user_id: str
    username: str
    role: str
    token_type: str
    session_id: str
    issued_at: datetime
    expires_at: datetime
    jti: str  # JWT unique ID


class TokenManager:
    """
    Creates, verifies, and decodes JWT tokens.

    SECURITY DESIGN:
    - Tokens are signed with HMAC-SHA256 (HS256)
    - Each token has a unique jti (prevents replay attacks)
    - Expiry is always enforced
    - Algorithm is explicitly specified (prevents "alg: none" attacks)
    """

    def __init__(self):
        self.secret_key = config.jwt.secret_key
        self.algorithm = config.jwt.algorithm
        self.access_expire = timedelta(minutes=config.jwt.access_token_expire_minutes)
        self.refresh_expire = timedelta(hours=config.jwt.refresh_token_expire_hours)

    def create_access_token(self, user_id: str, username: str, role: str, session_id: str) -> str:
        """
        Create a short-lived access token.

        This is what the client sends with every API request.
        Expires in 30 minutes — even if stolen, it becomes useless quickly.
        """
        return self._create_token(
            user_id=user_id,
            username=username,
            role=role,
            session_id=session_id,
            token_type="access",
            expires_delta=self.access_expire
        )

    def create_refresh_token(self, user_id: str, username: str, role: str, session_id: str) -> str:
        """
        Create a long-lived refresh token.

        Used ONLY to get a new access token when the current one expires.
        Should be stored securely (httpOnly cookie, secure storage).
        Never sent on regular API calls.
        """
        return self._create_token(
            user_id=user_id,
            username=username,
            role=role,
            session_id=session_id,
            token_type="refresh",
            expires_delta=self.refresh_expire
        )

    def _create_token(
        self,
        user_id: str,
        username: str,
        role: str,
        session_id: str,
        token_type: str,
        expires_delta: timedelta
    ) -> str:
        """
        Internal token creation method.

        The payload dict is what gets encoded into the JWT.
        We use standard JWT claim names:
          sub = subject (who the token is for)
          exp = expiration time
          iat = issued at
          jti = JWT ID (unique per token)
        """
        now = datetime.now(timezone.utc)
        expires_at = now + expires_delta

        payload = {
            "sub": user_id,                    # Subject — user identifier
            "username": username,
            "role": role,
            "token_type": token_type,
            "session_id": session_id,
            "iat": now,                        # Issued at
            "exp": expires_at,                 # Expiration
            "jti": str(uuid.uuid4())           # Unique token ID
        }

        # jwt.encode() signs the payload with our secret key
        # The result is a base64url-encoded string: header.payload.signature
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        return token

    def verify_token(self, token: str, expected_type: str = "access") -> Optional[TokenPayload]:
        """
        Verify a token and return its payload if valid.

        Returns None if:
        - Token is expired
        - Signature doesn't match (tampered token)
        - Token type doesn't match (access token used as refresh, etc.)
        - Token is malformed

        SECURITY NOTE: We explicitly pass algorithms=[] to prevent
        the "algorithm confusion" attack where an attacker changes
        the algorithm to "none" to bypass signature verification.
        """
        try:
            # Decode and verify in one step
            # jwt.decode() will raise exceptions if anything is wrong
            decoded = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm]  # Explicit — no "none" allowed
            )

            # Extra check: make sure token type matches what we expected
            if decoded.get("token_type") != expected_type:
                return None

            # Build and return a clean payload object
            return TokenPayload(
                user_id=decoded["sub"],
                username=decoded["username"],
                role=decoded["role"],
                token_type=decoded["token_type"],
                session_id=decoded["session_id"],
                issued_at=datetime.fromtimestamp(decoded["iat"], tz=timezone.utc),
                expires_at=datetime.fromtimestamp(decoded["exp"], tz=timezone.utc),
                jti=decoded["jti"]
            )

        except jwt.ExpiredSignatureError:
            # Token is valid but expired — user needs to refresh
            return None
        except jwt.InvalidTokenError:
            # Token is malformed, tampered, or wrong signature
            return None

    def decode_without_verify(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Decode token payload WITHOUT verifying signature.

        USE CAREFULLY — only for inspecting expired tokens
        to extract user info before rejecting them gracefully.
        NEVER use this for authorization decisions.
        """
        try:
            return jwt.decode(
                token,
                options={"verify_signature": False}
            )
        except Exception:
            return None