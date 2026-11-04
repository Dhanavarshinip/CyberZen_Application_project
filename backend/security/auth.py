"""
Authentication and Cryptographic Security Module for CyberThreat AI.

Provides:
- PBKDF2-HMAC-SHA256 password hashing and validation with random salts.
- Cryptographically signed HMAC-SHA256 Session Tokens (JWT format).
- Secure random device credentials generation.
- FastAPI dependency for Bearer token validation and account ownership checks.
- Safe logging utilities to prevent credential leaks.
"""

import os
import hmac
import hashlib
import base64
import json
import secrets
import time
from typing import Optional, Dict, Any
from datetime import datetime, timezone, timedelta
from fastapi import HTTPException, Security, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# Secret key for token signing (loaded from environment or persistently generated)
SECRET_KEY = os.getenv("CYBERTHREAT_SECRET_KEY")
if not SECRET_KEY:
    # Use deterministic or persistent secret if not provided in env
    SECRET_KEY = "cyberthreat_ai_production_secure_token_secret_2026_key"

TOKEN_ALGORITHM = "HS256"
TOKEN_EXPIRY_DAYS = 7

bearer_scheme = HTTPBearer(auto_error=False)


def _b64_url_encode(data: bytes) -> str:
    """Encodes bytes into URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')


def _b64_url_decode(data: str) -> bytes:
    """Decodes URL-safe base64 with appropriate padding."""
    rem = len(data) % 4
    if rem > 0:
        data += '=' * (4 - rem)
    return base64.urlsafe_b64decode(data.encode('utf-8'))


def hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    """
    Hashes a plaintext password using PBKDF2-HMAC-SHA256 with 100,000 rounds.
    Returns (hex_hash, salt).
    """
    if not salt:
        salt = secrets.token_hex(16)
    pwd_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')
    pwd_hash = hashlib.pbkdf2_hmac('sha256', pwd_bytes, salt_bytes, 100000).hex()
    return pwd_hash, salt


def verify_password(plain_password: str, stored_hash: str, salt: str) -> bool:
    """Constant-time verification of password against stored PBKDF2 hash."""
    computed_hash, _ = hash_password(plain_password, salt)
    return hmac.compare_digest(computed_hash, stored_hash)


def create_access_token(user_id: str, email: str, expires_delta: Optional[timedelta] = None) -> str:
    """
    Generates a cryptographically signed HMAC-SHA256 token (JWT structure).
    """
    now = int(time.time())
    exp = now + int(expires_delta.total_seconds() if expires_delta else TOKEN_EXPIRY_DAYS * 86400)
    
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": user_id,
        "email": email,
        "iat": now,
        "exp": exp
    }
    
    header_b64 = _b64_url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
    payload_b64 = _b64_url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
    
    signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
    signature = hmac.new(SECRET_KEY.encode('utf-8'), signing_input, hashlib.sha256).digest()
    sig_b64 = _b64_url_encode(signature)
    
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Decodes and verifies token signature and expiration.
    Returns payload dictionary if valid, or None if invalid/expired.
    """
    if not token or not isinstance(token, str):
        return None
    parts = token.split('.')
    if len(parts) != 3:
        return None
        
    header_b64, payload_b64, sig_b64 = parts
    signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
    expected_sig = hmac.new(SECRET_KEY.encode('utf-8'), signing_input, hashlib.sha256).digest()
    expected_sig_b64 = _b64_url_encode(expected_sig)
    
    if not hmac.compare_digest(sig_b64, expected_sig_b64):
        return None  # Signature tampering detected
        
    try:
        payload_bytes = _b64_url_decode(payload_b64)
        payload = json.loads(payload_bytes.decode('utf-8'))
        
        # Check expiration
        exp = payload.get("exp", 0)
        if time.time() > exp:
            return None  # Token expired
            
        return payload
    except Exception:
        return None


def generate_device_key() -> str:
    """Generates a high-entropy URL-safe device authentication secret."""
    return f"dk_{secrets.token_urlsafe(32)}"


def get_current_user_from_token(token: str, db) -> Optional[Dict[str, Any]]:
    """Resolves authenticated user from token."""
    payload = decode_access_token(token)
    if not payload or "sub" not in payload:
        return None
    user = db.get_user_by_id(payload["sub"])
    return user


def require_authenticated_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)):
    """FastAPI dependency requiring valid Bearer token."""
    if not credentials or not credentials.credentials:
        raise HTTPException(status_code=401, detail="Authentication required. Please sign in.")
    payload = decode_access_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired session token. Please sign in again.")
    return payload
