import base64
import hashlib
import hmac
import json
import os
import re
import secrets
from datetime import datetime, timedelta, timezone

try:
    import bcrypt
except ImportError:  # pragma: no cover - optional dependency
    bcrypt = None

from flask import abort, current_app, request, session


AUTH_COOKIE_NAME = "alstan_auth"
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", os.environ.get("FLASK_SECRET_KEY", "alstandesign_secure_key_2026"))
JWT_TTL_SECONDS = int(os.environ.get("JWT_TTL_SECONDS", str(60 * 60 * 8)))
LOCKOUT_THRESHOLD = 5
LOCKOUT_MINUTES = 15
OTP_MAX_ATTEMPTS = 5
PASSWORD_MIN_LENGTH = 8

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9 .,'\-]{2,80}$")


def _utc_now():
    return datetime.now(timezone.utc)


def _format_dt(dt):
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).isoformat()


def _parse_dt(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def _b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value):
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def create_jwt(payload):
    header = {"alg": "HS256", "typ": "JWT"}
    header_bytes = json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    header_part = _b64url_encode(header_bytes)
    payload_part = _b64url_encode(payload_bytes)
    signing_input = f"{header_part}.{payload_part}".encode("ascii")
    signature = hmac.new(JWT_SECRET_KEY.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{header_part}.{payload_part}.{_b64url_encode(signature)}"


def decode_jwt(token):
    try:
        header_part, payload_part, signature_part = token.split(".")
        signing_input = f"{header_part}.{payload_part}".encode("ascii")
        expected_signature = hmac.new(
            JWT_SECRET_KEY.encode("utf-8"),
            signing_input,
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(_b64url_decode(signature_part), expected_signature):
            return None

        header = json.loads(_b64url_decode(header_part))
        if header.get("alg") != "HS256":
            return None

        payload = json.loads(_b64url_decode(payload_part))
        exp = payload.get("exp")
        if exp is not None and int(exp) < int(_utc_now().timestamp()):
            return None
        return payload
    except Exception:
        return None


def hash_password(password):
    password_bytes = password.encode("utf-8")
    if bcrypt is not None:
        return "bcrypt$" + bcrypt.hashpw(password_bytes, bcrypt.gensalt(rounds=12)).decode("utf-8")

    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password_bytes, salt, 210_000)
    return "pbkdf2_sha256${}${}".format(
        _b64url_encode(salt),
        _b64url_encode(digest),
    )


def verify_password(password, stored_hash):
    if not stored_hash:
        return False

    password_bytes = password.encode("utf-8")
    if stored_hash.startswith("bcrypt$"):
        if bcrypt is None:
            return False
        return bcrypt.checkpw(password_bytes, stored_hash.split("$", 1)[1].encode("utf-8"))

    if stored_hash.startswith("pbkdf2_sha256$"):
        try:
            _, salt_part, digest_part = stored_hash.split("$", 2)
            salt = _b64url_decode(salt_part)
            expected = _b64url_decode(digest_part)
            actual = hashlib.pbkdf2_hmac("sha256", password_bytes, salt, 210_000)
            return hmac.compare_digest(actual, expected)
        except Exception:
            return False

    return hmac.compare_digest(password, stored_hash)


def normalize_email(value):
    return (value or "").strip().lower()


def normalize_username(value):
    return " ".join((value or "").strip().split())


def validate_email(email):
    return bool(email and len(email) <= 254 and EMAIL_RE.fullmatch(email))


def validate_username(username):
    return bool(username and USERNAME_RE.fullmatch(username))


def validate_password_strength(password):
    if not password or len(password) < PASSWORD_MIN_LENGTH:
        return False, f"Password must be at least {PASSWORD_MIN_LENGTH} characters long."
    checks = [
        (re.search(r"[A-Z]", password), "an uppercase letter"),
        (re.search(r"[a-z]", password), "a lowercase letter"),
        (re.search(r"\d", password), "a number"),
        (re.search(r"[^A-Za-z0-9]", password), "a special character"),
    ]
    missing = [label for passed, label in checks if not passed]
    if missing:
        return False, "Password must include " + ", ".join(missing) + "."
    return True, ""


def sanitize_message(message):
    cleaned = (message or "").strip()
    cleaned = cleaned.replace("\x00", "")
    return cleaned


def generate_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def validate_csrf_token():
    session_token = session.get("_csrf_token")
    form_token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    if not session_token or not form_token or not hmac.compare_digest(session_token, form_token):
        abort(400)


def issue_auth_cookie(response, user):
    now = _utc_now()
    payload = {
        "sub": user["id"],
        "username": user["username"],
        "role": (user["role"] or "user").lower(),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=JWT_TTL_SECONDS)).timestamp()),
        "jti": secrets.token_hex(16),
    }
    response.set_cookie(
        AUTH_COOKIE_NAME,
        create_jwt(payload),
        httponly=True,
        secure=current_app.config["SESSION_COOKIE_SECURE"],
        samesite="Lax",
        max_age=JWT_TTL_SECONDS,
        path="/",
    )


def clear_auth_cookie(response):
    response.delete_cookie(AUTH_COOKIE_NAME, path="/")


def add_security_headers(response):
    csp = (
        "default-src 'self'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "object-src 'none'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
        "img-src 'self' data: https:; "
        "font-src 'self' https://fonts.gstatic.com; "
        "connect-src 'self'; "
        "frame-src https://www.google.com https://maps.google.com"
    )
    response.headers["Content-Security-Policy"] = csp
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if response.mimetype == "text/html":
        response.headers["Cache-Control"] = "no-store, max-age=0"
    return response
