import hmac
from datetime import timedelta
from functools import wraps

from flask import flash, g, redirect, request, session, url_for

from db import get_user_by_id
from security import (
    AUTH_COOKIE_NAME,
    LOCKOUT_MINUTES,
    LOCKOUT_THRESHOLD,
    _format_dt,
    _parse_dt,
    _utc_now,
    decode_jwt,
    hash_password,
    verify_password,
)


def get_current_user():
    if hasattr(g, "current_user"):
        return g.current_user

    token = request.cookies.get(AUTH_COOKIE_NAME)
    if not token:
        g.current_user = None
        return None

    payload = decode_jwt(token)
    if not payload or "sub" not in payload:
        g.current_user = None
        return None

    user = get_user_by_id(payload["sub"])
    g.current_user = user
    return user


def is_admin(user):
    return (user["role"] or "user").lower() == "admin"


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = get_current_user()
        if not user:
            flash("Please login first.", "danger")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def role_required(*allowed_roles):
    normalized = {role.lower() for role in allowed_roles}

    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = get_current_user()
            if not user:
                flash("Please login first.", "danger")
                return redirect(url_for("login"))
            if (user["role"] or "user").lower() not in normalized:
                flash("You do not have permission to access that page.", "danger")
                return redirect(url_for("dashboard"))
            return view(*args, **kwargs)

        return wrapped

    return decorator


def clear_pending_auth_state():
    for key in (
        "pending_registration_user_id",
        "pending_registration_username",
        "pending_mfa_user_id",
        "pending_mfa_username",
        "pending_mfa_target",
        "mfa_attempts",
    ):
        session.pop(key, None)


def _password_matches_and_upgrade(conn, user, password):
    stored_password_hash = user["password_hash"]
    if stored_password_hash:
        return verify_password(password, stored_password_hash)

    legacy_password = user["password"]
    if legacy_password and hmac.compare_digest(password, legacy_password):
        upgraded_hash = hash_password(password)
        conn.execute(
            "UPDATE users SET password_hash = ?, password = ? WHERE id = ?",
            (upgraded_hash, upgraded_hash, user["id"]),
        )
        conn.commit()
        return True
    return False


def _clear_login_failures(conn, user_id):
    conn.execute(
        "UPDATE users SET failed_login_attempts = 0, lockout_until = NULL WHERE id = ?",
        (user_id,),
    )
    conn.commit()


def _mark_failed_login(conn, user):
    attempts = int(user["failed_login_attempts"] or 0) + 1
    lockout_until = None
    if attempts >= LOCKOUT_THRESHOLD:
        lockout_until = _format_dt(_utc_now() + timedelta(minutes=LOCKOUT_MINUTES))
        attempts = 0
    conn.execute(
        "UPDATE users SET failed_login_attempts = ?, lockout_until = ? WHERE id = ?",
        (attempts, lockout_until, user["id"]),
    )
    conn.commit()


def _unlock_if_expired(conn, user):
    lockout_until = _parse_dt(user["lockout_until"])
    if not lockout_until:
        return False
    if lockout_until > _utc_now():
        remaining = int((lockout_until - _utc_now()).total_seconds() // 60) + 1
        flash(
            f"Account is locked. Try again in about {remaining} minute(s).",
            "danger",
        )
        return True

    _clear_login_failures(conn, user["id"])
    return False
