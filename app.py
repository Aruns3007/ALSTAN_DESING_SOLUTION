import base64
import csv
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps

import pyotp
import qrcode
from flask import (
    Flask,
    abort,
    flash,
    g,
    make_response,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)

try:
    import bcrypt
except ImportError:  # pragma: no cover - optional dependency
    bcrypt = None


app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "alstandesign_secure_key_2026")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_COOKIE_SECURE", "0") == "1",
    PREFERRED_URL_SCHEME="https",
)

AUTH_COOKIE_NAME = "alstan_auth"
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", app.secret_key)
JWT_TTL_SECONDS = int(os.environ.get("JWT_TTL_SECONDS", str(60 * 60 * 8)))
LOCKOUT_THRESHOLD = 5
LOCKOUT_MINUTES = 15
OTP_MAX_ATTEMPTS = 5
PASSWORD_MIN_LENGTH = 8

DB_PATH = os.path.join(os.path.dirname(__file__), "alstandesign.db")
VIDEOS_DIR = os.path.join(os.path.dirname(__file__), "videos")
IMAGES_DIR = os.path.join(os.path.dirname(__file__), "images")
VIDEO_ASSETS = {
    "semiconductors": {
        "filename": "WhatsApp Video 2026-04-04 at 1.41.49 PM.mp4",
        "title": "Semiconductors & VLSI",
        "description": "RTL design, verification, and timing-aware implementation for low-power silicon workflows.",
        "badge": "IC Design",
        "summary": "A focused look at chip design, verification, and silicon-ready implementation.",
        "hero_image": "20260413_1202_image.png",
        "gallery": [
            "20260413_1202_image (1).png",
            "20260413_1202_image (2).png",
        ],
        "highlights": [
            "RTL and block-level design flow",
            "Verification and timing awareness",
            "Low-power implementation mindset",
        ],
    },
    "ai": {
        "filename": "WhatsApp Video 2026-04-08 at 12.07.42 PM.mp4",
        "title": "AI & Neural Networks",
        "description": "Inference pipelines and model-driven control tuned for real-world automation.",
        "badge": "AI Core",
        "summary": "How model-driven logic can be applied to practical decision systems.",
        "hero_image": "Gemini_Generated_Image_i4si37i4si37i4si.png",
        "gallery": [
            "Gemini_Generated_Image_f69xbdf69xbdf69x.png",
            "Gemini_Generated_Image_tk81lqtk81lqtk81.png",
        ],
        "highlights": [
            "Inference pipeline thinking",
            "Automation-assisted decision support",
            "Real-world deployment focus",
        ],
    },
    "cloud": {
        "filename": "Next-Gen Cloud Infrastructure Demo_720p_caption.mp4",
        "title": "Cloud & DevOps",
        "description": "Resilient multi-region delivery with CI/CD, observability, and rollback planning.",
        "badge": "Cloud Systems",
        "summary": "A practical view of delivery pipelines, monitoring, and resilience.",
        "hero_image": "Gemini_Generated_Image_bhqe6bbhqe6bbhqe.png",
        "gallery": [
            "Gemini_Generated_Image_heu8ztheu8ztheu8.png",
        ],
        "highlights": [
            "CI/CD and release control",
            "Monitoring and observability",
            "Multi-region resilience planning",
        ],
    },
    "process": {
        "filename": "Cyan Precision Automation_720p_caption.mp4",
        "title": "Process Automation",
        "description": "Sensor-to-actuator control and production orchestration for stable operations.",
        "badge": "Automation",
        "summary": "A concise look at control loops and automation for production systems.",
        "hero_image": "Gemini_Generated_Image_egpoacegpoacegpo.png",
        "gallery": [
            "Gemini_Generated_Image_lsy778lsy778lsy7.png",
        ],
        "highlights": [
            "Sensor-to-actuator control",
            "Process monitoring and tuning",
            "Stable production operations",
        ],
    },
}
ALLOWED_VIDEO_FILENAMES = {asset["filename"] for asset in VIDEO_ASSETS.values()}
ALLOWED_IMAGE_FILENAMES = {
    asset["hero_image"]
    for asset in VIDEO_ASSETS.values()
} | {
    image
    for asset in VIDEO_ASSETS.values()
    for image in asset["gallery"]
}

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9 .,'\-]{2,80}$")


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _table_columns(conn, table_name):
    return {row["name"] for row in conn.execute(f"PRAGMA table_info({table_name})")}


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


def get_user_by_id(user_id):
    conn = get_db_connection()
    user = conn.execute(
        """
        SELECT id, username, email, password, password_hash, otp_secret,
               is_verified, role, failed_login_attempts, lockout_until
        FROM users
        WHERE id = ?
        """,
        (user_id,),
    ).fetchone()
    conn.close()
    return user


def get_user_by_email(email):
    conn = get_db_connection()
    user = conn.execute(
        """
        SELECT id, username, email, password, password_hash, otp_secret,
               is_verified, role, failed_login_attempts, lockout_until
        FROM users
        WHERE email = ?
        """,
        (email,),
    ).fetchone()
    conn.close()
    return user


def get_user_by_username(username):
    conn = get_db_connection()
    user = conn.execute(
        """
        SELECT id, username, email, password, password_hash, otp_secret,
               is_verified, role, failed_login_attempts, lockout_until
        FROM users
        WHERE username = ?
        """,
        (username,),
    ).fetchone()
    conn.close()
    return user


def is_admin(user):
    return (user["role"] or "user").lower() == "admin"


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
        secure=app.config["SESSION_COOKIE_SECURE"],
        samesite="Lax",
        max_age=JWT_TTL_SECONDS,
        path="/",
    )


def clear_auth_cookie(response):
    response.delete_cookie(AUTH_COOKIE_NAME, path="/")


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


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = get_current_user()
        if not user:
            flash("Please login first.", "danger")
            return redirect(url_for("admin_login"))
        if not is_admin(user) or not session.get("admin_authenticated"):
            flash("Please use the admin login page to continue.", "danger")
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)

    return wrapped


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


def _start_pending_mfa(user, target):
    session["pending_mfa_user_id"] = user["id"]
    session["pending_mfa_username"] = user["username"]
    session["pending_mfa_target"] = target
    session["mfa_attempts"] = 0


def ensure_columns_and_defaults():
    conn = get_db_connection()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                otp_secret TEXT,
                is_verified INTEGER DEFAULT 0
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS inquiries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                message TEXT NOT NULL,
                status TEXT DEFAULT 'PENDING'
            )
            """
        )

        user_columns = _table_columns(conn, "users")
        if "password_hash" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
        if "role" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
        if "failed_login_attempts" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0")
        if "lockout_until" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN lockout_until TEXT")
        if "otp_secret" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN otp_secret TEXT")
        if "is_verified" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN is_verified INTEGER DEFAULT 0")

        conn.execute(
            "UPDATE users SET role = 'user' WHERE LOWER(email) = 'light14@gmail.com' AND LOWER(COALESCE(role, 'user')) = 'admin'"
        )

        conn.commit()
    finally:
        conn.close()


def _admin_account_exists():
    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT 1 FROM users WHERE LOWER(COALESCE(role, 'user')) = 'admin' LIMIT 1"
        ).fetchone()
        return row is not None
    finally:
        conn.close()


ensure_columns_and_defaults()


@app.before_request
def load_current_user():
    g.current_user = None
    token = request.cookies.get(AUTH_COOKIE_NAME)
    if token:
        payload = decode_jwt(token)
        if payload and payload.get("sub") is not None:
            g.current_user = get_user_by_id(payload["sub"])

    if request.method == "POST":
        validate_csrf_token()


@app.context_processor
def inject_security_helpers():
    return {
        "current_user": get_current_user(),
        "csrf_token": generate_csrf_token,
        "admin_authenticated": session.get("admin_authenticated", False),
    }


@app.after_request
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


def _build_video_assets():
    return {
        key: {
            **asset,
            "url": url_for("serve_video", filename=asset["filename"]),
            "hero_image": url_for("serve_image", filename=asset["hero_image"]),
            "gallery": [url_for("serve_image", filename=image) for image in asset["gallery"]],
        }
        for key, asset in VIDEO_ASSETS.items()
    }


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


def _create_user_account(conn, username, email, password, role):
    existing_user = conn.execute(
        "SELECT id FROM users WHERE email = ?",
        (email,),
    ).fetchone()
    if existing_user:
        return None

    otp_secret = pyotp.random_base32()
    password_hash = hash_password(password)

    conn.execute(
        """
        INSERT INTO users (username, email, password, password_hash, otp_secret, role, is_verified)
        VALUES (?, ?, ?, ?, ?, ?, 0)
        """,
        (username, email, password_hash, password_hash, otp_secret, role),
    )
    conn.commit()
    return conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]


def _promote_user_to_admin(conn, user_id):
    return conn.execute(
        "UPDATE users SET role = 'admin' WHERE id = ? AND LOWER(COALESCE(role, 'user')) <> 'admin'",
        (user_id,),
    ).rowcount


def _handle_admin_signup():
    username = normalize_username(request.form.get("username"))
    email = normalize_email(request.form.get("email"))
    password = request.form.get("password") or ""

    if not validate_username(username):
        flash("Please enter a valid full name.", "danger")
        return render_template("admin_login.html", admin_exists=False)
    if not validate_email(email):
        flash("Please enter a valid email address.", "danger")
        return render_template("admin_login.html", admin_exists=False)

    password_ok, password_message = validate_password_strength(password)
    if not password_ok:
        flash(password_message, "danger")
        return render_template("admin_login.html", admin_exists=False)

    conn = get_db_connection()
    try:
        user_id = _create_user_account(conn, username, email, password, "admin")
        if user_id is None:
            flash("Email already registered. Please choose another email.", "danger")
            return render_template("admin_login.html", admin_exists=False)

        session["pending_registration_user_id"] = user_id
        session["pending_registration_username"] = username
        flash("Admin account created. Complete 2FA setup to finish.", "success")
        return redirect(url_for("setup_2fa"))
    finally:
        conn.close()


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


@app.route("/")
def index():
    current_user = get_current_user()
    card_videos = _build_video_assets()
    return render_template(
        "index.html",
        name=current_user["username"] if current_user else session.get("user"),
        current_user=current_user,
        card_videos=card_videos,
    )


@app.route("/videos/<path:filename>")
def serve_video(filename):
    if filename not in ALLOWED_VIDEO_FILENAMES:
        abort(404)
    return send_from_directory(VIDEOS_DIR, filename)


@app.route("/images/<path:filename>")
def serve_image(filename):
    if filename not in ALLOWED_IMAGE_FILENAMES:
        abort(404)
    return send_from_directory(IMAGES_DIR, filename)


@app.route("/portfolio/<slug>")
def portfolio_detail(slug):
    asset = _build_video_assets().get(slug)
    if not asset:
        abort(404)

    video_asset = {
        **asset,
    }
    return render_template(
        "portfolio_detail.html",
        asset=asset,
        video_asset=video_asset,
        portfolio_slug=slug,
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = normalize_username(request.form.get("username"))
        email = normalize_email(request.form.get("email"))
        password = request.form.get("password") or ""

        if not validate_username(username):
            flash("Please enter a valid full name.", "danger")
            return render_template("register.html")
        if not validate_email(email):
            flash("Please enter a valid email address.", "danger")
            return render_template("register.html")

        password_ok, password_message = validate_password_strength(password)
        if not password_ok:
            flash(password_message, "danger")
            return render_template("register.html")

        conn = get_db_connection()
        try:
            user_id = _create_user_account(conn, username, email, password, "user")
            if user_id is None:
                flash("Email already registered. Please login.", "danger")
                return redirect(url_for("login"))

            session["pending_registration_user_id"] = user_id
            session["pending_registration_username"] = username
            return redirect(url_for("setup_2fa"))
        except sqlite3.IntegrityError:
            flash("Email already registered. Please login.", "danger")
            return redirect(url_for("login"))
        finally:
            conn.close()

    return render_template("register.html")


@app.route("/setup_2fa", defaults={"username": None})
@app.route("/setup_2fa/<username>")
def setup_2fa(username):
    user_id = session.get("pending_registration_user_id")
    user = get_user_by_id(user_id) if user_id else None

    if not user:
        flash("Please complete registration first.", "warning")
        return redirect(url_for("register"))

    if not user["otp_secret"]:
        conn = get_db_connection()
        otp_secret = pyotp.random_base32()
        conn.execute(
            "UPDATE users SET otp_secret = ?, is_verified = 0 WHERE id = ?",
            (otp_secret, user["id"]),
        )
        conn.commit()
        conn.close()
        user = get_user_by_id(user["id"])

    if user["is_verified"] == 1:
        flash("Account already verified.", "info")
        return redirect(url_for("login"))

    totp = pyotp.TOTP(user["otp_secret"])
    provisioning_url = totp.provisioning_uri(name=user["username"], issuer_name="AlstanDesign")

    img = qrcode.make(provisioning_url)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    session["pending_registration_user_id"] = user["id"]
    session["pending_registration_username"] = user["username"]

    return render_template(
        "verify.html",
        qr_code=qr_b64,
        username=user["username"],
        setup_key=user["otp_secret"],
        issuer_name="AlstanDesign",
        provisioning_url=provisioning_url,
    )


@app.route("/verify", methods=["POST"])
@app.route("/verify/<username>", methods=["POST"])
def verify_otp(username=None):
    user_id = session.get("pending_registration_user_id")
    user = get_user_by_id(user_id) if user_id else None

    if not user:
        flash("Please complete registration first.", "warning")
        return redirect(url_for("register"))

    if not user["otp_secret"]:
        flash("2FA is not configured yet. Please restart registration.", "warning")
        return redirect(url_for("register"))

    user_code = (request.form.get("otp") or "").strip().replace(" ", "")
    totp = pyotp.TOTP(user["otp_secret"])
    if totp.verify(user_code, valid_window=1):
        conn = get_db_connection()
        conn.execute("UPDATE users SET is_verified = 1 WHERE id = ?", (user["id"],))
        conn.commit()
        conn.close()

        clear_pending_auth_state()
        flash("Account verified. You can now log in.", "success")
        return render_template("welcome.html", message="Synchronization Complete!")

    flash("Invalid verification code. Please try again.", "danger")
    return redirect(url_for("setup_2fa"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = normalize_email(request.form.get("email"))
        password = request.form.get("password") or ""

        if not validate_email(email):
            flash("Please enter a valid email address.", "danger")
            return render_template("login.html")

        conn = get_db_connection()
        try:
            user = conn.execute(
                """
                SELECT id, username, email, password, password_hash, otp_secret,
                       is_verified, role, failed_login_attempts, lockout_until
                FROM users
                WHERE email = ?
                """,
                (email,),
            ).fetchone()

            if not user:
                flash("Invalid email or password.", "danger")
                return render_template("login.html")

            if _unlock_if_expired(conn, user):
                return render_template("login.html")

            if not _password_matches_and_upgrade(conn, user, password):
                _mark_failed_login(conn, user)
                fresh_user = get_user_by_id(user["id"])
                if fresh_user and _parse_dt(fresh_user["lockout_until"]):
                    flash("Too many failed attempts. Account temporarily locked.", "danger")
                else:
                    flash("Invalid email or password.", "danger")
                return render_template("login.html")

            _clear_login_failures(conn, user["id"])

            if user["is_verified"] == 0:
                session["pending_registration_user_id"] = user["id"]
                session["pending_registration_username"] = user["username"]
                return redirect(url_for("setup_2fa"))

            if not user["otp_secret"]:
                otp_secret = pyotp.random_base32()
                conn.execute(
                    "UPDATE users SET otp_secret = ?, is_verified = 0 WHERE id = ?",
                    (otp_secret, user["id"]),
                )
                conn.commit()
                session["pending_registration_user_id"] = user["id"]
                session["pending_registration_username"] = user["username"]
                flash("2FA is not configured yet. Please scan the new QR code.", "info")
                return redirect(url_for("setup_2fa"))

            session.pop("admin_authenticated", None)
            _start_pending_mfa(user, "dashboard")
            return redirect(url_for("login_otp"))
        finally:
            conn.close()

    return render_template("login.html")


@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = normalize_email(request.form.get("email"))
        if not validate_email(email):
            flash("Please enter a valid email address.", "danger")
            return render_template("forgot_password.html")

        user = get_user_by_email(email)
        # Only allow reset for verified users with MFA configured
        if user and user["otp_secret"] and user["is_verified"] == 1:
            _start_pending_mfa(user, "reset_password")
            flash("Identity verification required. Please enter your 2FA code.", "info")
            return redirect(url_for("login_otp"))

        # Generic message to prevent account enumeration
        flash("If an account exists with that email, a reset process has started via MFA.", "info")
        return redirect(url_for("login"))

    return render_template("forgot_password.html")


@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    user_id = session.get("reset_password_user_id")
    if not user_id:
        flash("Unauthorized access. Please use the forgot password form.", "danger")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form.get("password") or ""
        ok, msg = validate_password_strength(password)
        if not ok:
            flash(msg, "danger")
            return render_template("reset_password.html")

        conn = get_db_connection()
        try:
            hashed = hash_password(password)
            conn.execute("UPDATE users SET password_hash = ?, password = ? WHERE id = ?", (hashed, hashed, user_id))
            conn.commit()
            session.pop("reset_password_user_id", None)
            flash("Password updated successfully. Please log in.", "success")
            return redirect(url_for("login"))
        finally:
            conn.close()

    return render_template("reset_password.html")


@app.route("/admin_login", methods=["GET", "POST"])
def admin_login():
    admin_exists = _admin_account_exists()

    current_user = get_current_user()
    if request.method == "GET" and current_user and is_admin(current_user) and session.get("admin_authenticated"):
        return redirect(url_for("admin_panel"))

    if request.method == "POST":
        if not admin_exists:
            return _handle_admin_signup()

        email = normalize_email(request.form.get("email"))
        password = request.form.get("password") or ""

        if not validate_email(email):
            flash("Please enter a valid email address.", "danger")
            return render_template("admin_login.html", admin_exists=True)

        conn = get_db_connection()
        try:
            user = conn.execute(
                """
                SELECT id, username, email, password, password_hash, otp_secret,
                       is_verified, role, failed_login_attempts, lockout_until
                FROM users
                WHERE email = ?
                """,
                (email,),
            ).fetchone()

            if not user or not is_admin(user):
                flash("Admin access denied.", "danger")
                return render_template("admin_login.html", admin_exists=True)

            if _unlock_if_expired(conn, user):
                return render_template("admin_login.html", admin_exists=True)

            if not _password_matches_and_upgrade(conn, user, password):
                _mark_failed_login(conn, user)
                flash("Invalid admin credentials.", "danger")
                return render_template("admin_login.html", admin_exists=True)

            _clear_login_failures(conn, user["id"])

            if user["is_verified"] == 0 or not user["otp_secret"]:
                flash("Admin account requires 2FA setup before access.", "warning")
                return render_template("admin_login.html", admin_exists=True)

            _start_pending_mfa(user, "admin_panel")
            return redirect(url_for("login_otp"))
        finally:
            conn.close()

    return render_template("admin_login.html", admin_exists=admin_exists)


@app.route("/setup_admin", methods=["GET", "POST"])
def setup_admin():
    admin_exists = _admin_account_exists()
    if request.method == "POST":
        return _handle_admin_signup()

    return render_template("setup_admin.html", admin_exists=admin_exists)


@app.route("/login_otp")
def login_otp():
    if not session.get("pending_mfa_user_id"):
        flash("Please login first.", "warning")
        return redirect(url_for("login"))
    return render_template("login_otp.html", username=session.get("pending_mfa_username"))


@app.route("/login_verify", methods=["POST"])
def login_verify():
    user_id = session.get("pending_mfa_user_id")
    if not user_id:
        flash("Authentication failed. Please restart login.", "danger")
        return redirect(url_for("login"))

    user = get_user_by_id(user_id)
    if not user:
        clear_pending_auth_state()
        flash("Authentication failed. Please restart login.", "danger")
        return redirect(url_for("login"))

    attempts = int(session.get("mfa_attempts", 0))
    if attempts >= OTP_MAX_ATTEMPTS:
        clear_pending_auth_state()
        flash("Too many failed OTP attempts. Please log in again.", "danger")
        return redirect(url_for("login"))

    user_code = (request.form.get("otp") or "").strip().replace(" ", "")
    totp = pyotp.TOTP(user["otp_secret"])
    if totp.verify(user_code, valid_window=1):
        target = session.get("pending_mfa_target") or "dashboard"
        uid = user["id"]
        clear_pending_auth_state()

        if target == "reset_password":
            session["reset_password_user_id"] = uid
            return redirect(url_for("reset_password"))

        session["user"] = user["username"]

        if target == "admin_panel" and not is_admin(user):
            flash("Admin access denied.", "danger")
            return redirect(url_for("dashboard"))

        if target == "admin_panel":
            session["admin_authenticated"] = True
        else:
            session.pop("admin_authenticated", None)

        response = redirect(url_for(target))
        issue_auth_cookie(response, user)
        return response

    session["mfa_attempts"] = attempts + 1
    if session["mfa_attempts"] >= OTP_MAX_ATTEMPTS:
        clear_pending_auth_state()
        flash("Too many failed OTP attempts. Please log in again.", "danger")
        return redirect(url_for("login"))

    flash("Authentication failed. Please try again.", "danger")
    return redirect(url_for("login_otp"))


@app.route("/dashboard")
@login_required
def dashboard():
    current_user = get_current_user()
    return render_template(
        "dashboard.html",
        current_user=current_user,
        name=current_user["username"],
    )


@app.route("/submit", methods=["POST"])
def submit_inquiry():
    email = normalize_email(request.form.get("email"))
    message = sanitize_message(request.form.get("message"))

    if not validate_email(email) or not message:
        flash("All fields are required.", "warning")
        return redirect(url_for("index"))

    if len(message) > 4000:
        flash("Message is too long.", "warning")
        return redirect(url_for("index"))

    conn = get_db_connection()
    conn.execute(
        "INSERT INTO inquiries (email, message) VALUES (?, ?)",
        (email, message),
    )
    conn.commit()
    conn.close()
    flash("Inquiry received successfully.", "success")
    destination = request.referrer or url_for("index")
    return redirect(destination)


@app.route("/admin")
@admin_required
def admin_panel():
    conn = get_db_connection()
    users = conn.execute(
        """
        SELECT id, username, email, role, is_verified
        FROM users
        ORDER BY id
        """
    ).fetchall()
    inquiries = conn.execute(
        "SELECT id, email, message, status FROM inquiries ORDER BY id DESC"
    ).fetchall()
    conn.close()
    return render_template("admin.html", users=users, inquiries=inquiries, current_user=get_current_user())


@app.route("/admin_create_user", methods=["POST"])
@admin_required
def admin_create_user():
    username = normalize_username(request.form.get("username"))
    email = normalize_email(request.form.get("email"))
    password = request.form.get("password") or ""

    if not validate_username(username):
        flash("Please enter a valid full name.", "danger")
        return redirect(url_for("admin_panel"))
    if not validate_email(email):
        flash("Please enter a valid email address.", "danger")
        return redirect(url_for("admin_panel"))

    password_ok, password_message = validate_password_strength(password)
    if not password_ok:
        flash(password_message, "danger")
        return redirect(url_for("admin_panel"))

    conn = get_db_connection()
    try:
        user_id = _create_user_account(conn, username, email, password, "user")
        if user_id is None:
            flash("Email already registered. Please choose another email.", "danger")
            return redirect(url_for("admin_panel"))

        flash("User created successfully.", "success")
        return redirect(url_for("admin_panel"))
    finally:
        conn.close()


@app.route("/promote_admin", methods=["POST"])
@admin_required
def promote_admin_by_email():
    email = normalize_email(request.form.get("email"))

    if not validate_email(email):
        flash("Please enter a valid email address.", "danger")
        return redirect(url_for("admin_panel"))

    current_user = get_current_user()
    conn = get_db_connection()
    try:
        user = conn.execute(
            "SELECT id, username, role FROM users WHERE email = ?",
            (email,),
        ).fetchone()

        if not user:
            flash("User not found.", "warning")
            return redirect(url_for("admin_panel"))

        if current_user and int(current_user["id"]) == int(user["id"]):
            flash("You are already using your own admin session.", "info")
            return redirect(url_for("admin_panel"))

        updated = _promote_user_to_admin(conn, user["id"])
        if updated:
            conn.commit()
            flash(f"{user['username']} promoted to admin successfully.", "success")
        else:
            flash("User is already an admin.", "warning")
        return redirect(url_for("admin_panel"))
    finally:
        conn.close()


@app.route("/delete_user/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user_id):
    current_user = get_current_user()
    if current_user and int(current_user["id"]) == int(user_id):
        flash("You cannot delete your own active account.", "warning")
        return redirect(url_for("admin_panel"))

    conn = get_db_connection()
    deleted = conn.execute("DELETE FROM users WHERE id = ?", (user_id,)).rowcount
    conn.commit()
    conn.close()
    if deleted:
        flash("User deleted successfully.", "success")
    else:
        flash("User not found.", "warning")
    return redirect(url_for("admin_panel"))


@app.route("/make_admin/<int:user_id>", methods=["POST"])
@admin_required
def make_admin(user_id):
    current_user = get_current_user()
    if current_user and int(current_user["id"]) == int(user_id):
        flash("You are already using your own admin session.", "info")
        return redirect(url_for("admin_panel"))

    conn = get_db_connection()
    updated = _promote_user_to_admin(conn, user_id)
    conn.commit()
    conn.close()
    if updated:
        flash("User promoted to admin successfully.", "success")
    else:
        flash("User is already an admin or not found.", "warning")
    return redirect(url_for("admin_panel"))


@app.route("/export_inquiries")
@admin_required
def export_inquiries():
    conn = get_db_connection()
    inquiries = conn.execute(
        "SELECT email, message, status FROM inquiries ORDER BY id DESC"
    ).fetchall()
    conn.close()

    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["Email", "Message", "Status"])
    for row in inquiries:
        status = row["status"] if row["status"] else "PENDING"
        cw.writerow([row["email"], row["message"], status])

    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=alstandesign_inquiries.csv"
    output.headers["Content-Type"] = "text/csv"
    return output


@app.route("/resolve_inquiry/<int:id>", methods=["POST"])
@admin_required
def resolve_inquiry(id):
    conn = get_db_connection()
    conn.execute("UPDATE inquiries SET status = 'REPLIED' WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    flash("Inquiry marked as replied.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/logout")
def logout():
    response = redirect(url_for("index"))
    clear_auth_cookie(response)
    session.clear()
    return response


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1")
