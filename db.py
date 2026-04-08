import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(__file__), "alstandesign.db")


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _table_columns(conn, table_name):
    return {row["name"] for row in conn.execute(f"PRAGMA table_info({table_name})")}


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
