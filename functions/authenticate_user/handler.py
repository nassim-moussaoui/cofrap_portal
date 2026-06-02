import json
import os
from datetime import datetime, timedelta

import bcrypt
import psycopg2
import pyotp

PASSWORD_VALIDITY_DAYS = 180

DB_HOST = os.getenv("COFRAP_DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("COFRAP_DB_PORT", "5432"))
DB_NAME = os.getenv("COFRAP_DB_NAME", "cofrap_db")
DB_USER = os.getenv("COFRAP_DB_USER", "cofrap_user")


def _db_password():
    secret_path = "/var/openfaas/secrets/cofrap-db-password"
    if os.path.exists(secret_path):
        with open(secret_path) as f:
            return f.read().strip()
    return os.getenv("COFRAP_DB_PASSWORD", "cofrap_password")


def _get_user(username):
    conn = psycopg2.connect(
        host=DB_HOST, port=DB_PORT, dbname=DB_NAME, user=DB_USER, password=_db_password()
    )
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT username, password_hash, mfa_secret, gendate, expired FROM users WHERE username = %s;",
                    (username,),
                )
                return cur.fetchone()
    finally:
        conn.close()


def _mark_expired(username):
    conn = psycopg2.connect(
        host=DB_HOST, port=DB_PORT, dbname=DB_NAME, user=DB_USER, password=_db_password()
    )
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE users SET expired = TRUE WHERE username = %s;", (username,))
    finally:
        conn.close()


def handle(event, context):
    try:
        body = json.loads(event.body or "{}")
        username = body.get("username", "").strip()
        password = body.get("password", "")
        otp_code = body.get("otp_code", "").strip()

        if not username:
            return {"statusCode": 400, "body": json.dumps({"error": "username requis"})}

        user = _get_user(username)
        if user is None:
            return {"statusCode": 401, "body": json.dumps({"error": "identifiant inconnu"})}

        db_username, password_hash, mfa_secret, gendate, expired = user

        # Check expiration
        is_expired = expired or (datetime.now() > gendate + timedelta(days=PASSWORD_VALIDITY_DAYS))
        if is_expired:
            _mark_expired(username)
            return {"statusCode": 401, "body": json.dumps({"error": "identifiants expirés", "expired": True})}

        # Stage 1 — password only
        if password and not otp_code:
            if not bcrypt.checkpw(password.encode(), password_hash.encode()):
                return {"statusCode": 401, "body": json.dumps({"error": "mot de passe incorrect"})}
            if not mfa_secret:
                return {"statusCode": 401, "body": json.dumps({"error": "2FA non configurée"})}
            return {"statusCode": 200, "body": json.dumps({"step": "otp_required", "username": db_username})}

        # Stage 2 — OTP only (password already verified in stage 1)
        if otp_code and not password:
            if not mfa_secret:
                return {"statusCode": 401, "body": json.dumps({"error": "2FA non configurée"})}
            if not pyotp.TOTP(mfa_secret).verify(otp_code):
                return {"statusCode": 401, "body": json.dumps({"error": "code 2FA incorrect"})}
            return {"statusCode": 200, "body": json.dumps({"step": "authenticated", "username": db_username})}

        return {"statusCode": 400, "body": json.dumps({"error": "password ou otp_code requis"})}

    except Exception as e:
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}
