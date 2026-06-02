import json
import os

import psycopg2
import pyotp

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


def _user_exists(username):
    conn = psycopg2.connect(
        host=DB_HOST, port=DB_PORT, dbname=DB_NAME, user=DB_USER, password=_db_password()
    )
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM users WHERE username = %s;", (username,))
                return cur.fetchone() is not None
    finally:
        conn.close()


def _save_mfa_secret(username, secret):
    conn = psycopg2.connect(
        host=DB_HOST, port=DB_PORT, dbname=DB_NAME, user=DB_USER, password=_db_password()
    )
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE users SET mfa_secret = %s WHERE username = %s;",
                    (secret, username),
                )
    finally:
        conn.close()


def handle(event, context):
    try:
        body = json.loads(event.body or "{}")
        username = body.get("username", "").strip()
        if not username:
            return {"statusCode": 400, "body": json.dumps({"error": "username requis"})}

        if not _user_exists(username):
            return {"statusCode": 404, "body": json.dumps({"error": "utilisateur introuvable"})}

        secret = pyotp.random_base32()
        totp_uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="COFRAP")
        _save_mfa_secret(username, secret)

        return {
            "statusCode": 200,
            "body": json.dumps({"secret": secret, "totp_uri": totp_uri}),
        }
    except Exception as e:
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}
