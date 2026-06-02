import json
import os
import secrets
import string

import bcrypt
import psycopg2

PASSWORD_LENGTH = 24

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


def _generate_password(length=PASSWORD_LENGTH):
    chars = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*()-_=+[]{};:,.?/"),
    ]
    pool = string.ascii_uppercase + string.ascii_lowercase + string.digits + "!@#$%^&*()-_=+[]{};:,.?/"
    while len(chars) < length:
        chars.append(secrets.choice(pool))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def _save_user(username, password_hash):
    conn = psycopg2.connect(
        host=DB_HOST, port=DB_PORT, dbname=DB_NAME, user=DB_USER, password=_db_password()
    )
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO users (username, password_hash)
                    VALUES (%s, %s)
                    ON CONFLICT (username) DO UPDATE
                      SET password_hash = EXCLUDED.password_hash,
                          gendate = CURRENT_TIMESTAMP,
                          expired = FALSE;
                    """,
                    (username, password_hash),
                )
    finally:
        conn.close()


def handle(event, context):
    try:
        body = json.loads(event.body or "{}")
        username = body.get("username", "").strip()
        if not username:
            return {"statusCode": 400, "body": json.dumps({"error": "username requis"})}

        password = _generate_password()
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        _save_user(username, password_hash)

        return {
            "statusCode": 200,
            "body": json.dumps({"password": password, "password_hash": password_hash}),
        }
    except Exception as e:
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}
