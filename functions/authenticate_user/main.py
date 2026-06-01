from pathlib import Path
import os
import sys
from datetime import datetime, timedelta

import bcrypt
import psycopg2
import pyotp

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from env_utils import load_env_file


PASSWORD_VALIDITY_DAYS = 180

BASE_DIR = ROOT_DIR
load_env_file(BASE_DIR / ".env")

DB_HOST = os.getenv("COFRAP_DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("COFRAP_DB_PORT", "5433"))
DB_NAME = os.getenv("COFRAP_DB_NAME", "cofrap_db")
DB_USER = os.getenv("COFRAP_DB_USER", "cofrap_user")
DB_PASSWORD = os.getenv("COFRAP_DB_PASSWORD", "cofrap_password")


def get_database_connection():
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
    )


def get_user(username: str):
    connection = get_database_connection()

    try:
        with connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT id, username, password_hash, mfa_secret, gendate, expired
                    FROM users
                    WHERE username = %s;
                    """,
                    (username,),
                )
                return cursor.fetchone()
    finally:
        connection.close()


def mark_user_as_expired(username: str) -> None:
    connection = get_database_connection()

    try:
        with connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE users
                    SET expired = TRUE
                    WHERE username = %s;
                    """,
                    (username,),
                )
    finally:
        connection.close()


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(
        password.encode("utf-8"),
        password_hash.encode("utf-8"),
    )


def verify_totp_code(secret: str, code: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(code)


def is_account_expired(gendate: datetime, expired: bool) -> bool:
    if expired:
        return True

    expiration_date = gendate + timedelta(days=PASSWORD_VALIDITY_DAYS)
    return datetime.now() > expiration_date


def main() -> None:
    username = input("Nom d'utilisateur COFRAP : ").strip()
    password = input("Mot de passe : ").strip()
    otp_code = input("Code 2FA Authenticator : ").strip()

    if not username or not password or not otp_code:
        print("Erreur : username, mot de passe et code 2FA sont obligatoires.")
        return

    user = get_user(username)

    if user is None:
        print("Authentification refusée : utilisateur introuvable.")
        return

    user_id, db_username, password_hash, mfa_secret, gendate, expired = user

    if is_account_expired(gendate, expired):
        mark_user_as_expired(username)
        print("Authentification refusée : identifiants expirés, renouvellement nécessaire.")
        return

    if not verify_password(password, password_hash):
        print("Authentification refusée : mot de passe incorrect.")
        return

    if not mfa_secret:
        print("Authentification refusée : 2FA non configurée.")
        return

    if not verify_totp_code(mfa_secret, otp_code):
        print("Authentification refusée : code 2FA incorrect.")
        return

    print("\nAuthentification réussie.")
    print("Utilisateur :", db_username)
    print("Statut : accès autorisé")


if __name__ == "__main__":
    main()
