import os
from pathlib import Path

import psycopg2
import pyotp
import qrcode

from env_utils import load_env_file


BASE_DIR = Path(__file__).resolve().parents[2]
load_env_file(BASE_DIR / ".env")

OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)

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


def user_exists(username: str) -> bool:
    connection = get_database_connection()

    try:
        with connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT id FROM users WHERE username = %s;",
                    (username,),
                )
                return cursor.fetchone() is not None
    finally:
        connection.close()


def generate_2fa_secret() -> str:
    """
    Génère un secret TOTP compatible avec les applications d'authentification.
    """

    return pyotp.random_base32()


def generate_totp_uri(username: str, secret: str) -> str:
    """
    Génère l'URI utilisée par les applications comme Google Authenticator.
    """

    totp = pyotp.TOTP(secret)

    return totp.provisioning_uri(
        name=username,
        issuer_name="COFRAP",
    )


def generate_qr_code(data: str, filename: str) -> Path:
    output_path = OUTPUT_DIR / filename

    qr = qrcode.QRCode(
        version=1,
        box_size=10,
        border=4,
    )

    qr.add_data(data)
    qr.make(fit=True)

    image = qr.make_image(fill_color="black", back_color="white")
    image.save(output_path)

    return output_path


def save_2fa_secret(username: str, secret: str) -> None:
    connection = get_database_connection()

    try:
        with connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE users
                    SET mfa_secret = %s
                    WHERE username = %s;
                    """,
                    (secret, username),
                )
    finally:
        connection.close()


def main() -> None:
    username = input("Nom d'utilisateur COFRAP : ").strip()

    if not username:
        print("Erreur : le nom d'utilisateur est obligatoire.")
        return

    if not user_exists(username):
        print("Erreur : l'utilisateur n'existe pas en base.")
        print("Crée d'abord l'utilisateur avec la fonction generate_password.")
        return

    secret = generate_2fa_secret()
    totp_uri = generate_totp_uri(username, secret)
    qr_path = generate_qr_code(totp_uri, f"{username}_2fa_qr.png")

    save_2fa_secret(username, secret)

    print("\nUtilisateur :", username)
    print("Secret 2FA généré :", secret)
    print("QR Code 2FA généré :", qr_path)
    print("Secret 2FA enregistré en base PostgreSQL.")


if __name__ == "__main__":
    main()
