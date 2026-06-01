import os
import secrets
import string
from pathlib import Path

import qrcode
import bcrypt
import psycopg2

from env_utils import load_env_file


PASSWORD_LENGTH = 24

BASE_DIR = Path(__file__).resolve().parents[2]
load_env_file(BASE_DIR / ".env")

OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)

DB_HOST = os.getenv("COFRAP_DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("COFRAP_DB_PORT", "5433"))
DB_NAME = os.getenv("COFRAP_DB_NAME", "cofrap_db")
DB_USER = os.getenv("COFRAP_DB_USER", "cofrap_user")
DB_PASSWORD = os.getenv("COFRAP_DB_PASSWORD", "cofrap_password")


def generate_secure_password(length: int = PASSWORD_LENGTH) -> str:
    if length < 4:
        raise ValueError("La longueur minimale doit être d'au moins 4 caractères.")

    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    digits = string.digits
    special_chars = "!@#$%^&*()-_=+[]{};:,.?/"

    password_chars = [
        secrets.choice(uppercase),
        secrets.choice(lowercase),
        secrets.choice(digits),
        secrets.choice(special_chars),
    ]

    all_chars = uppercase + lowercase + digits + special_chars

    while len(password_chars) < length:
        password_chars.append(secrets.choice(all_chars))

    secrets.SystemRandom().shuffle(password_chars)

    return "".join(password_chars)

def hash_password(password: str) -> str:
    """
    Hash le mot de passe avant stockage.
    Le mot de passe en clair sert uniquement à générer le QR Code.
    """

    password_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password_bytes, salt)

    return hashed_password.decode("utf-8")

def save_user_to_database(username: str, password_hash: str) -> None:
    """
    Enregistre l'utilisateur et le hash du mot de passe dans PostgreSQL.
    Le mot de passe en clair n'est jamais stocké.
    """

    connection = psycopg2.connect(
        f"host={DB_HOST} "
        f"port={DB_PORT} "
        f"dbname={DB_NAME} "
        f"user={DB_USER} "
        f"password={DB_PASSWORD} "
        "client_encoding=UTF8"
    )

    try:
        with connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO users (username, password_hash)
                    VALUES (%s, %s)
                    ON CONFLICT (username)
                    DO UPDATE SET
                        password_hash = EXCLUDED.password_hash,
                        gendate = CURRENT_TIMESTAMP,
                        expired = FALSE;
                    """,
                    (username, password_hash),
                )
    finally:
        connection.close()


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


def main() -> None:
    username = input("Nom d'utilisateur COFRAP : ").strip()

    if not username:
        print("Erreur : le nom d'utilisateur est obligatoire.")
        return

    password = generate_secure_password()
    hashed_password = hash_password(password)
    qr_path = generate_qr_code(password, f"{username}_password_qr.png")
    save_user_to_database(username, hashed_password)

    print("\nUtilisateur :", username)
    print("Mot de passe généré :", password)
    print("Hash du mot de passe :", hashed_password)
    print("Longueur :", len(password))
    print("QR Code généré :", qr_path)
    print("Utilisateur enregistré en base PostgreSQL.")


if __name__ == "__main__":
    main()
