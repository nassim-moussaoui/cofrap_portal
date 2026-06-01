from datetime import datetime, timedelta
import os
from pathlib import Path

import bcrypt
import psycopg2
import pyotp
import qrcode
import secrets
import string
from flask import Flask, redirect, render_template, request, session, url_for

from env_utils import load_env_file


app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "dev-only-change-me")

PASSWORD_LENGTH = 24
PASSWORD_VALIDITY_DAYS = 180

PORTAL_STATUS = [
    {
        "label": "Portail d’accès",
        "description": "Accès interne disponible pour les collaborateurs autorisés.",
        "value": "Disponible",
        "state": "ok",
    },
    {
        "label": "Authentification forte",
        "description": "Parcours sécurisé avec mot de passe et code à usage temporaire.",
        "value": "En service",
        "state": "ok",
    },
    {
        "label": "Rotation des identifiants",
        "description": "Renouvellement périodique prévu par la politique d’accès.",
        "value": "180 jours",
        "state": "neutral",
    },
]

CLOUD_APPS = [
    {
        "name": "Gestion commerciale",
        "description": "Suivi des opportunités, validation des devis et pilotage des comptes clients.",
        "tag": "Accès métier",
    },
    {
        "name": "Portail RH",
        "description": "Consultation des dossiers collaborateurs, congés et indicateurs RH.",
        "tag": "Accès sensible",
    },
    {
        "name": "Support client",
        "description": "Traitement des demandes, tickets prioritaires et suivi des SLA.",
        "tag": "Service support",
    },
    {
        "name": "Reporting métier",
        "description": "Tableaux de bord consolidés pour les responsables d’activité.",
        "tag": "Lecture sécurisée",
    },
]

BASE_DIR = Path(__file__).resolve().parent.parent
load_env_file(BASE_DIR / ".env")
OUTPUT_DIR = BASE_DIR / "frontend" / "static" / "generated"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

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


def generate_secure_password(length: int = PASSWORD_LENGTH) -> str:
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
    return bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(),
    ).decode("utf-8")


def generate_qr_code(data: str, filename: str) -> str:
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

    return f"generated/{filename}"


def create_or_update_user(username: str, password_hash: str) -> None:
    connection = get_database_connection()

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


def get_user(username: str):
    connection = get_database_connection()

    try:
        with connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT username, password_hash, mfa_secret, gendate, expired
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


def is_account_expired(gendate: datetime, expired: bool) -> bool:
    if expired:
        return True

    expiration_date = gendate + timedelta(days=PASSWORD_VALIDITY_DAYS)
    return datetime.now() > expiration_date


@app.route("/")
def index():
    return render_template("index.html", service_status=PORTAL_STATUS)


@app.route("/create-user", methods=["GET", "POST"])
def create_user():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        full_name = request.form.get("full_name", "").strip()
        service = request.form.get("service", "").strip()

        if not username:
            return render_template(
                "create_user.html",
                error="Le nom d’utilisateur est obligatoire.",
                username=username,
                full_name=full_name,
                service=service,
            )

        password = generate_secure_password()
        password_hash = hash_password(password)
        create_or_update_user(username, password_hash)

        qr_image = generate_qr_code(
            password,
            f"{username}_password_qr.png",
        )

        return render_template(
            "create_user.html",
            success=True,
            username=username,
            full_name=full_name,
            service=service,
            password=password,
            qr_image=qr_image,
        )

    return render_template("create_user.html")


@app.route("/activate-2fa", methods=["GET", "POST"])
def activate_2fa():
    if request.method == "POST":
        username = request.form.get("username", "").strip()

        if not username:
            return render_template(
                "activate_2fa.html",
                error="Le nom d’utilisateur est obligatoire.",
                username=username,
            )

        if not user_exists(username):
            return render_template(
                "activate_2fa.html",
                error="Utilisateur introuvable. Créez d’abord le compte.",
                username=username,
            )

        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)

        totp_uri = totp.provisioning_uri(
            name=username,
            issuer_name="COFRAP",
        )

        qr_image = generate_qr_code(
            totp_uri,
            f"{username}_2fa_qr.png",
        )

        save_2fa_secret(username, secret)

        return render_template(
            "activate_2fa.html",
            success=True,
            username=username,
            secret=secret,
            qr_image=qr_image,
        )

    return render_template(
        "activate_2fa.html",
        username=request.args.get("username", "").strip(),
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        stage = request.form.get("stage", "credentials")

        if stage == "credentials":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip()

            if not username or not password:
                return render_template(
                    "login.html",
                    error="Les deux premiers champs sont obligatoires.",
                    username=username,
                )

            user = get_user(username)

            if user is None:
                return render_template(
                    "login.html",
                    error="Accès refusé : identifiant inconnu.",
                    username=username,
                )

            db_username, password_hash, mfa_secret, gendate, expired = user

            if is_account_expired(gendate, expired):
                mark_user_as_expired(username)
                return render_template(
                    "login.html",
                    error="Renouvellement requis : les identifiants ont expiré.",
                    expired=True,
                    username=username,
                )

            if not bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8")):
                return render_template(
                    "login.html",
                    error="Accès refusé : mot de passe incorrect.",
                    username=username,
                )

            if not mfa_secret:
                return render_template(
                    "login.html",
                    error="Authentification impossible : la double authentification n’est pas activée.",
                    username=username,
                )

            session["pending_login_username"] = db_username

            return render_template(
                "login.html",
                username=db_username,
                otp_pending=True,
            )

        username = session.get("pending_login_username", "").strip()

        if not username:
            return render_template(
                "login.html",
                error="La session de vérification a expiré. Reprenez la connexion depuis le début.",
            )

        otp_code = request.form.get("otp_code", "").strip()

        if not otp_code:
            return render_template(
                "login.html",
                error="Le code de vérification est obligatoire.",
                username=username,
                otp_pending=True,
            )

        user = get_user(username)

        if user is None:
            session.pop("pending_login_username", None)
            return render_template(
                "login.html",
                error="Authentification refusée : compte introuvable.",
            )

        _, _, mfa_secret, gendate, expired = user

        if is_account_expired(gendate, expired):
            session.pop("pending_login_username", None)
            mark_user_as_expired(username)
            return render_template(
                "login.html",
                error="Renouvellement requis : les identifiants ont expiré.",
                expired=True,
                username=username,
            )

        if not mfa_secret:
            session.pop("pending_login_username", None)
            return render_template(
                "login.html",
                error="Authentification impossible : la double authentification n’est pas activée.",
            )

        totp = pyotp.TOTP(mfa_secret)

        if not totp.verify(otp_code):
            return render_template(
                "login.html",
                error="Accès refusé : le code de vérification n’est pas valide.",
                username=username,
                otp_pending=True,
            )

        session.pop("pending_login_username", None)

        return redirect(url_for("dashboard", username=username))

    pending_username = session.get("pending_login_username", "").strip()

    return render_template(
        "login.html",
        username=request.args.get("username", "").strip() or pending_username,
        otp_pending=bool(pending_username),
    )


@app.route("/dashboard")
def dashboard():
    username = request.args.get("username", "").strip()

    return render_template(
        "dashboard.html",
        username=username,
        service_status=PORTAL_STATUS,
        cloud_apps=CLOUD_APPS,
    )


if __name__ == "__main__":
    app.run(debug=True)
