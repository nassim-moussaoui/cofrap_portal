import os
import sys
from pathlib import Path

import qrcode
import requests
from flask import Flask, redirect, render_template, request, session, url_for

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from env_utils import load_env_file

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "dev-only-change-me")

PORTAL_STATUS = [
    {
        "label": "Portail d'accès",
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
        "description": "Renouvellement périodique prévu par la politique d'accès.",
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
        "description": "Tableaux de bord consolidés pour les responsables d'activité.",
        "tag": "Lecture sécurisée",
    },
]

BASE_DIR = ROOT_DIR
load_env_file(BASE_DIR / ".env")
OUTPUT_DIR = BASE_DIR / "frontend" / "static" / "generated"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

OPENFAAS_URL = os.getenv("OPENFAAS_GATEWAY_URL", "http://gateway.openfaas:8080")


def call_fn(name, payload):
    resp = requests.post(f"{OPENFAAS_URL}/function/{name}", json=payload, timeout=10)
    resp.raise_for_status()
    return resp.json()


def generate_qr_code(data: str, filename: str) -> str:
    output_path = OUTPUT_DIR / filename
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(data)
    qr.make(fit=True)
    qr.make_image(fill_color="black", back_color="white").save(output_path)
    return f"generated/{filename}"


@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/create-user", methods=["GET", "POST"])
def create_user():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        full_name = request.form.get("full_name", "").strip()
        service = request.form.get("service", "").strip()

        if not username:
            return render_template(
                "create_user.html",
                error="Le nom d'utilisateur est obligatoire.",
                username=username,
                full_name=full_name,
                service=service,
            )

        try:
            data = call_fn("generate-password", {"username": username})
        except Exception as e:
            return render_template(
                "create_user.html",
                error=f"Erreur service : {e}",
                username=username,
                full_name=full_name,
                service=service,
            )

        password = data["password"]
        qr_image = generate_qr_code(password, f"{username}_password_qr.png")

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


@app.route("/first-connection", methods=["GET", "POST"])
def first_connection():
    step = session.get("first_connection_step", "username")
    username = session.get("first_connection_username", "").strip()
    password = session.get("first_connection_password", "")
    password_qr = session.get("first_connection_password_qr", "")
    mfa_qr = session.get("first_connection_mfa_qr", "")

    if request.method == "POST":
        action = request.form.get("action", "start")

        if action == "start":
            username = request.form.get("username", "").strip()
            if not username:
                return render_template(
                    "first_connection.html",
                    step="username",
                    error="Le nom d'utilisateur est obligatoire.",
                    username=username,
                )

            try:
                data = call_fn("generate-password", {"username": username})
            except Exception as e:
                return render_template(
                    "first_connection.html",
                    step="username",
                    error=f"Erreur service : {e}",
                    username=username,
                )

            password = data["password"]
            password_qr = generate_qr_code(password, f"{username}_password_qr.png")

            session["first_connection_step"] = "password"
            session["first_connection_username"] = username
            session["first_connection_password"] = password
            session["first_connection_password_qr"] = password_qr

            return render_template(
                "first_connection.html",
                step="password",
                username=username,
                password=password,
                password_qr=password_qr,
            )

        if action == "configure_mfa":
            username = session.get("first_connection_username", "").strip()
            password = session.get("first_connection_password", "")

            if not username or not password:
                session.pop("first_connection_step", None)
                session.pop("first_connection_username", None)
                session.pop("first_connection_password", None)
                session.pop("first_connection_password_qr", None)
                session.pop("first_connection_mfa_qr", None)
                return redirect(url_for("first_connection"))

            try:
                data = call_fn("generate-2fa", {"username": username})
            except Exception as e:
                return render_template(
                    "first_connection.html",
                    step="password",
                    error=f"Erreur service : {e}",
                    username=username,
                    password=password,
                    password_qr=session.get("first_connection_password_qr", ""),
                )

            mfa_qr = generate_qr_code(data["totp_uri"], f"{username}_2fa_qr.png")
            session["first_connection_step"] = "mfa"
            session["first_connection_mfa_secret"] = data["secret"]
            session["first_connection_mfa_qr"] = mfa_qr

            return render_template(
                "first_connection.html",
                step="mfa",
                username=username,
                password=password,
                password_qr=session.get("first_connection_password_qr", ""),
                mfa_qr=mfa_qr,
            )

        if action == "finish":
            session.pop("first_connection_step", None)
            session.pop("first_connection_username", None)
            session.pop("first_connection_password", None)
            session.pop("first_connection_password_qr", None)
            session.pop("first_connection_mfa_qr", None)
            session.pop("first_connection_mfa_secret", None)
            return redirect(url_for("login", username=username))

    if step == "password" and username and password:
        return render_template(
            "first_connection.html",
            step="password",
            username=username,
            password=password,
            password_qr=password_qr,
        )

    if step == "mfa" and username and password:
        return render_template(
            "first_connection.html",
            step="mfa",
            username=username,
            password=password,
            password_qr=password_qr,
            mfa_qr=mfa_qr,
        )

    return render_template("first_connection.html", step="username")


@app.route("/activate-2fa", methods=["GET", "POST"])
def activate_2fa():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        if not username:
            return render_template(
                "activate_2fa.html",
                error="Le nom d'utilisateur est obligatoire.",
                username=username,
            )

        try:
            data = call_fn("generate-2fa", {"username": username})
        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code == 404:
                return render_template(
                    "activate_2fa.html",
                    error="Utilisateur introuvable. Créez d'abord le compte.",
                    username=username,
                )
            return render_template(
                "activate_2fa.html",
                error=f"Erreur service : {e}",
                username=username,
            )
        except Exception as e:
            return render_template(
                "activate_2fa.html",
                error=f"Erreur service : {e}",
                username=username,
            )

        qr_image = generate_qr_code(data["totp_uri"], f"{username}_2fa_qr.png")

        return render_template(
            "activate_2fa.html",
            success=True,
            username=username,
            secret=data["secret"],
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

            try:
                data = call_fn("authenticate-user", {"username": username, "password": password})
            except requests.HTTPError as e:
                resp_data = {}
                if e.response is not None:
                    try:
                        resp_data = e.response.json()
                    except Exception:
                        pass
                if resp_data.get("expired"):
                    return render_template("login.html", error="Renouvellement requis : les identifiants ont expiré.", expired=True, username=username)
                return render_template("login.html", error=resp_data.get("error", "Accès refusé."), username=username)
            except Exception as e:
                return render_template("login.html", error=f"Erreur service : {e}", username=username)

            if data.get("step") == "otp_required":
                session["pending_login_username"] = data["username"]
                return render_template("login.html", username=data["username"], otp_pending=True)

            return render_template("login.html", error="Réponse inattendue du service.", username=username)

        # OTP stage
        username = session.get("pending_login_username", "").strip()
        if not username:
            return render_template("login.html", error="La session de vérification a expiré. Reprenez la connexion depuis le début.")

        otp_code = request.form.get("otp_code", "").strip()
        if not otp_code:
            return render_template("login.html", error="Le code de vérification est obligatoire.", username=username, otp_pending=True)

        try:
            data = call_fn("authenticate-user", {"username": username, "otp_code": otp_code})
        except requests.HTTPError as e:
            resp_data = {}
            if e.response is not None:
                try:
                    resp_data = e.response.json()
                except Exception:
                    pass
            if resp_data.get("expired"):
                session.pop("pending_login_username", None)
                return render_template("login.html", error="Renouvellement requis : les identifiants ont expiré.", expired=True, username=username)
            return render_template("login.html", error=resp_data.get("error", "Code incorrect."), username=username, otp_pending=True)
        except Exception as e:
            return render_template("login.html", error=f"Erreur service : {e}", username=username, otp_pending=True)

        if data.get("step") == "authenticated":
            session.pop("pending_login_username", None)
            return redirect(url_for("dashboard", username=username))

        return render_template("login.html", error="Réponse inattendue du service.", username=username, otp_pending=True)

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
    app.run(host="0.0.0.0", debug=True)
