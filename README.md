# COFRAP - Portail d'acces securise

Portail web COFRAP pour la gestion des acces collaborateurs avec mot de passe hache, double authentification TOTP et renouvellement periodique des identifiants.

Le projet est pense pour une demo de bout en bout :

- creation d'un utilisateur via script Python
- generation d'un mot de passe fort et d'un QR Code
- activation du secret 2FA / TOTP
- connexion en deux etapes dans le portail web
- redirection vers un dashboard fictif de type back-office COFRAP

## Arborescence utile

- `database/init.sql` : schema PostgreSQL
- `functions/generate_password/main.py` : creation d'un utilisateur et generation du mot de passe
- `functions/generate_2fa/main.py` : generation du secret TOTP et du QR Code 2FA
- `functions/authenticate_user/main.py` : verification mot de passe + code 2FA
- `frontend/app.py` : portail Flask
- `frontend/templates/` : vues HTML
- `frontend/static/css/style.css` : style du portail
- `outputs/` : QR Codes generes par les scripts Python

## Pre-requis

- Python 3.10+ recommande
- Docker Desktop
- PowerShell sur Windows
- Les dependances Python du fichier `requirements.txt`

## Installation

Depuis la racine du projet :

```powershell
python -m venv .venv
(Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned) ; (& .\.venv\Scripts\Activate.ps1)
pip install -r requirements.txt
```

## Configuration locale

Le projet peut charger un fichier `.env` a la racine pour la cle Flask et les parametres PostgreSQL.
Pour partir du modele fourni :

```powershell
Copy-Item .env.example .env
```

Puis adapte les valeurs si besoin avant de lancer le portail ou les scripts.

## Base de donnees PostgreSQL

Lance PostgreSQL via Docker :

```powershell
docker compose up -d
```

La base est disponible avec les parametres suivants :

- host : `127.0.0.1`
- port : `5433`
- dbname : `cofrap_db`
- user : `cofrap_user`
- password : `cofrap_password`

Le schema est charge automatiquement depuis `database/init.sql` lors du premier demarrage du conteneur.

## Demarrage du portail web

Lance le front Flask depuis la racine du projet :

```powershell
python frontend\app.py
```

Puis ouvre le portail dans le navigateur a l'adresse affichee par Flask, en general :

```text
http://127.0.0.1:5000
```

## Demo complete de A a Z

### 1. Creer un utilisateur

Lance le script de creation :

```powershell
python functions\generate_password\main.py
```

Le script demande un nom d'utilisateur, puis :

- genere un mot de passe fort de 24 caracteres
- cree un QR Code du mot de passe dans `outputs/`
- enregistre l'utilisateur en base avec le mot de passe hache

Exemple de nom d'utilisateur : `cduval`

### 2. Activer la double authentification

Lance le script 2FA :

```powershell
python functions\generate_2fa\main.py
```

Le script :

- verifie que l'utilisateur existe deja
- genere un secret TOTP
- produit un QR Code compatible Google Authenticator / Microsoft Authenticator
- stocke le secret 2FA en base

Le QR Code est aussi enregistre dans `outputs/`.

### 3. Tester l'authentification

Lance le script d'authentification :

```powershell
python functions\authenticate_user\main.py
```

Le script demande :

- l'identifiant
- le mot de passe
- le code 2FA courant

Si tout est correct, la connexion est validee.

### 4. Tester le portail web

Dans le navigateur :

- page d'accueil COFRAP
- clic sur `Connexion`
- saisie de l'identifiant et du mot de passe
- puis saisie du code secret a 6 chiffres
- redirection vers le dashboard fictif

Le dashboard simule un espace collaborateur COFRAP avec un faux back-office et des blocs metiers.

## Scenario de demo

1. Demarrer PostgreSQL avec `docker compose up -d`
2. Activer la venv Python
3. Lancer `python functions\generate_password\main.py`
4. Noter le mot de passe genere
5. Lancer `python functions\generate_2fa\main.py`
6. Scanner le QR Code 2FA avec une application Authenticator
7. Lancer `python frontend\app.py`
8. Ouvrir le portail dans le navigateur
9. Se connecter avec l'identifiant et le mot de passe
10. Saisir le code 2FA actuel
11. Montrer le dashboard COFRAP

## Verification de la base

Tu peux tester la connexion a PostgreSQL avec :

```powershell
python test_db.py
```

## Fichiers generes

Les QR Codes et autres sorties temporaires sont stockes dans `outputs/`.

## Notes

- Le mot de passe n'est jamais stocke en clair en base.
- Le secret 2FA est stocke pour permettre la verification TOTP.
- Le portail est concu pour une demonstration interne COFRAP et reste volontairement simple a exploiter en soutenance.
