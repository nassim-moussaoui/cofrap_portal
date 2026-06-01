import psycopg2

try:
    connection = psycopg2.connect(
        host="127.0.0.1",
        port=5433,
        dbname="cofrap_db",
        user="cofrap_user",
        password="cofrap_password",
        options="-c client_encoding=UTF8",
    )

    print("Connexion PostgreSQL OK")

    with connection.cursor() as cursor:
        cursor.execute("SELECT version();")
        print(cursor.fetchone())

    connection.close()

except Exception as error:
    print("Erreur connexion PostgreSQL :")
    print(repr(error))
