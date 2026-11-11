
from getpass import getpass

from werkzeug.security import generate_password_hash
from app import app, mysql


ADMIN_NAME = "Joahanna Grace Herradura"
ADMIN_USERNAME = "cupofjsadmin"


def create_admin():
    print("\n=== CUP OF J'S ADMIN ACCOUNT SETUP ===")

    email = input("Enter Admin email address: ").strip().lower()

    password = getpass("Create Admin password: ")
    confirm_password = getpass("Confirm Admin password: ")

    if not email:
        print("Error: Email is required.")
        return

    if len(password) < 8:
        print("Error: Password must be at least 8 characters.")
        return

    if password != confirm_password:
        print("Error: Passwords do not match.")
        return

    password_hash = generate_password_hash(password)

    with app.app_context():
        cursor = mysql.connection.cursor()

        try:
            cursor.execute(
                """
                SELECT user_id
                FROM users
                WHERE username = %s OR email = %s
                """,
                (ADMIN_USERNAME, email)
            )

            existing_user = cursor.fetchone()

            if existing_user:
                print("Error: This username or email is already registered.")
                return

            cursor.execute(
                """
                INSERT INTO users
                (full_name, username, email, password_hash, role)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    ADMIN_NAME,
                    ADMIN_USERNAME,
                    email,
                    password_hash,
                    "admin"
                )
            )

            mysql.connection.commit()

            print("\nAdmin account successfully created!")
            print("Name:", ADMIN_NAME)
            print("Username:", ADMIN_USERNAME)
            print("Role: admin")

        except Exception as error:
            mysql.connection.rollback()
            print("Admin Creation Error:", error)

        finally:
            cursor.close()


if __name__ == "__main__":
    create_admin()
