
from getpass import getpass

from werkzeug.security import generate_password_hash
from app import app, mysql


USERNAME = "cupofjsadmin"


def reset_admin_password():
    print("\n=== CUP OF J'S ADMIN PASSWORD RESET ===")

    password = getpass("Enter new Admin password: ")
    confirm_password = getpass("Confirm new Admin password: ")

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
                UPDATE users
                SET password_hash = %s
                WHERE username = %s AND role = %s
                """,
                (password_hash, USERNAME, "admin")
            )

            mysql.connection.commit()

            if cursor.rowcount == 1:
                print("\nAdmin password successfully updated!")
            else:
                print("\nAdmin account was not found or was not updated.")

        except Exception as error:
            mysql.connection.rollback()
            print("Password Reset Error:", error)

        finally:
            cursor.close()


if __name__ == "__main__":
    reset_admin_password()
