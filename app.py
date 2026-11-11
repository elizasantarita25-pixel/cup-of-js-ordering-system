import secrets
import smtplib
import os
import uuid
from werkzeug.utils import secure_filename
from flask import send_file

from email.message import EmailMessage
from flask import (
    Flask, render_template, redirect,
    url_for, flash, session, request
)
from flask_mysqldb import MySQL
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)
from decimal import Decimal
from functools import wraps
from datetime import datetime, timedelta
from models import ProductVariant, Order, OrderItem, Addon, Customer, Admin

from config import Config
from forms import (
    RegistrationForm,
    LoginForm,
    CategoryForm,
    ProductForm,
    ProductVariantForm,
    InventoryForm,
    AddonForm,
    OrderForm,
    OrderItemForm
)

app = Flask(__name__)
app.config.from_object(Config)

# GCash payment proof upload settings
app.config["UPLOAD_FOLDER"] = os.path.join(
    app.instance_path,
    "gcash_proofs"
)

app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

csrf = CSRFProtect(app)
mysql = MySQL(app)


# SEND OTP EMAIL


def send_otp_email(recipient_email, otp, purpose="verification"):

    try:
        message = EmailMessage()

        if purpose == "password_reset":
            message["Subject"] = "Cup of J's - Password Reset"
            email_content = f"""
Hello!

You requested to reset your Cup of J's account password.

Your password reset code is:

{otp}

This code will expire after 5 minutes.

Please do not share this code with anyone.

If you did not request a password reset, you may ignore this email.

Thank you!
Cup of J's
"""
        else:
            message["Subject"] = "Cup of J's - Email Verification"
            email_content = f"""
Hello!

Thank you for registering at Cup of J's.

Your email verification code is:

{otp}

This code will expire after 5 minutes.

Please do not share this code with anyone.

If you did not request this verification, you may ignore this email.

Thank you!
Cup of J's
"""

        message["From"] = app.config["MAIL_DEFAULT_SENDER"]
        message["To"] = recipient_email
        message.set_content(email_content)

        with smtplib.SMTP(
            app.config["MAIL_SERVER"],
            app.config["MAIL_PORT"],
            timeout=20
        ) as server:

            server.starttls()

            server.login(
                app.config["MAIL_USERNAME"],
                app.config["MAIL_PASSWORD"]
            )

            server.send_message(message)

        return True

    except Exception as error:
        print("OTP Email Error:", error)
        return False


# SEND PASSWORD RESET EMAIL

def send_password_reset_email(recipient_email, otp):

    try:
        message = EmailMessage()

        message["Subject"] = "Cup of J's - Password Reset"
        message["From"] = app.config["MAIL_DEFAULT_SENDER"]
        message["To"] = recipient_email

        message.set_content(f"""
Hello!

We received a request to reset your Cup of J's account password.

Your password reset verification code is:

{otp}

This code will expire after 5 minutes.

Please do not share this code with anyone.

If you did not request a password reset, you may ignore this email.

Thank you!
Cup of J's
        """)

        with smtplib.SMTP(
            app.config["MAIL_SERVER"],
            app.config["MAIL_PORT"],
            timeout=20
        ) as server:

            server.starttls()

            server.login(
                app.config["MAIL_USERNAME"],
                app.config["MAIL_PASSWORD"]
            )

            server.send_message(message)

        return True

    except Exception as error:
        print("Password Reset Email Error:", error)
        return False

# =========================
# ACCESS CONTROL DECORATORS
# =========================

def login_required(route_function):
    @wraps(route_function)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "error")
            return redirect(url_for("login"))

        return route_function(*args, **kwargs)

    return wrapper


def role_required(required_role):
    def decorator(route_function):
        @wraps(route_function)
        def wrapper(*args, **kwargs):
            current_role = str(
                session.get("role", "")
            ).strip().lower()

            if current_role != required_role:
                flash(
                    "You are not authorized to access that page.",
                    "error"
                )

                if current_role == "admin":
                    return redirect(url_for("admin_dashboard"))

                if current_role == "customer":
                    return redirect(url_for("customer_dashboard"))

                session.clear()
                return redirect(url_for("login"))

            return route_function(*args, **kwargs)

        return wrapper
    return decorator

# =========================
# HOME
# =========================

@app.route("/")
def home():
    return redirect(url_for("login"))


# =========================
# CUSTOMER REGISTRATION
# =========================

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():

        full_name = form.full_name.data.strip()
        username = form.username.data.strip()
        email = form.email.data.strip().lower()
        password_hash = generate_password_hash(
            form.password.data
        )

        cursor = mysql.connection.cursor()

        try:
            # Check existing registered account
            cursor.execute("""
                SELECT user_id
                FROM users
                WHERE username = %s OR email = %s
            """, (username, email))

            if cursor.fetchone():
                flash(
                    "Username or email is already registered.",
                    "error"
                )
                return render_template(
                    "register.html",
                    form=form
                )

            # Remove expired pending registrations
            cursor.execute("""
                DELETE FROM pending_registrations
                WHERE expires_at <= NOW()
            """)

            # Check existing pending registration
            cursor.execute("""
                SELECT pending_id
                FROM pending_registrations
                WHERE username = %s OR email = %s
            """, (username, email))

            if cursor.fetchone():
                flash(
                    "A registration with this username or email is already awaiting verification.",
                    "error"
                )
                return render_template(
                    "register.html",
                    form=form
                )

            # Generate six-digit OTP
            otp = f"{secrets.randbelow(1000000):06d}"

            otp_hash = generate_password_hash(otp)

            now = datetime.now()
            expires_at = now + timedelta(minutes=5)

            # Save pending registration
            cursor.execute("""
                INSERT INTO pending_registrations
                (
                    full_name,
                    username,
                    email,
                    password_hash,
                    otp_hash,
                    expires_at,
                    attempts,
                    last_sent_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                full_name,
                username,
                email,
                password_hash,
                otp_hash,
                expires_at,
                0,
                now
            ))

            mysql.connection.commit()

            # Send OTP email
            email_sent = send_otp_email(
            email,
            otp,
            purpose="verification"
        )
            if not email_sent:
                cursor.execute("""
                    DELETE FROM pending_registrations
                    WHERE username = %s
                """, (username,))

                mysql.connection.commit()

                flash(
                    "Unable to send verification email. Please try again.",
                    "error"
                )

                return render_template(
                    "register.html",
                    form=form
                )

            flash(
                "A verification code has been sent to your email.",
                "success"
            )

            return redirect(
                url_for("verify_otp", email=email)
            )

        except Exception as error:
            mysql.connection.rollback()
            print("Registration Error:", error)

            flash(
                "Something went wrong. Please try again.",
                "error"
            )

        finally:
            cursor.close()

    return render_template("register.html", form=form)


# VERIFY REGISTRATION OTP

@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():

    email = request.args.get("email", "").strip().lower()

    if not email:
        flash("Invalid verification request.", "error")
        return redirect(url_for("register"))

    cursor = mysql.connection.cursor()

    try:
        cursor.execute("""
            SELECT
                pending_id,
                full_name,
                username,
                email,
                password_hash,
                otp_hash,
                expires_at,
                attempts
            FROM pending_registrations
            WHERE email = %s
        """, (email,))

        pending = cursor.fetchone()

        if not pending:
            flash(
                "Registration request not found. Please register again.",
                "error"
            )
            return redirect(url_for("register"))

        if request.method == "POST":

            otp = request.form.get("otp", "").strip()

            if not otp.isdigit() or len(otp) != 6:
                flash(
                    "Please enter a valid 6-digit verification code.",
                    "error"
                )
                return render_template(
                    "verify_otp.html",
                    email=email
                )

            # Check expiration
            if datetime.now() >= pending[6]:
                flash(
                    "Your verification code has expired. Please request a new code.",
                    "error"
                )
                return render_template(
                    "verify_otp.html",
                    email=email
                )

            # Check maximum attempts
            if pending[7] >= 5:
                flash(
                    "Maximum verification attempts reached. Please request a new code.",
                    "error"
                )
                return render_template(
                    "verify_otp.html",
                    email=email
                )

            # Verify OTP
            if not check_password_hash(pending[5], otp):

                cursor.execute("""
                    UPDATE pending_registrations
                    SET attempts = attempts + 1
                    WHERE pending_id = %s
                """, (pending[0],))

                mysql.connection.commit()

                flash(
                    "Incorrect verification code. Please try again.",
                    "error"
                )

                return render_template(
                    "verify_otp.html",
                    email=email
                )

            # Create customer account only after successful verification
            cursor.execute("""
                INSERT INTO users
                (
                    full_name,
                    username,
                    email,
                    password_hash,
                    role
                )
                VALUES (%s, %s, %s, %s, %s)
            """, (
                pending[1],
                pending[2],
                pending[3],
                pending[4],
                "customer"
            ))

            # Remove verified pending registration
            cursor.execute("""
                DELETE FROM pending_registrations
                WHERE pending_id = %s
            """, (pending[0],))

            mysql.connection.commit()

            flash(
                "Email verified! Your account has been created. You can now log in.",
                "success"
            )

            return redirect(url_for("login"))

        return render_template(
            "verify_otp.html",
            email=email
        )

    except Exception as error:
        mysql.connection.rollback()
        print("OTP Verification Error:", error)

        flash(
            "Unable to verify your email. Please try again.",
            "error"
        )

        return redirect(
            url_for("register")
        )

    finally:
        cursor.close()


# RESEND REGISTRATION OTP

@app.route("/resend-otp", methods=["POST"])
def resend_otp():

    email = request.form.get("email", "").strip().lower()

    if not email:
        flash("Invalid email address.", "error")
        return redirect(url_for("register"))

    cursor = mysql.connection.cursor()

    try:
        cursor.execute("""
            SELECT pending_id, last_sent_at
            FROM pending_registrations
            WHERE email = %s
        """, (email,))

        pending = cursor.fetchone()

        if not pending:
            flash(
                "Registration request not found. Please register again.",
                "error"
            )
            return redirect(url_for("register"))

        now = datetime.now()
        last_sent_at = pending[1]

        # Enforce 60-second resend cooldown
        elapsed = (now - last_sent_at).total_seconds()

        if elapsed < 60:
            remaining = int(60 - elapsed) + 1

            flash(
                f"Please wait {remaining} seconds before requesting another code.",
                "error"
            )

            return redirect(
                url_for("verify_otp", email=email)
            )

        # Generate a new six-digit OTP
        otp = f"{secrets.randbelow(1000000):06d}"
        otp_hash = generate_password_hash(otp)
        expires_at = now + timedelta(minutes=5)

        # Send the new OTP first
        email_sent = send_otp_email(
        email,
        otp,
        purpose="verification"
)

        if not email_sent:
            flash(
                "Unable to send a new verification code. Please try again later.",
                "error"
            )

            return redirect(
                url_for("verify_otp", email=email)
            )

        # Update OTP and reset attempts
        cursor.execute("""
            UPDATE pending_registrations
            SET otp_hash = %s,
                expires_at = %s,
                attempts = 0,
                last_sent_at = %s
            WHERE pending_id = %s
        """, (
            otp_hash,
            expires_at,
            now,
            pending[0]
        ))

        mysql.connection.commit()

        flash(
            "A new verification code has been sent to your email.",
            "success"
        )

        return redirect(
            url_for("verify_otp", email=email)
        )

    except Exception as error:
        mysql.connection.rollback()
        print("Resend OTP Error:", error)

        flash(
            "Unable to resend verification code.",
            "error"
        )

        return redirect(
            url_for("register")
        )

    finally:
        cursor.close()

# =========================
# LOGIN
# =========================


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        username_or_email = form.username.data.strip()
        password = form.password.data

        cursor = mysql.connection.cursor()

        try:
            cursor.execute(
                """
                SELECT
                    user_id,
                    full_name,
                    username,
                    email,
                    password_hash,
                    role
                FROM users
                WHERE username = %s OR email = %s
                LIMIT 1
                """,
                (username_or_email, username_or_email.lower())
            )

            user = cursor.fetchone()

            if user and check_password_hash(user[4], password):
                user_role = str(user[5]).strip().lower()

                if user_role == "admin":
                    account = Admin(
                        user_id=user[0],
                        full_name=user[1],
                        username=user[2],
                        email=user[3],
                        password_hash=user[4]
                    )

                elif user_role == "customer":
                    account = Customer(
                        user_id=user[0],
                        full_name=user[1],
                        username=user[2],
                        email=user[3],
                        password_hash=user[4]
                    )

                else:
                    flash("This account has an invalid role.", "error")
                    return redirect(url_for("login"))

                session.clear()
                session.permanent = True
                session["user_id"] = account.user_id
                session["full_name"] = account.full_name
                session["username"] = account.username
                session["role"] = account.role

                print("LOGIN USER ROLE:", repr(session.get("role")))

                flash(
                    "Login successful! Welcome, "
                    + account.full_name + ".",
                    "success"
                )

                if account.role == "admin":
                    return redirect(url_for("admin_dashboard"))

                elif account.role == "customer":
                    return redirect(url_for("customer_dashboard"))

            else:
                flash(
                    "Invalid username/email or password.",
                    "error"
                )

        except Exception as error:
            print("Login Error:", error)
            flash(
                "Something went wrong. Please try again.",
                "error"
            )

        finally:
            cursor.close()

    return render_template("login.html", form=form)


# FORGOT PASSWORD

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()

        if not email:
            flash("Please enter your email address.", "error")
            return render_template("forgot_password.html")

        cursor = mysql.connection.cursor()

        try:
            cursor.execute("""
                SELECT user_id
                FROM users
                WHERE email = %s
                AND role = 'customer'
            """, (email,))

            user = cursor.fetchone()

            if not user:
                flash(
                    "If an eligible account exists, a password reset code will be sent.",
                    "success"
                )
                return render_template("forgot_password.html")

            user_id = user[0]

            # Generate six-digit reset OTP
            otp = f"{secrets.randbelow(1000000):06d}"
            otp_hash = generate_password_hash(otp)

            now = datetime.now()
            expires_at = now + timedelta(minutes=5)

            # Check existing reset request
            cursor.execute("""
                SELECT reset_id, last_sent_at
                FROM password_resets
                WHERE user_id = %s
            """, (user_id,))

            existing_reset = cursor.fetchone()

            if existing_reset:

                elapsed = (
                    now - existing_reset[1]
                ).total_seconds()

                if elapsed < 60:
                    flash(
                        "Please wait before requesting another reset code.",
                        "error"
                    )
                    return render_template("forgot_password.html")

                cursor.execute("""
                    UPDATE password_resets
                    SET otp_hash = %s,
                        expires_at = %s,
                        attempts = 0,
                        last_sent_at = %s
                    WHERE reset_id = %s
                """, (
                    otp_hash,
                    expires_at,
                    now,
                    existing_reset[0]
                ))

            else:

                cursor.execute("""
                    INSERT INTO password_resets
                    (
                        user_id,
                        otp_hash,
                        expires_at,
                        attempts,
                        last_sent_at
                    )
                    VALUES (%s, %s, %s, %s, %s)
                """, (
                    user_id,
                    otp_hash,
                    expires_at,
                    0,
                    now
                ))

            mysql.connection.commit()

            # Send password reset OTP
            email_sent = send_otp_email(email, otp)

            if not email_sent:

                cursor.execute("""
                    DELETE FROM password_resets
                    WHERE user_id = %s
                """, (user_id,))

                mysql.connection.commit()

                flash(
                    "Unable to send reset code. Please try again later.",
                    "error"
                )

                return render_template("forgot_password.html")

            flash(
                "If an eligible account exists, a password reset code has been sent.",
                "success"
            )

            return redirect(
                url_for("reset_password", email=email)
            )

        except Exception as error:
            mysql.connection.rollback()
            print("Forgot Password Error:", error)

            flash(
                "Something went wrong. Please try again.",
                "error"
            )

        finally:
            cursor.close()

    return render_template("forgot_password.html")


# RESET PASSWORD

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():

    email = request.args.get("email", "").strip().lower()

    if not email:
        flash("Invalid password reset request.", "error")
        return redirect(url_for("forgot_password"))

    cursor = mysql.connection.cursor()

    try:
        cursor.execute("""
            SELECT
                pr.reset_id,
                pr.otp_hash,
                pr.expires_at,
                pr.attempts,
                u.user_id
            FROM password_resets pr
            INNER JOIN users u
                ON pr.user_id = u.user_id
            WHERE u.email = %s
            AND u.role = 'customer'
        """, (email,))

        reset = cursor.fetchone()

        if not reset:
            flash(
                "Password reset request not found. Please request a new code.",
                "error"
            )
            return redirect(url_for("forgot_password"))

        if request.method == "POST":

            otp = request.form.get("otp", "").strip()
            new_password = request.form.get("new_password", "")
            confirm_password = request.form.get("confirm_password", "")

            if not otp.isdigit() or len(otp) != 6:
                flash(
                    "Please enter a valid 6-digit verification code.",
                    "error"
                )
                return render_template(
                    "reset_password.html",
                    email=email
                )

            if datetime.now() >= reset[2]:
                flash(
                    "Your reset code has expired. Please request a new code.",
                    "error"
                )
                return render_template(
                    "reset_password.html",
                    email=email
                )

            if reset[3] >= 5:
                flash(
                    "Maximum verification attempts reached. Please request a new code.",
                    "error"
                )
                return render_template(
                    "reset_password.html",
                    email=email
                )

            if not check_password_hash(reset[1], otp):

                cursor.execute("""
                    UPDATE password_resets
                    SET attempts = attempts + 1
                    WHERE reset_id = %s
                """, (reset[0],))

                mysql.connection.commit()

                flash(
                    "Incorrect verification code. Please try again.",
                    "error"
                )

                return render_template(
                    "reset_password.html",
                    email=email
                )

            if len(new_password) < 8:
                flash(
                    "Password must be at least 8 characters.",
                    "error"
                )
                return render_template(
                    "reset_password.html",
                    email=email
                )

            if new_password != confirm_password:
                flash(
                    "Passwords do not match.",
                    "error"
                )
                return render_template(
                    "reset_password.html",
                    email=email
                )

            new_password_hash = generate_password_hash(
                new_password
            )

            cursor.execute("""
                UPDATE users
                SET password_hash = %s
                WHERE user_id = %s
            """, (
                new_password_hash,
                reset[4]
            ))

            # Delete reset request after successful password update
            cursor.execute("""
                DELETE FROM password_resets
                WHERE reset_id = %s
            """, (reset[0],))

            mysql.connection.commit()

            flash(
                "Your password has been reset successfully. You can now log in.",
                "success"
            )

            return redirect(url_for("login"))

        return render_template(
            "reset_password.html",
            email=email
        )

    except Exception as error:
        mysql.connection.rollback()
        print("Reset Password Error:", error)

        flash(
            "Unable to reset your password. Please try again.",
            "error"
        )

        return redirect(url_for("forgot_password"))

    finally:
        cursor.close()


# =========================
# GENERAL DASHBOARD REDIRECT
# =========================

@app.route("/dashboard")
@login_required
def dashboard():
    current_role = str(
        session.get("role", "")
    ).strip().lower()

    if current_role == "admin":
        return redirect(url_for("admin_dashboard"))

    if current_role == "customer":
        return redirect(url_for("customer_dashboard"))

    session.clear()
    flash("Invalid account role. Please log in again.", "error")
    return redirect(url_for("login"))


# =========================
# ADMIN DASHBOARD
# =========================


@app.route("/admin/dashboard")
@login_required
@role_required("admin")
def admin_dashboard():
    cursor = mysql.connection.cursor()

    try:
        # Total Products
        cursor.execute("""
            SELECT COUNT(*)
            FROM products
        """)
        total_products = cursor.fetchone()[0]

        # Low-Stock Products
        cursor.execute("""
            SELECT COUNT(DISTINCT product_id)
            FROM product_variants
            WHERE stock_quantity > 0
            AND stock_quantity <= low_stock_threshold
        """)
        low_stock_products = cursor.fetchone()[0]

        # Pending Orders
        cursor.execute("""
            SELECT COUNT(*)
            FROM orders
            WHERE order_status = 'pending'
        """)
        pending_orders = cursor.fetchone()[0]

        # Total Recorded Sales
        cursor.execute("""
            SELECT COALESCE(SUM(total_amount), 0)
            FROM sales
        """)
        total_sales = cursor.fetchone()[0]

        # Recent Orders
        cursor.execute("""
            SELECT
                o.order_id,
                o.order_date,
                u.full_name,
                o.total_amount,
                o.order_status
            FROM orders o
            LEFT JOIN users u
                ON o.customer_id = u.user_id
            ORDER BY o.order_date DESC
            LIMIT 5
        """)
        recent_orders = cursor.fetchall()

        return render_template(
            "admin_dashboard.html",
            full_name=session["full_name"],
            username=session["username"],
            role=session["role"],
            total_products=total_products,
            low_stock_products=low_stock_products,
            pending_orders=pending_orders,
            total_sales=total_sales,
            recent_orders=recent_orders
        )

    except Exception as error:
        print("Admin Dashboard Error:", error)
        flash("Unable to load dashboard information.", "error")
        return redirect(url_for("admin_dashboard"))

    finally:
        cursor.close()

# =========================
# CUSTOMER DASHBOARD
# =========================

@app.route("/customer/dashboard")
@login_required
@role_required("customer")
def customer_dashboard():
    return render_template(
        "customer_dashboard.html",
        full_name=session["full_name"],
        username=session["username"],
        role=session["role"]
    )


# CATEGORY MANAGEMENT

@app.route("/admin/categories")
@login_required
@role_required("admin")
def manage_categories():
    cursor = mysql.connection.cursor()

    try:
        cursor.execute("""
            SELECT category_id, category_name, description, created_at
            FROM categories
            ORDER BY category_name ASC
        """)

        categories = cursor.fetchall()

        return render_template(
            "categories.html",
            categories=categories
        )

    except Exception as error:
        print("Category Loading Error:", error)
        flash("Unable to load categories.", "error")
        return redirect(url_for("admin_dashboard"))

    finally:
        cursor.close()


@app.route("/admin/categories/add", methods=["GET", "POST"])
@login_required
@role_required("admin")
def add_category():
    form = CategoryForm()

    if form.validate_on_submit():
        category_name = form.category_name.data.strip()
        description = form.description.data.strip() or None

        cursor = mysql.connection.cursor()

        try:
            cursor.execute("""
                SELECT category_id
                FROM categories
                WHERE LOWER(category_name) = LOWER(%s)
            """, (category_name,))

            if cursor.fetchone():
                flash("This category already exists.", "error")
                return render_template(
                    "add_category.html",
                    form=form
                )

            cursor.execute("""
                INSERT INTO categories (category_name, description)
                VALUES (%s, %s)
            """, (category_name, description))

            mysql.connection.commit()

            flash("Category added successfully!", "success")
            return redirect(url_for("manage_categories"))

        except Exception as error:
            mysql.connection.rollback()
            print("Add Category Error:", error)
            flash("Unable to add category.", "error")

        finally:
            cursor.close()

    return render_template("add_category.html", form=form)


@app.route("/admin/categories/edit/<int:category_id>", methods=["GET", "POST"])
@login_required
@role_required("admin")
def edit_category(category_id):
    cursor = mysql.connection.cursor()

    try:
        cursor.execute("""
            SELECT category_name, description
            FROM categories
            WHERE category_id = %s
        """, (category_id,))

        category = cursor.fetchone()

        if not category:
            flash("Category not found.", "error")
            return redirect(url_for("manage_categories"))

        form = CategoryForm()

        if form.validate_on_submit():
            category_name = form.category_name.data.strip()
            description = form.description.data.strip() or None

            cursor.execute("""
                SELECT category_id
                FROM categories
                WHERE LOWER(category_name) = LOWER(%s)
                AND category_id != %s
            """, (category_name, category_id))

            if cursor.fetchone():
                flash("Another category already uses that name.", "error")
                return render_template(
                    "edit_category.html",
                    form=form,
                    category_id=category_id
                )

            cursor.execute("""
                UPDATE categories
                SET category_name = %s,
                    description = %s
                WHERE category_id = %s
            """, (category_name, description, category_id))

            mysql.connection.commit()

            flash("Category updated successfully!", "success")
            return redirect(url_for("manage_categories"))

        if not form.is_submitted():
            form.category_name.data = category[0]
            form.description.data = category[1] or ""

        return render_template(
            "edit_category.html",
            form=form,
            category_id=category_id
        )

    except Exception as error:
        mysql.connection.rollback()
        print("Edit Category Error:", error)
        flash("Unable to edit category.", "error")
        return redirect(url_for("manage_categories"))

    finally:
        cursor.close()


@app.route("/admin/categories/delete/<int:category_id>", methods=["POST"])
@login_required
@role_required("admin")
def delete_category(category_id):
    cursor = mysql.connection.cursor()

    try:
        cursor.execute("""
            SELECT category_id
            FROM categories
            WHERE category_id = %s
        """, (category_id,))

        if not cursor.fetchone():
            flash("Category not found.", "error")
            return redirect(url_for("manage_categories"))

        cursor.execute("""
            SELECT COUNT(*)
            FROM products
            WHERE category_id = %s
        """, (category_id,))

        product_count = cursor.fetchone()[0]

        if product_count > 0:
            flash(
                "This category cannot be deleted because it has products.",
                "error"
            )
            return redirect(url_for("manage_categories"))

        cursor.execute("""
            DELETE FROM categories
            WHERE category_id = %s
        """, (category_id,))

        mysql.connection.commit()

        flash("Category deleted successfully!", "success")

    except Exception as error:
        mysql.connection.rollback()
        print("Delete Category Error:", error)
        flash("Unable to delete category.", "error")

    finally:
        cursor.close()

    return redirect(url_for("manage_categories"))


# =========================
# PRODUCT MANAGEMENT
# =========================

@app.route("/admin/products")
@login_required
@role_required("admin")
def manage_products():
    cursor = mysql.connection.cursor()

    try:
        cursor.execute("""
            SELECT
                p.product_id,
                p.product_name,
                c.category_name,
                p.description,
                p.is_available
            FROM products p
            INNER JOIN categories c
                ON p.category_id = c.category_id
            ORDER BY c.category_name, p.product_name
        """)

        products = cursor.fetchall()

        return render_template(
            "products.html",
            products=products
        )

    except Exception as error:
        print("Product Loading Error:", error)
        flash("Unable to load products.", "error")
        return redirect(url_for("admin_dashboard"))

    finally:
        cursor.close()


@app.route("/admin/products/add", methods=["GET", "POST"])
@login_required
@role_required("admin")
def add_product():
    form = ProductForm()
    cursor = mysql.connection.cursor()

    try:
        cursor.execute("""
            SELECT category_id, category_name
            FROM categories
            ORDER BY category_name
        """)

        categories = cursor.fetchall()
        form.category_id.choices = categories

        if not form.is_submitted():
            form.is_available.data = True

        if form.validate_on_submit():
            cursor.execute("""
                INSERT INTO products
                (category_id, product_name, description, is_available)
                VALUES (%s, %s, %s, %s)
            """, (
                form.category_id.data,
                form.product_name.data.strip(),
                form.description.data.strip() or None,
                form.is_available.data
            ))

            mysql.connection.commit()

            flash("Product added successfully!", "success")
            return redirect(url_for("manage_products"))

        return render_template("add_product.html", form=form)

    except Exception as error:
        mysql.connection.rollback()
        print("Add Product Error:", error)
        flash("Unable to add product.", "error")
        return redirect(url_for("manage_products"))

    finally:
        cursor.close()


@app.route("/admin/products/edit/<int:product_id>", methods=["GET", "POST"])
@login_required
@role_required("admin")
def edit_product(product_id):
    cursor = mysql.connection.cursor()

    try:
        cursor.execute("""
            SELECT
                product_id,
                category_id,
                product_name,
                description,
                is_available
            FROM products
            WHERE product_id = %s
        """, (product_id,))

        product = cursor.fetchone()

        if not product:
            flash("Product not found.", "error")
            return redirect(url_for("manage_products"))

        cursor.execute("""
            SELECT category_id, category_name
            FROM categories
            ORDER BY category_name
        """)

        categories = cursor.fetchall()

        form = ProductForm()
        form.category_id.choices = categories

        if form.validate_on_submit():
            cursor.execute("""
                UPDATE products
                SET category_id = %s,
                    product_name = %s,
                    description = %s,
                    is_available = %s
                WHERE product_id = %s
            """, (
                form.category_id.data,
                form.product_name.data.strip(),
                form.description.data.strip() or None,
                form.is_available.data,
                product_id
            ))

            mysql.connection.commit()

            flash("Product updated successfully!", "success")
            return redirect(url_for("manage_products"))

        if not form.is_submitted():
            form.category_id.data = product[1]
            form.product_name.data = product[2]
            form.description.data = product[3] or ""
            form.is_available.data = bool(product[4])

        return render_template(
            "edit_product.html",
            form=form,
            product_id=product_id
        )

    except Exception as error:
        mysql.connection.rollback()
        print("Edit Product Error:", error)
        flash("Unable to edit product.", "error")
        return redirect(url_for("manage_products"))

    finally:
        cursor.close()


@app.route("/admin/products/delete/<int:product_id>", methods=["POST"])
@login_required
@role_required("admin")
def delete_product(product_id):
    cursor = mysql.connection.cursor()

    try:
        cursor.execute("""
            SELECT product_id
            FROM products
            WHERE product_id = %s
        """, (product_id,))

        if not cursor.fetchone():
            flash("Product not found.", "error")
            return redirect(url_for("manage_products"))

        cursor.execute("""
            SELECT COUNT(*)
            FROM product_variants
            WHERE product_id = %s
        """, (product_id,))

        variant_count = cursor.fetchone()[0]

        if variant_count > 0:
            flash(
                "This product cannot be deleted because it has product variants.",
                "error"
            )
            return redirect(url_for("manage_products"))

        cursor.execute("""
            DELETE FROM products
            WHERE product_id = %s
        """, (product_id,))

        mysql.connection.commit()

        flash("Product deleted successfully!", "success")

    except Exception as error:
        mysql.connection.rollback()
        print("Delete Product Error:", error)
        flash("Unable to delete product.", "error")

    finally:
        cursor.close()

    return redirect(url_for("manage_products"))


# =========================
# PRODUCT VARIANT MANAGEMENT
# =========================

@app.route("/admin/variants")
@login_required
@role_required("admin")
def manage_variants():
    cursor = mysql.connection.cursor()

    try:
        cursor.execute("""
            SELECT
                pv.variant_id,
                p.product_name,
                pv.variant_name,
                pv.price,
                pv.stock_quantity,
                pv.low_stock_threshold,
                pv.is_available
            FROM product_variants pv
            INNER JOIN products p
                ON pv.product_id = p.product_id
            ORDER BY p.product_name, pv.variant_name
        """)

        variants = cursor.fetchall()

        return render_template(
            "variants.html",
            variants=variants
        )

    except Exception as error:
        print("Variant Loading Error:", error)
        flash("Unable to load product variants.", "error")
        return redirect(url_for("admin_dashboard"))

    finally:
        cursor.close()


@app.route("/admin/variants/add", methods=["GET", "POST"])
@login_required
@role_required("admin")
def add_variant():
    form = ProductVariantForm()
    cursor = mysql.connection.cursor()

    try:
        cursor.execute("""
            SELECT product_id, product_name
            FROM products
            ORDER BY product_name
        """)

        products = cursor.fetchall()
        form.product_id.choices = products

        if not form.is_submitted():
            form.is_available.data = True

        if form.validate_on_submit():
            product_id = form.product_id.data
            variant_name = form.variant_name.data.strip()

            cursor.execute("""
                SELECT variant_id
                FROM product_variants
                WHERE product_id = %s
                AND LOWER(variant_name) = LOWER(%s)
            """, (product_id, variant_name))

            if cursor.fetchone():
                flash("This variant already exists for the selected product.", "error")
                return render_template("add_variant.html", form=form)

            cursor.execute("""
                INSERT INTO product_variants
                (
                    product_id,
                    variant_name,
                    price,
                    stock_quantity,
                    low_stock_threshold,
                    is_available
                )
                VALUES (%s, %s, %s, 0, %s, %s)
            """, (
                product_id,
                variant_name,
                form.price.data,
                form.low_stock_threshold.data,
                form.is_available.data
            ))

            mysql.connection.commit()

            flash("Product variant added successfully!", "success")
            return redirect(url_for("manage_variants"))

        return render_template("add_variant.html", form=form)

    except Exception as error:
        mysql.connection.rollback()
        print("Add Variant Error:", error)
        flash("Unable to add product variant.", "error")
        return redirect(url_for("manage_variants"))

    finally:
        cursor.close()


@app.route("/admin/variants/edit/<int:variant_id>", methods=["GET", "POST"])
@login_required
@role_required("admin")
def edit_variant(variant_id):
    cursor = mysql.connection.cursor()

    try:
        cursor.execute("""
            SELECT
                variant_id,
                product_id,
                variant_name,
                price,
                low_stock_threshold,
                is_available
            FROM product_variants
            WHERE variant_id = %s
        """, (variant_id,))

        variant = cursor.fetchone()

        if not variant:
            flash("Product variant not found.", "error")
            return redirect(url_for("manage_variants"))

        cursor.execute("""
            SELECT product_id, product_name
            FROM products
            ORDER BY product_name
        """)

        products = cursor.fetchall()

        form = ProductVariantForm()
        form.product_id.choices = products

        if form.validate_on_submit():
            product_id = form.product_id.data
            variant_name = form.variant_name.data.strip()

            cursor.execute("""
                SELECT variant_id
                FROM product_variants
                WHERE product_id = %s
                AND LOWER(variant_name) = LOWER(%s)
                AND variant_id != %s
            """, (product_id, variant_name, variant_id))

            if cursor.fetchone():
                flash("This variant already exists for the selected product.", "error")
                return render_template(
                    "edit_variant.html",
                    form=form,
                    variant_id=variant_id
                )

            cursor.execute("""
                UPDATE product_variants
                SET product_id = %s,
                    variant_name = %s,
                    price = %s,
                    low_stock_threshold = %s,
                    is_available = %s
                WHERE variant_id = %s
            """, (
                product_id,
                variant_name,
                form.price.data,
                form.low_stock_threshold.data,
                form.is_available.data,
                variant_id
            ))

            mysql.connection.commit()

            flash("Product variant updated successfully!", "success")
            return redirect(url_for("manage_variants"))

        if not form.is_submitted():
            form.product_id.data = variant[1]
            form.variant_name.data = variant[2]
            form.price.data = variant[3]
            form.low_stock_threshold.data = variant[4]
            form.is_available.data = bool(variant[5])

        return render_template(
            "edit_variant.html",
            form=form,
            variant_id=variant_id
        )

    except Exception as error:
        mysql.connection.rollback()
        print("Edit Variant Error:", error)
        flash("Unable to edit product variant.", "error")
        return redirect(url_for("manage_variants"))

    finally:
        cursor.close()


@app.route("/admin/variants/delete/<int:variant_id>", methods=["POST"])
@login_required
@role_required("admin")
def delete_variant(variant_id):
    cursor = mysql.connection.cursor()

    try:
        cursor.execute("""
            SELECT stock_quantity
            FROM product_variants
            WHERE variant_id = %s
        """, (variant_id,))

        variant = cursor.fetchone()

        if not variant:
            flash("Product variant not found.", "error")
            return redirect(url_for("manage_variants"))

        if variant[0] > 0:
            flash(
                "This variant has remaining stock. Adjust its inventory before deleting.",
                "error"
            )
            return redirect(url_for("manage_variants"))

        cursor.execute("""
            SELECT COUNT(*)
            FROM order_items
            WHERE variant_id = %s
        """, (variant_id,))

        order_count = cursor.fetchone()[0]

        cursor.execute("""
            SELECT COUNT(*)
            FROM inventory_transactions
            WHERE variant_id = %s
        """, (variant_id,))

        transaction_count = cursor.fetchone()[0]

        if order_count > 0 or transaction_count > 0:
            flash(
                "This variant has order or inventory history and cannot be deleted.",
                "error"
            )
            return redirect(url_for("manage_variants"))

        cursor.execute("""
            DELETE FROM product_variants
            WHERE variant_id = %s
        """, (variant_id,))

        mysql.connection.commit()

        flash("Product variant deleted successfully!", "success")

    except Exception as error:
        mysql.connection.rollback()
        print("Delete Variant Error:", error)
        flash("Unable to delete product variant.", "error")

    finally:
        cursor.close()

    return redirect(url_for("manage_variants"))

# =========================
# INVENTORY MANAGEMENT
# =========================


@app.route("/admin/inventory")
@login_required
@role_required("admin")
def manage_inventory():
    cursor = mysql.connection.cursor()

    try:
        cursor.execute("""
            SELECT
                pv.variant_id,
                p.product_name,
                pv.variant_name,
                pv.price,
                pv.stock_quantity,
                pv.low_stock_threshold
            FROM product_variants pv
            INNER JOIN products p
                ON pv.product_id = p.product_id
            ORDER BY p.product_name, pv.variant_name
        """)

        inventory_rows = cursor.fetchall()
        inventory = []

        for row in inventory_rows:
            variant = ProductVariant(
                variant_id=row[0],
                product_name=row[1],
                variant_name=row[2],
                price=row[3],
                stock_quantity=row[4],
                low_stock_threshold=row[5]
            )

            inventory.append((
                variant.variant_id,
                variant.product_name,
                variant.variant_name,
                variant.price,
                variant.stock_quantity,
                variant.low_stock_threshold,
                variant.stock_status
            ))

        return render_template(
            "inventory.html",
            inventory=inventory
        )

    except Exception as error:
        print("Inventory Loading Error:", error)
        flash("Unable to load inventory.", "error")
        return redirect(url_for("admin_dashboard"))

    finally:
        cursor.close()





@app.route("/admin/inventory/update", methods=["GET", "POST"])
@login_required
@role_required("admin")
def update_inventory():
    form = InventoryForm()
    cursor = mysql.connection.cursor()

    try:
        cursor.execute("""
            SELECT
                pv.variant_id,
                CONCAT(
                    p.product_name,
                    ' - ',
                    pv.variant_name,
                    ' (Stock: ',
                    pv.stock_quantity,
                    ')'
                )
            FROM product_variants pv
            INNER JOIN products p
                ON pv.product_id = p.product_id
            ORDER BY p.product_name, pv.variant_name
        """)

        form.variant_id.choices = cursor.fetchall()

        if form.validate_on_submit():
            variant_id = form.variant_id.data
            transaction_type = form.transaction_type.data

            if transaction_type not in (
                "stock_in",
                "adjustment_increase",
                "adjustment_decrease"
            ):
                flash("Invalid inventory transaction type.", "error")
                return render_template(
                    "update_inventory.html",
                    form=form
                )

            quantity = form.quantity.data
            remarks = form.remarks.data.strip() if form.remarks.data else ""

            # Start database transaction
            mysql.connection.begin()

            cursor.execute("""
                SELECT stock_quantity
                FROM product_variants
                WHERE variant_id = %s
                FOR UPDATE
            """, (variant_id,))

            variant = cursor.fetchone()

            if not variant:
                mysql.connection.rollback()
                flash("Selected product variant was not found.", "error")
                return render_template(
                    "update_inventory.html",
                    form=form
                )

            current_stock = variant[0]

            if transaction_type == "stock_in":
                new_stock = current_stock + quantity
                database_type = "stock_in"
                final_remarks = remarks or "Stock added."

            elif transaction_type == "adjustment_increase":
                new_stock = current_stock + quantity
                database_type = "adjustment"
                final_remarks = remarks or "Stock increased through adjustment."

            else:
                if quantity > current_stock:
                    mysql.connection.rollback()
                    flash(
                        "Insufficient stock. The quantity cannot exceed current stock.",
                        "error"
                    )
                    return render_template(
                        "update_inventory.html",
                        form=form
                    )

                new_stock = current_stock - quantity
                database_type = "adjustment"
                final_remarks = remarks or "Stock decreased through adjustment."

            cursor.execute("""
                UPDATE product_variants
                SET stock_quantity = %s
                WHERE variant_id = %s
            """, (new_stock, variant_id))

            cursor.execute("""
                INSERT INTO inventory_transactions
                (
                    variant_id,
                    transaction_type,
                    quantity,
                    remarks
                )
                VALUES (%s, %s, %s, %s)
            """, (
                variant_id,
                database_type,
                quantity,
                final_remarks
            ))

            mysql.connection.commit()

            flash("Inventory successfully updated!", "success")
            return redirect(url_for("manage_inventory"))

        return render_template(
            "update_inventory.html",
            form=form
        )

    except Exception as error:
        mysql.connection.rollback()
        print("Inventory Update Error:", error)
        flash("Unable to update inventory.", "error")
        return redirect(url_for("manage_inventory"))

    finally:
        cursor.close()




@app.route("/admin/inventory/history")
@login_required
@role_required("admin")
def inventory_history():
    cursor = mysql.connection.cursor()

    try:
        cursor.execute("""
            SELECT
                it.transaction_id,
                p.product_name,
                pv.variant_name,
                it.transaction_type,
                it.quantity,
                pv.stock_quantity,
                it.remarks,
                it.created_at
            FROM inventory_transactions it
            INNER JOIN product_variants pv
                ON it.variant_id = pv.variant_id
            INNER JOIN products p
                ON pv.product_id = p.product_id
            ORDER BY it.created_at DESC, it.transaction_id DESC
        """)

        transactions = cursor.fetchall()

        return render_template(
            "inventory_history.html",
            transactions=transactions
        )

    except Exception as error:
        print("Inventory History Error:", error)
        flash("Unable to load inventory history.", "error")
        return redirect(url_for("manage_inventory"))

    finally:
        cursor.close()
        


# ADD-ONS MANAGEMENT

@app.route("/admin/addons")
@login_required
@role_required("admin")
def addons():
    cursor = mysql.connection.cursor()

    try:
        cursor.execute("""
            SELECT
                a.addon_id,
                a.addon_name,
                c.category_name,
                a.price,
                a.is_available
            FROM addons a
            JOIN categories c
                ON a.category_id = c.category_id
            ORDER BY c.category_name, a.addon_name
        """)

        addon_list = cursor.fetchall()

        return render_template(
            "addons.html",
            addons=addon_list
        )

    except Exception as error:
        print("Add-ons List Error:", error)
        flash("Unable to load add-ons.", "error")
        return redirect(url_for("admin_dashboard"))

    finally:
        cursor.close()


@app.route("/admin/addons/add", methods=["GET", "POST"])
@login_required
@role_required("admin")
def add_addon():
    form = AddonForm()

    cursor = mysql.connection.cursor()

    try:
        cursor.execute("""
            SELECT category_id, category_name
            FROM categories
            ORDER BY category_name
        """)

        categories = cursor.fetchall()

        form.category_id.choices = [
            (category[0], category[1])
            for category in categories
        ]

        if form.validate_on_submit():
            category_id = form.category_id.data
            addon_name = form.addon_name.data.strip()
            price = form.price.data
            is_available = 1 if form.is_available.data else 0

            cursor.execute("""
                SELECT addon_id
                FROM addons
                WHERE category_id = %s
                  AND addon_name = %s
            """, (category_id, addon_name))

            if cursor.fetchone():
                flash(
                    "This add-on already exists in the selected category.",
                    "error"
                )
            else:
                cursor.execute("""
                    INSERT INTO addons
                    (category_id, addon_name, price, is_available)
                    VALUES (%s, %s, %s, %s)
                """, (
                    category_id,
                    addon_name,
                    price,
                    is_available
                ))

                mysql.connection.commit()

                flash("Add-on added successfully!", "success")
                return redirect(url_for("addons"))

        return render_template("add_addon.html", form=form)

    except Exception as error:
        mysql.connection.rollback()
        print("Add Add-on Error:", error)
        flash("Unable to add add-on. Please try again.", "error")
        return redirect(url_for("addons"))

    finally:
        cursor.close()


@app.route(
    "/admin/addons/edit/<int:addon_id>",
    methods=["GET", "POST"]
)
@login_required
@role_required("admin")
def edit_addon(addon_id):
    form = AddonForm()
    cursor = mysql.connection.cursor()

    try:
        cursor.execute("""
            SELECT addon_id, category_id, addon_name,
                   price, is_available
            FROM addons
            WHERE addon_id = %s
        """, (addon_id,))

        addon = cursor.fetchone()

        if not addon:
            flash("Add-on not found.", "error")
            return redirect(url_for("addons"))

        cursor.execute("""
            SELECT category_id, category_name
            FROM categories
            ORDER BY category_name
        """)

        categories = cursor.fetchall()

        form.category_id.choices = [
            (category[0], category[1])
            for category in categories
        ]

        if form.validate_on_submit():
            category_id = form.category_id.data
            addon_name = form.addon_name.data.strip()
            price = form.price.data
            is_available = 1 if form.is_available.data else 0

            cursor.execute("""
                SELECT addon_id
                FROM addons
                WHERE category_id = %s
                  AND addon_name = %s
                  AND addon_id != %s
            """, (category_id, addon_name, addon_id))

            if cursor.fetchone():
                flash(
                    "This add-on already exists in the selected category.",
                    "error"
                )
            else:
                cursor.execute("""
                    UPDATE addons
                    SET category_id = %s,
                        addon_name = %s,
                        price = %s,
                        is_available = %s
                    WHERE addon_id = %s
                """, (
                    category_id,
                    addon_name,
                    price,
                    is_available,
                    addon_id
                ))

                mysql.connection.commit()

                flash("Add-on updated successfully!", "success")
                return redirect(url_for("addons"))

        elif not form.is_submitted():
            form.category_id.data = addon[1]
            form.addon_name.data = addon[2]
            form.price.data = addon[3]
            form.is_available.data = bool(addon[4])

        return render_template(
            "edit_addon.html",
            form=form,
            addon=addon
        )

    except Exception as error:
        mysql.connection.rollback()
        print("Edit Add-on Error:", error)
        flash("Unable to update add-on.", "error")
        return redirect(url_for("addons"))

    finally:
        cursor.close()


@app.route(
    "/admin/addons/delete/<int:addon_id>",
    methods=["POST"]
)
@login_required
@role_required("admin")
def delete_addon(addon_id):
    cursor = mysql.connection.cursor()

    try:
        cursor.execute("""
            SELECT addon_id
            FROM addons
            WHERE addon_id = %s
        """, (addon_id,))

        addon = cursor.fetchone()

        if not addon:
            flash("Add-on not found.", "error")
            return redirect(url_for("addons"))

        cursor.execute("""
            SELECT COUNT(*)
            FROM order_item_addons
            WHERE addon_id = %s
        """, (addon_id,))

        usage_count = cursor.fetchone()[0]

        if usage_count > 0:
            flash(
                "This add-on cannot be deleted because it is already used in an order.",
                "error"
            )
        else:
            cursor.execute("""
                DELETE FROM addons
                WHERE addon_id = %s
            """, (addon_id,))

            mysql.connection.commit()
            flash("Add-on deleted successfully!", "success")

        return redirect(url_for("addons"))

    except Exception as error:
        mysql.connection.rollback()
        print("Delete Add-on Error:", error)
        flash("Unable to delete add-on.", "error")
        return redirect(url_for("addons"))

    finally:
         cursor.close()

# =========================
# ORDER MANAGEMENT
# =========================

@app.route("/admin/orders")
@login_required
@role_required("admin")
def admin_orders():
    cursor = mysql.connection.cursor()

    try:
        cursor.execute("""
            SELECT
                o.order_id,
                COALESCE(u.full_name, 'Walk-in Customer'),
                o.order_type,
                o.fulfillment_method,
                o.total_amount,
                o.order_status,
                o.order_date,
                COALESCE(p.payment_method, 'Not recorded'),
                COALESCE(p.payment_status, 'Not recorded')
            FROM orders o
            LEFT JOIN users u
                ON o.customer_id = u.user_id
            LEFT JOIN payments p
                ON o.order_id = p.order_id
            ORDER BY o.order_date DESC, o.order_id DESC
        """)

        order_list = cursor.fetchall()

        return render_template(
            "orders.html",
            orders=order_list
        )

    except Exception as error:
        print("Orders List Error:", error)
        flash("Unable to load orders.", "error")
        return redirect(url_for("admin_dashboard"))

    finally:
        cursor.close()


# CREATE ORDER

@app.route("/admin/orders/create", methods=["GET", "POST"])
@login_required
@role_required("admin")
def create_order():
    form = OrderForm()

    if form.validate_on_submit():
        session["order_draft"] = {
            "order_type": form.order_type.data,
            "fulfillment_method": form.fulfillment_method.data,
            "payment_method": form.payment_method.data
        }

        session.pop("order_cart", None)

        flash(
            "Order details saved. You can now add products.",
            "success"
        )

        return redirect(url_for("add_order_items"))

    return render_template(
        "create_order.html",
        form=form
    )


# ADD PRODUCTS TO ORDER

@app.route("/admin/orders/add-items", methods=["GET", "POST"])
@login_required
@role_required("admin")
def add_order_items():

    order_draft = session.get("order_draft")

    if not order_draft:
        flash("Please create an order first.", "error")
        return redirect(url_for("create_order"))

    form = OrderItemForm()
    cursor = mysql.connection.cursor()

    try:
        cursor.execute("""
            SELECT
                pv.variant_id,
                CONCAT(
                    p.product_name,
                    ' - ',
                    pv.variant_name,
                    ' (₱',
                    pv.price,
                    ')'
                )
            FROM product_variants pv
            INNER JOIN products p
                ON pv.product_id = p.product_id
            WHERE pv.is_available = 1
              AND p.is_available = 1
            ORDER BY p.product_name, pv.variant_name
        """)

        form.variant_id.choices = cursor.fetchall()

        if form.validate_on_submit():

            cursor.execute("""
                SELECT
                    pv.variant_id,
                    p.product_name,
                    pv.variant_name,
                    pv.price
                FROM product_variants pv
                INNER JOIN products p
                    ON pv.product_id = p.product_id
                WHERE pv.variant_id = %s
                  AND pv.is_available = 1
                  AND p.is_available = 1
            """, (form.variant_id.data,))

            product = cursor.fetchone()

            if not product:
                flash("Selected product is unavailable.", "error")

            else:
                cart = session.get("order_cart", [])

                existing_item = next(
                    (
                        item for item in cart
                        if item["variant_id"] == product[0]
                    ),
                    None
                )

                if existing_item:
                    existing_item["quantity"] += form.quantity.data
                    existing_item["subtotal"] = (
                        existing_item["unit_price"]
                        * existing_item["quantity"]
                    )

                else:
                    cart.append({
                        "variant_id": product[0],
                        "product_name": product[1],
                        "variant_name": product[2],
                        "quantity": form.quantity.data,
                        "unit_price": float(product[3]),
                        "subtotal": (
                            float(product[3]) * form.quantity.data
                        ),
                        "addons": []
                    })

                session["order_cart"] = cart
                session.modified = True

                flash(
                    "Product added to temporary order cart.",
                    "success"
                )

                return redirect(url_for("add_order_items"))

        cart = session.get("order_cart", [])

        total_amount = sum(
            item["subtotal"] +
            sum(
                addon["subtotal"]
                for addon in item.get("addons", [])
            ) * item["quantity"]
            for item in cart
        )

        return render_template(
            "add_order_items.html",
            form=form,
            cart=cart,
            total_amount=total_amount
        )

    except Exception as error:
        print("Add Order Items Error:", error)
        flash("Unable to load products.", "error")
        return redirect(url_for("create_order"))

    finally:
        cursor.close()


# ADD-ONS TO ORDER

@app.route("/admin/orders/add-ons/<int:variant_id>", methods=["GET", "POST"])
@login_required
@role_required("admin")
def add_order_addons(variant_id):

    cart = session.get("order_cart", [])

    selected_item = next(
        (
            item for item in cart
            if item["variant_id"] == variant_id
        ),
        None
    )

    if not selected_item:
        flash("Order item not found in cart.", "error")
        return redirect(url_for("add_order_items"))

    cursor = mysql.connection.cursor()

    try:
        cursor.execute("""
            SELECT c.category_id
            FROM product_variants pv
            INNER JOIN products p
                ON pv.product_id = p.product_id
            INNER JOIN categories c
                ON p.category_id = c.category_id
            WHERE pv.variant_id = %s
        """, (variant_id,))

        category = cursor.fetchone()

        if not category:
            flash("Product category not found.", "error")
            return redirect(url_for("add_order_items"))

        category_id = category[0]

        if category_id not in (9, 19):
            flash("This product does not have add-ons.", "error")
            return redirect(url_for("add_order_items"))

        cursor.execute("""
            SELECT addon_id, addon_name, price
            FROM addons
            WHERE category_id = %s
              AND is_available = 1
            ORDER BY addon_name
        """, (category_id,))

        available_addons = cursor.fetchall()

        if request.method == "POST":

            selected_addon_ids = request.form.getlist("addon_id")
            selected_addons = []

            for addon_id in selected_addon_ids:

                try:
                    addon_id = int(addon_id)
                    quantity = int(
                        request.form.get(f"quantity_{addon_id}", 1)
                    )
                except (ValueError, TypeError):
                    flash("Invalid add-on selection.", "error")
                    return redirect(
                        url_for(
                            "add_order_addons",
                            variant_id=variant_id
                        )
                    )

                if quantity < 1:
                    flash(
                        "Add-on quantity must be at least 1.",
                        "error"
                    )
                    return redirect(
                        url_for(
                            "add_order_addons",
                            variant_id=variant_id
                        )
                    )

                addon = next(
                    (
                        item for item in available_addons
                        if item[0] == addon_id
                    ),
                    None
                )

                if not addon:
                    flash("Invalid add-on selected.", "error")
                    return redirect(
                        url_for(
                            "add_order_addons",
                            variant_id=variant_id
                        )
                    )

                selected_addons.append({
                    "addon_id": addon[0],
                    "addon_name": addon[1],
                    "quantity": quantity,
                    "unit_price": float(addon[2]),
                    "subtotal": float(addon[2]) * quantity
                })

            selected_item["addons"] = selected_addons

            session["order_cart"] = cart
            session.modified = True

            flash("Add-ons saved successfully.", "success")
            return redirect(url_for("add_order_items"))

        return render_template(
            "add_order_addons.html",
            item=selected_item,
            addons=available_addons
        )

    except Exception as error:
        print("Add Order Add-ons Error:", error)
        flash("Unable to process add-ons.", "error")
        return redirect(url_for("add_order_items"))

    finally:
        cursor.close()


# REMOVE PRODUCT FROM TEMPORARY CART

@app.route("/admin/orders/remove-item/<int:variant_id>", methods=["POST"])
@login_required
@role_required("admin")
def remove_order_item(variant_id):

    cart = session.get("order_cart", [])

    updated_cart = [
        item for item in cart
        if item["variant_id"] != variant_id
    ]

    if len(updated_cart) == len(cart):
        flash("Product not found in order cart.", "error")
    else:
        session["order_cart"] = updated_cart
        session.modified = True
        flash("Product removed from order cart.", "success")

    return redirect(url_for("add_order_items"))


# UPDATE PRODUCT QUANTITY

@app.route("/admin/orders/update-quantity/<int:variant_id>", methods=["POST"])
@login_required
@role_required("admin")
def update_order_quantity(variant_id):

    cart = session.get("order_cart", [])

    try:
        new_quantity = int(request.form.get("quantity", 0))
    except (ValueError, TypeError):
        flash("Please enter a valid quantity.", "error")
        return redirect(url_for("add_order_items"))

    if new_quantity < 1:
        flash("Quantity must be at least 1.", "error")
        return redirect(url_for("add_order_items"))

    item_found = False

    for item in cart:
        if item["variant_id"] == variant_id:
            item["quantity"] = new_quantity
            item["subtotal"] = (
                item["unit_price"] * new_quantity
            )
            item_found = True
            break

    if item_found:
        session["order_cart"] = cart
        session.modified = True
        flash("Product quantity updated successfully.", "success")
    else:
        flash("Product not found in order cart.", "error")

    return redirect(url_for("add_order_items"))


# REVIEW ORDER

@app.route("/admin/orders/review")
@login_required
@role_required("admin")
def review_order():

    cart = session.get("order_cart", [])
    order_draft = session.get("order_draft")

    if not order_draft:
        flash("Please complete the order information first.", "error")
        return redirect(url_for("create_order"))

    if not cart:
        flash("Please add at least one product to the order.", "error")
        return redirect(url_for("add_order_items"))

    total_amount = sum(
        item["subtotal"] +
        sum(
            addon["subtotal"]
            for addon in item.get("addons", [])
        ) * item["quantity"]
        for item in cart
    )

    return render_template(
        "review_order.html",
        cart=cart,
        order_draft=order_draft,
        total_amount=total_amount
    )


# SAVE ORDER

@app.route("/admin/orders/place", methods=["POST"])
@login_required
@role_required("admin")
def place_order():

    cart = session.get("order_cart", [])
    order_draft = session.get("order_draft")

    if not order_draft or not cart:
        flash("Invalid order. Please review your order again.", "error")
        return redirect(url_for("create_order"))

    if order_draft["fulfillment_method"] == "delivery":
        flash(
            "Delivery orders are not yet available. Please select pickup.",
            "error"
        )
        return redirect(url_for("review_order"))

    connection = mysql.connection
    cursor = None

    try:
        connection.begin()
        cursor = connection.cursor()

        total_amount = Decimal("0.00")
        prepared_items = []

        for item in cart:

            variant_id = int(item["variant_id"])
            quantity = int(item["quantity"])

            if quantity < 1:
                raise ValueError("Invalid product quantity.")

            cursor.execute("""
                SELECT
                    pv.variant_name,
                    pv.price,
                    pv.stock_quantity,
                    pv.is_available,
                    p.product_name,
                    p.is_available,
                    p.category_id
                FROM product_variants pv
                JOIN products p
                    ON pv.product_id = p.product_id
                WHERE pv.variant_id = %s
                FOR UPDATE
            """, (variant_id,))

            variant = cursor.fetchone()

            if not variant:
                raise ValueError("A selected product was not found.")

            (
                variant_name,
                unit_price,
                stock_quantity,
                variant_available,
                product_name,
                product_available,
                category_id
            ) = variant

            if not variant_available or not product_available:
                raise ValueError(
                    f"{product_name} is currently unavailable."
                )

            if stock_quantity < quantity:
                raise ValueError(
                    f"Insufficient stock for {product_name} "
                    f"({variant_name}). Available stock: {stock_quantity}."
                )

            base_subtotal = Decimal(str(unit_price)) * quantity
            item_total = base_subtotal
            addon_data = []

            for addon in item.get("addons", []):

                addon_id = int(addon["addon_id"])
                addon_quantity = int(addon["quantity"])

                if addon_quantity < 1:
                    raise ValueError("Invalid add-on quantity.")

                cursor.execute("""
                    SELECT
                        addon_name,
                        price,
                        category_id,
                        is_available
                    FROM addons
                    WHERE addon_id = %s
                """, (addon_id,))

                addon_record = cursor.fetchone()

                if not addon_record:
                    raise ValueError("A selected add-on was not found.")

                (
                    addon_name,
                    addon_price,
                    addon_category_id,
                    addon_available
                ) = addon_record

                if not addon_available or addon_category_id != category_id:
                    raise ValueError(
                        f"{addon_name} is not available for this product."
                    )

                addon_price = Decimal(str(addon_price))

                addon_data.append({
                    "addon_id": addon_id,
                    "quantity": addon_quantity,
                    "unit_price": addon_price
                })

                item_total += (
                    addon_price * addon_quantity * quantity
                )

            total_amount += item_total

            prepared_items.append({
                "variant_id": variant_id,
                "product_name": product_name,
                "variant_name": variant_name,
                "quantity": quantity,
                "unit_price": Decimal(str(unit_price)),
                "subtotal": base_subtotal,
                "addons": addon_data
            })

        cursor.execute("""
            INSERT INTO orders (
                customer_id,
                encoded_by,
                order_type,
                fulfillment_method,
                total_amount,
                order_status
            )
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            None,
            session["user_id"],
            order_draft["order_type"],
            order_draft["fulfillment_method"],
            total_amount,
            "pending"
        ))

        order_id = cursor.lastrowid

        for item in prepared_items:

            cursor.execute("""
                INSERT INTO order_items (
                    order_id,
                    variant_id,
                    product_name,
                    variant_name,
                    quantity,
                    unit_price,
                    subtotal
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                order_id,
                item["variant_id"],
                item["product_name"],
                item["variant_name"],
                item["quantity"],
                item["unit_price"],
                item["subtotal"]
            ))

            order_item_id = cursor.lastrowid

            for addon in item["addons"]:

                cursor.execute("""
                    INSERT INTO order_item_addons (
                        order_item_id,
                        addon_id,
                        quantity,
                        unit_price
                    )
                    VALUES (%s, %s, %s, %s)
                """, (
                    order_item_id,
                    addon["addon_id"],
                    addon["quantity"],
                    addon["unit_price"]
                ))

        payment_status = (
            "pending_verification"
            if order_draft["payment_method"] == "gcash"
            else "pending"
        )

        cursor.execute("""
            INSERT INTO payments (
                order_id,
                payment_method,
                amount,
                payment_status
            )
            VALUES (%s, %s, %s, %s)
        """, (
            order_id,
            order_draft["payment_method"],
            total_amount,
            payment_status
        ))

        connection.commit()

        session.pop("order_cart", None)
        session.pop("order_draft", None)

        flash(
            f"Order #{order_id} saved successfully!",
            "success"
        )

        return redirect(url_for("admin_orders"))

    except ValueError as error:
        connection.rollback()
        flash(str(error), "error")
        return redirect(url_for("review_order"))

    except Exception as error:
        connection.rollback()
        print("ORDER SAVING ERROR:", error)
        flash("Unable to save the order. Please check the application error log.", "error")
        return redirect(url_for("review_order"))

    finally:
        if cursor:
            cursor.close()


# VIEW ORDER DETAILS


@app.route("/admin/orders/<int:order_id>")
@login_required
@role_required("admin")
def order_details(order_id):

    cursor = mysql.connection.cursor()

    try:
        cursor.execute("""
            SELECT
                o.order_id,
                COALESCE(u.full_name, 'Walk-in Customer'),
                o.order_type,
                o.fulfillment_method,
                o.total_amount,
                o.order_status,
                o.order_date,
                p.payment_method,
                p.payment_status,
                p.gcash_reference_number,
                p.gcash_proof_image
            FROM orders o
            LEFT JOIN users u
                ON o.customer_id = u.user_id
            LEFT JOIN payments p
                ON o.order_id = p.order_id
            WHERE o.order_id = %s
        """, (order_id,))

        order = cursor.fetchone()

        if not order:
            flash("Order not found.", "error")
            return redirect(url_for("admin_orders"))

        cursor.execute("""
            SELECT
                order_item_id,
                product_name,
                variant_name,
                quantity,
                unit_price,
                subtotal
            FROM order_items
            WHERE order_id = %s
            ORDER BY order_item_id
        """, (order_id,))

        item_records = cursor.fetchall()
        items = []

        for item in item_records:

            cursor.execute("""
                SELECT
                    a.addon_name,
                    oia.quantity,
                    oia.unit_price
                FROM order_item_addons oia
                INNER JOIN addons a
                    ON oia.addon_id = a.addon_id
                WHERE oia.order_item_id = %s
            """, (item[0],))

            addons = cursor.fetchall()

            items.append({
                "order_item_id": item[0],
                "product_name": item[1],
                "variant_name": item[2],
                "quantity": item[3],
                "unit_price": item[4],
                "subtotal": item[5],
                "addons": addons
            })

        cursor.execute("""
            SELECT
                d.delivery_address,
                d.delivery_fee,
                d.delivery_status,
                dl.location_name
            FROM deliveries d
            LEFT JOIN delivery_locations dl
                ON d.location_id = dl.location_id
            WHERE d.order_id = %s
        """, (order_id,))

        delivery = cursor.fetchone()

        return render_template(
            "order_details.html",
            order=order,
            items=items,
            delivery=delivery
        )

    except Exception as error:
        print("Order Details Error:", error)
        flash("Unable to load order details.", "error")
        return redirect(url_for("admin_orders"))

    finally:
        cursor.close()



@app.route("/admin/orders/gcash-proof/<int:order_id>")
@login_required
@role_required("admin")
def view_gcash_proof(order_id):

    cursor = mysql.connection.cursor()

    try:
        cursor.execute("""
            SELECT gcash_proof_image
            FROM payments
            WHERE order_id = %s
              AND payment_method = 'gcash'
        """, (order_id,))

        payment = cursor.fetchone()

        if not payment or not payment[0]:
            flash("No GCash proof of payment found.", "error")
            return redirect(
                url_for("order_details", order_id=order_id)
            )

        filename = os.path.basename(payment[0])

        filepath = os.path.join(
            app.config["UPLOAD_FOLDER"],
            filename
        )

        if not os.path.isfile(filepath):
            flash("GCash receipt file could not be found.", "error")
            return redirect(
                url_for("order_details", order_id=order_id)
            )

        return send_file(
            filepath,
            as_attachment=False
        )

    except Exception as error:
        print("GCash Proof Viewing Error:", error)
        flash("Unable to open GCash proof of payment.", "error")
        return redirect(
            url_for("order_details", order_id=order_id)
        )

    finally:
        cursor.close()



# CONFIRM CASH ORDER

@app.route("/admin/orders/confirm/<int:order_id>", methods=["POST"])
@login_required
@role_required("admin")
def confirm_cash_order(order_id):

    success, message = process_order_confirmation(
        order_id,
        "cash"
    )

    if success:
        flash(message, "success")
    else:
        flash(message, "error")

    return redirect(
        url_for("order_details", order_id=order_id)
    )


# VERIFY GCash PAYMENT

@app.route("/admin/orders/verify-gcash/<int:order_id>", methods=["POST"])
@login_required
@role_required("admin")
def verify_gcash_payment(order_id):

    success, message = process_order_confirmation(
        order_id,
        "gcash"
    )

    if success:
        flash(message, "success")
    else:
        flash(message, "error")

    return redirect(
        url_for("order_details", order_id=order_id)
    )
    



# SHARED ORDER CONFIRMATION PROCESS

def process_order_confirmation(order_id, expected_payment_method):

    connection = mysql.connection
    cursor = None

    try:
        connection.begin()
        cursor = connection.cursor()

        # Lock the order and payment records.
        cursor.execute("""
            SELECT
                o.order_status,
                p.payment_method,
                p.payment_status
            FROM orders o
            INNER JOIN payments p
                ON o.order_id = p.order_id
            WHERE o.order_id = %s
            FOR UPDATE
        """, (order_id,))

        order = cursor.fetchone()

        if not order:
            raise ValueError("Order or payment record not found.")

        order_status = order[0]
        payment_method = order[1]
        payment_status = order[2]

        if order_status != "pending":
            raise ValueError(
                "Only pending orders can be confirmed."
            )

        if payment_method != expected_payment_method:
            raise ValueError(
                "Payment method does not match."
            )

        # Validate Cash payment.
        if expected_payment_method == "cash":

            if payment_status != "pending":
                raise ValueError(
                    "Cash payment is not awaiting confirmation."
                )

        # Validate GCash payment.
        elif expected_payment_method == "gcash":

            if payment_status != "pending_verification":
                raise ValueError(
                    "GCash payment is not awaiting verification."
                )

            cursor.execute("""
                SELECT
                    gcash_reference_number,
                    gcash_proof_image
                FROM payments
                WHERE order_id = %s
            """, (order_id,))

            gcash_details = cursor.fetchone()

            if not gcash_details:
                raise ValueError(
                    "GCash payment details not found."
                )

            reference_number = gcash_details[0]
            proof_image = gcash_details[1]

            if not reference_number or not proof_image:
                raise ValueError(
                    "GCash reference number and proof of payment are required."
                )

        else:
            raise ValueError("Unsupported payment method.")

        # Get ordered products.
        cursor.execute("""
            SELECT
                variant_id,
                product_name,
                variant_name,
                quantity
            FROM order_items
            WHERE order_id = %s
        """, (order_id,))

        order_items = cursor.fetchall()

        if not order_items:
            raise ValueError("This order has no products.")

        # Validate and deduct stock.
        for item in order_items:

            variant_id = item[0]
            product_name = item[1]
            variant_name = item[2]
            quantity = item[3]

            cursor.execute("""
                SELECT stock_quantity
                FROM product_variants
                WHERE variant_id = %s
                FOR UPDATE
            """, (variant_id,))

            variant = cursor.fetchone()

            if not variant:
                raise ValueError(
                    f"{product_name} - {variant_name} was not found."
                )

            current_stock = variant[0]

            if current_stock < quantity:
                raise ValueError(
                    f"Insufficient stock for {product_name} - "
                    f"{variant_name}. Available: {current_stock}, "
                    f"Requested: {quantity}."
                )

            new_stock = current_stock - quantity

            cursor.execute("""
                UPDATE product_variants
                SET stock_quantity = %s
                WHERE variant_id = %s
            """, (new_stock, variant_id))

            # Record inventory deduction.
            cursor.execute("""
                INSERT INTO inventory_transactions (
                    variant_id,
                    transaction_type,
                    quantity,
                    remarks
                )
                VALUES (
                    %s,
                    'order_deduction',
                    %s,
                    %s
                )
            """, (
                variant_id,
                quantity,
                f"Stock deducted for Order #{order_id}"
            ))

        # Verify GCash payment after manual admin verification.
        if expected_payment_method == "gcash":

            cursor.execute("""
                UPDATE payments
                SET
                    payment_status = 'verified',
                    verified_by = %s,
                    verified_at = NOW()
                WHERE order_id = %s
            """, (session["user_id"], order_id))

        # Confirm the order.
        cursor.execute("""
            UPDATE orders
            SET order_status = 'confirmed'
            WHERE order_id = %s
        """, (order_id,))

        connection.commit()

        return True, (
            f"Order #{order_id} confirmed successfully. "
            "Inventory has been updated."
        )

    except ValueError as error:

        connection.rollback()
        return False, str(error)

    except Exception as error:

        connection.rollback()

        print(
            "Order Confirmation Error:",
            error
        )

        return False, (
            "Unable to confirm order. "
            "Please check the application log."
        )

    finally:

        if cursor:
            cursor.close()



@app.route("/admin/orders/cancel/<int:order_id>", methods=["POST"])
@login_required
@role_required("admin")
def cancel_order(order_id):

    cursor = mysql.connection.cursor()

    try:
        mysql.connection.begin()

        cursor.execute("""
            SELECT
                order_status,
                fulfillment_method
            FROM orders
            WHERE order_id = %s
            FOR UPDATE
        """, (order_id,))

        order = cursor.fetchone()

        if not order:
            mysql.connection.rollback()
            flash("Order not found.", "error")
            return redirect(url_for("admin_orders"))

        current_status = order[0]
        fulfillment_method = order[1]

        if current_status in ("completed", "cancelled"):
            mysql.connection.rollback()
            flash(
                "This order can no longer be cancelled.",
                "error"
            )
            return redirect(
                url_for("order_details", order_id=order_id)
            )

        # Restore stock only if the order was already confirmed.
        if current_status in ("confirmed", "preparing", "ready"):

            cursor.execute("""
                SELECT variant_id, quantity
                FROM order_items
                WHERE order_id = %s
            """, (order_id,))

            items = cursor.fetchall()

            for variant_id, quantity in items:

                cursor.execute("""
                    SELECT stock_quantity
                    FROM product_variants
                    WHERE variant_id = %s
                    FOR UPDATE
                """, (variant_id,))

                variant = cursor.fetchone()

                if not variant:
                    raise ValueError(
                        f"Product variant {variant_id} was not found."
                    )

                cursor.execute("""
                    UPDATE product_variants
                    SET stock_quantity = stock_quantity + %s
                    WHERE variant_id = %s
                """, (quantity, variant_id))

                cursor.execute("""
                    INSERT INTO inventory_transactions (
                        variant_id,
                        transaction_type,
                        quantity,
                        remarks
                    )
                    VALUES (%s, 'cancellation_restore', %s, %s)
                """, (
                    variant_id,
                    quantity,
                    f"Stock restored from cancelled Order #{order_id}"
                ))

        # Cancel the order.
        cursor.execute("""
            UPDATE orders
            SET order_status = 'cancelled'
            WHERE order_id = %s
        """, (order_id,))

        # Update delivery status if this is a delivery order.
        if fulfillment_method == "delivery":
            cursor.execute("""
                UPDATE deliveries
                SET delivery_status = 'cancelled'
                WHERE order_id = %s
                  AND delivery_status != 'delivered'
            """, (order_id,))

        # Reject payments that are still awaiting processing.
        cursor.execute("""
            UPDATE payments
            SET payment_status = 'rejected'
            WHERE order_id = %s
              AND payment_status IN (
                  'pending',
                  'pending_verification'
              )
        """, (order_id,))

        mysql.connection.commit()

        flash(
            "Order cancelled successfully. Applicable stock has been restored.",
            "success"
        )

    except Exception as error:
        mysql.connection.rollback()
        print("Cancel Order Error:", error)
        flash(
            "Unable to cancel order. Please check the application log.",
            "error"
        )

    finally:
        cursor.close()

    return redirect(
        url_for("order_details", order_id=order_id)
    )  


# UPDATE ORDER STATUS

@app.route(
    "/admin/orders/update-status/<int:order_id>/<string:new_status>",
    methods=["POST"]
)
@login_required
@role_required("admin")
def update_order_status(order_id, new_status):

    allowed_transitions = {
        "confirmed": "preparing",
        "preparing": "ready",
        "ready": "completed"
    }

    cursor = mysql.connection.cursor()

    try:
        mysql.connection.begin()

        cursor.execute("""
            SELECT
                o.order_status,
                o.total_amount,
                o.fulfillment_method,
                p.payment_method,
                p.payment_status
            FROM orders o
            INNER JOIN payments p
                ON o.order_id = p.order_id
            WHERE o.order_id = %s
            FOR UPDATE
        """, (order_id,))

        order = cursor.fetchone()

        if not order:
            mysql.connection.rollback()
            flash("Order or payment record not found.", "error")
            return redirect(url_for("admin_orders"))

        current_status = order[0]
        total_amount = order[1]
        fulfillment_method = order[2]
        payment_method = order[3]
        payment_status = order[4]

        # Delivery orders must be managed through Manage Deliveries.
        if fulfillment_method == "delivery":
            mysql.connection.rollback()
            flash(
                "Please manage this order through Manage Deliveries.",
                "error"
            )
            return redirect(
                url_for("order_details", order_id=order_id)
            )

        expected_status = allowed_transitions.get(current_status)

        if expected_status != new_status:
            mysql.connection.rollback()
            flash("Invalid order status transition.", "error")
            return redirect(
                url_for("order_details", order_id=order_id)
            )

        if new_status == "completed":

            if payment_method == "gcash" and payment_status != "verified":
                mysql.connection.rollback()
                flash(
                    "GCash payment must be verified before completing the order.",
                    "error"
                )
                return redirect(
                    url_for("order_details", order_id=order_id)
                )

            if payment_method == "cash":
                cursor.execute("""
                    UPDATE payments
                    SET payment_status = 'verified',
                        verified_by = %s,
                        verified_at = NOW()
                    WHERE order_id = %s
                """, (session["user_id"], order_id))

            # Prevent duplicate sales records.
            cursor.execute("""
                SELECT 1
                FROM sales
                WHERE order_id = %s
                LIMIT 1
            """, (order_id,))

            existing_sale = cursor.fetchone()

            if not existing_sale:
                cursor.execute("""
                    INSERT INTO sales (
                        order_id,
                        total_amount,
                        sale_date
                    )
                    VALUES (%s, %s, NOW())
                """, (order_id, total_amount))

        cursor.execute("""
            UPDATE orders
            SET order_status = %s
            WHERE order_id = %s
        """, (new_status, order_id))

        mysql.connection.commit()

        flash(
            f"Order status updated to {new_status.replace('_', ' ').title()}!",
            "success"
        )

    except Exception as error:
        mysql.connection.rollback()
        print("Update Order Status Error:", error)
        flash("Unable to update order status.", "error")

    finally:
        cursor.close()

    return redirect(url_for("order_details", order_id=order_id))

# SALES MANAGEMENT

@app.route("/admin/sales")
@login_required
@role_required("admin")
def admin_sales():

    cursor = mysql.connection.cursor()

    try:
        cursor.execute("""
            SELECT
                s.sale_id,
                s.order_id,
                COALESCE(u.full_name, 'Walk-in Customer'),
                o.order_type,
                o.fulfillment_method,
                s.total_amount,
                s.sale_date
            FROM sales s
            INNER JOIN orders o
                ON s.order_id = o.order_id
            LEFT JOIN users u
                ON o.customer_id = u.user_id
            ORDER BY s.sale_date DESC, s.sale_id DESC
        """)

        sales_list = cursor.fetchall()

        cursor.execute("""
            SELECT
                COUNT(*),
                COALESCE(SUM(total_amount), 0)
            FROM sales
        """)

        summary = cursor.fetchone()

        return render_template(
            "sales.html",
            sales=sales_list,
            total_transactions=summary[0],
            total_sales=summary[1]
        )

    except Exception as error:
        print("Sales Management Error:", error)
        flash("Unable to load sales records.", "error")
        return redirect(url_for("admin_dashboard"))

    finally:
        cursor.close()


# CUSTOMER MENU


@app.route("/customer/menu")
@login_required
@role_required("customer")
def customer_menu():

    cursor = mysql.connection.cursor()

    try:
        cursor.execute("""
            SELECT
                c.category_name,
                p.product_id,
                p.product_name,
                p.description,
                pv.variant_id,
                pv.variant_name,
                pv.price,
                c.category_id,
                pv.stock_quantity
            FROM products p
            INNER JOIN categories c
                ON p.category_id = c.category_id
            INNER JOIN product_variants pv
                ON p.product_id = pv.product_id
            WHERE p.is_available = 1
              AND pv.is_available = 1
            ORDER BY c.category_id, p.product_id, pv.variant_id
        """)

        products = cursor.fetchall()

        cursor.execute("""
            SELECT
                addon_id,
                category_id,
                addon_name,
                price
            FROM addons
            WHERE is_available = 1
            ORDER BY addon_name
        """)

        addon_rows = cursor.fetchall()

        addons_by_category = {}

        for addon in addon_rows:
            category_id = addon[1]

            if category_id not in addons_by_category:
                addons_by_category[category_id] = []

            addons_by_category[category_id].append({
                "addon_id": addon[0],
                "addon_name": addon[2],
                "price": float(addon[3])
            })

        return render_template(
            "customer_menu.html",
            products=products,
            addons_by_category=addons_by_category
        )

    except Exception as error:
        print("Customer Menu Error:", error)
        flash("Unable to load the menu.", "error")
        return redirect(url_for("customer_dashboard"))

    finally:
        cursor.close()


# CUSTOMER ADD TO CART


@app.route("/customer/cart/add", methods=["POST"])
@login_required
@role_required("customer")
def customer_add_to_cart():

    cursor = mysql.connection.cursor()

    try:
        variant_id = int(request.form.get("variant_id", 0))
        quantity = int(request.form.get("quantity", 1))

        if quantity < 1:
            raise ValueError("Quantity must be at least 1.")

        cursor.execute("""
            SELECT
                pv.variant_id,
                p.product_name,
                pv.variant_name,
                pv.price,
                pv.stock_quantity,
                p.category_id
            FROM product_variants pv
            INNER JOIN products p
                ON pv.product_id = p.product_id
            WHERE pv.variant_id = %s
              AND pv.is_available = 1
              AND p.is_available = 1
        """, (variant_id,))

        product = cursor.fetchone()

        if not product:
            raise ValueError("Product variant is unavailable.")

        available_stock = int(product[4])

        if available_stock <= 0:
            raise ValueError("This product is currently out of stock.")

        cart = session.get("customer_cart", [])

        # Check the total quantity of this variant
        # already in the cart, regardless of selected add-ons.
        existing_variant_quantity = sum(
            int(item.get("quantity", 0))
            for item in cart
            if int(item.get("variant_id", 0)) == variant_id
        )

        total_requested_quantity = (
            existing_variant_quantity + quantity
        )

        if total_requested_quantity > available_stock:
            raise ValueError(
                f"Insufficient stock. You already have "
                f"{existing_variant_quantity} in your cart. "
                f"Available stock: {available_stock}."
            )

        # Get selected add-ons from the menu form.
        selected_addon_ids = request.form.getlist("addon_ids")

        addon_ids = []

        for addon_id in selected_addon_ids:
            try:
                addon_id = int(addon_id)
            except ValueError:
                raise ValueError("Invalid add-on selection.")

            if addon_id not in addon_ids:
                addon_ids.append(addon_id)

        selected_addons = []

        if addon_ids:
            placeholders = ", ".join(["%s"] * len(addon_ids))

            cursor.execute(f"""
                SELECT addon_id, addon_name, price
                FROM addons
                WHERE addon_id IN ({placeholders})
                  AND category_id = %s
                  AND is_available = 1
            """, tuple(addon_ids) + (product[5],))

            addon_rows = cursor.fetchall()

            if len(addon_rows) != len(addon_ids):
                raise ValueError(
                    "One or more selected add-ons are unavailable."
                )

            for addon in addon_rows:
                addon_quantity_input = request.form.get(
                    f"addon_quantity_{addon[0]}", "1"
                )

                try:
                    addon_quantity = int(addon_quantity_input)
                except ValueError:
                    raise ValueError("Invalid add-on quantity.")

                if addon_quantity < 1:
                    raise ValueError(
                        "Add-on quantity must be at least 1."
                    )

                selected_addons.append({
                    "addon_id": addon[0],
                    "addon_name": addon[1],
                    "unit_price": float(addon[2]),
                    "quantity": addon_quantity
                })

        # Calculate the price of one product including its add-ons.
        addon_price_per_product = sum(
            addon["unit_price"] * addon["quantity"]
            for addon in selected_addons
        )

        unit_price = float(product[3])
        subtotal_per_product = unit_price + addon_price_per_product

        item_subtotal = subtotal_per_product * quantity

        # Only combine items with the same variant AND same add-ons.
        addon_signature = tuple(sorted(
            (addon["addon_id"], addon["quantity"])
            for addon in selected_addons
        ))

        existing_item = next(
            (
                item for item in cart
                if item["variant_id"] == variant_id
                and tuple(sorted(
                    (
                        addon["addon_id"],
                        addon["quantity"]
                    )
                    for addon in item.get("addons", [])
                )) == addon_signature
            ),
            None
        )

        if existing_item:
            existing_item["quantity"] += quantity

            existing_item["subtotal"] = (
                existing_item["unit_price"]
                + sum(
                    addon["unit_price"] * addon["quantity"]
                    for addon in existing_item.get("addons", [])
                )
            ) * existing_item["quantity"]

        else:
            cart.append({
                "variant_id": product[0],
                "product_name": product[1],
                "variant_name": product[2],
                "unit_price": unit_price,
                "quantity": quantity,
                "addons": selected_addons,
                "subtotal": item_subtotal
            })

        session["customer_cart"] = cart
        session.modified = True

        flash(
            "Product and selected add-ons added to your cart!",
            "success"
        )

    except ValueError as error:
        flash(str(error), "error")

    except Exception as error:
        print("Customer Add to Cart Error:", error)
        flash("Unable to add product to cart.", "error")

    finally:
        cursor.close()

    return redirect(url_for("customer_menu"))


@app.route("/customer/cart")
@login_required
@role_required("customer")
def customer_cart():

    cart = session.get("customer_cart", [])

    total_amount = sum(
        item["subtotal"] for item in cart
    )

    return render_template(
        "customer_cart.html",
        cart=cart,
        total_amount=total_amount
    )
    
@app.route("/customer/checkout")
@login_required
@role_required("customer")
def customer_checkout():

    cart = session.get("customer_cart", [])

    if not cart:
        flash("Your cart is empty.", "error")
        return redirect(url_for("customer_cart"))

    total_amount = sum(
        item["subtotal"] for item in cart
    )

    cursor = mysql.connection.cursor()

    try:
        cursor.execute("""
            SELECT location_id, location_name, delivery_fee
            FROM delivery_locations
            WHERE is_active = 1
            ORDER BY location_name
        """)

        delivery_locations = cursor.fetchall()

        return render_template(
            "customer_checkout.html",
            cart=cart,
            total_amount=total_amount,
            delivery_locations=delivery_locations
        )

    except Exception as error:
        print("Customer Checkout Error:", error)
        flash("Unable to load checkout.", "error")
        return redirect(url_for("customer_cart"))

    finally:
        cursor.close()
        


@app.route("/customer/place-order", methods=["POST"])
@login_required
@role_required("customer")
def customer_place_order():

    cart = session.get("customer_cart", [])

    if not cart:
        flash("Your cart is empty.", "error")
        return redirect(url_for("customer_cart"))

    fulfillment_method = request.form.get(
        "fulfillment_method", ""
    ).strip()

    payment_method = request.form.get(
        "payment_method", ""
    ).strip()

    gcash_reference_number = request.form.get(
        "gcash_reference_number", ""
    ).strip()

    proof_file = request.files.get("gcash_proof_image")

    if fulfillment_method not in ("pickup", "delivery"):
        flash("Please select a valid fulfillment method.", "error")
        return redirect(url_for("customer_checkout"))

    if payment_method not in ("cash", "gcash"):
        flash("Please select a valid payment method.", "error")
        return redirect(url_for("customer_checkout"))

    # Validate GCash details before processing the order.
    if payment_method == "gcash":

        if not gcash_reference_number:
            flash("Please enter your GCash reference number.", "error")
            return redirect(url_for("customer_checkout"))

        if len(gcash_reference_number) > 100:
            flash("GCash reference number is too long.", "error")
            return redirect(url_for("customer_checkout"))

        if not proof_file or not proof_file.filename:
            flash("Please upload your GCash payment receipt.", "error")
            return redirect(url_for("customer_checkout"))

        original_filename = secure_filename(proof_file.filename)
        file_extension = os.path.splitext(original_filename)[1].lower()

        allowed_extensions = {
            ".png": "png",
            ".jpg": "jpg",
            ".jpeg": "jpg",
            ".webp": "webp"
        }

        if file_extension not in allowed_extensions:
            flash(
                "Invalid receipt format. Please upload PNG, JPG, JPEG, or WEBP.",
                "error"
            )
            return redirect(url_for("customer_checkout"))

        # Check the actual image file signature.
        file_header = proof_file.read(12)
        proof_file.seek(0)

        is_valid_image = False

        if file_extension == ".png":
            is_valid_image = file_header.startswith(
                b"\x89PNG\r\n\x1a\n"
            )

        elif file_extension in (".jpg", ".jpeg"):
            is_valid_image = file_header.startswith(b"\xff\xd8\xff")

        elif file_extension == ".webp":
            is_valid_image = (
                len(file_header) >= 12
                and file_header[:4] == b"RIFF"
                and file_header[8:12] == b"WEBP"
            )

        if not is_valid_image:
            flash(
                "The uploaded file is not a valid supported image.",
                "error"
            )
            return redirect(url_for("customer_checkout"))

    cursor = mysql.connection.cursor()

    saved_proof_path = None

    try:
        cursor.execute("START TRANSACTION")

        location_id = None
        delivery_address = None
        delivery_fee = Decimal("0.00")

        if fulfillment_method == "delivery":

            location_id = request.form.get(
                "location_id", ""
            ).strip()

            delivery_address = request.form.get(
                "delivery_address", ""
            ).strip()

            if not location_id or not delivery_address:
                raise ValueError(
                    "Please provide your delivery location and complete address."
                )

            try:
                location_id = int(location_id)
            except ValueError:
                raise ValueError("Invalid delivery location.")

            cursor.execute("""
                SELECT delivery_fee
                FROM delivery_locations
                WHERE location_id = %s
                  AND is_active = 1
                FOR UPDATE
            """, (location_id,))

            location = cursor.fetchone()

            if not location:
                raise ValueError(
                    "The selected delivery location is unavailable."
                )

            delivery_fee = Decimal(str(location[0]))

        verified_items = []
        subtotal_amount = Decimal("0.00")

        # Combine quantities of duplicate variants.
        total_quantities = {}

        for item in cart:

            try:
                variant_id = int(item["variant_id"])
                quantity = int(item["quantity"])
            except (KeyError, TypeError, ValueError):
                raise ValueError("Invalid cart item.")

            if quantity < 1:
                raise ValueError("Invalid product quantity.")

            total_quantities[variant_id] = (
                total_quantities.get(variant_id, 0) + quantity
            )

        # Revalidate products and stock.
        checked_variants = {}

        for variant_id, total_quantity in total_quantities.items():

            cursor.execute("""
                SELECT
                    pv.variant_id,
                    p.product_name,
                    pv.variant_name,
                    pv.price,
                    pv.stock_quantity,
                    p.category_id
                FROM product_variants pv
                INNER JOIN products p
                    ON pv.product_id = p.product_id
                WHERE pv.variant_id = %s
                  AND pv.is_available = 1
                  AND p.is_available = 1
                FOR UPDATE
            """, (variant_id,))

            product = cursor.fetchone()

            if not product:
                raise ValueError(
                    "One of the products in your cart is unavailable."
                )

            available_stock = int(product[4])

            if total_quantity > available_stock:
                raise ValueError(
                    f"Insufficient stock for {product[1]} "
                    f"({product[2]}). "
                    f"Requested: {total_quantity}. "
                    f"Available stock: {available_stock}."
                )

            checked_variants[variant_id] = product

        # Revalidate prices and add-ons.
        for item in cart:

            variant_id = int(item["variant_id"])
            quantity = int(item["quantity"])

            product = checked_variants[variant_id]

            unit_price = Decimal(str(product[3]))
            item_addons = []
            addon_total = Decimal("0.00")

            for cart_addon in item.get("addons", []):

                addon_id = int(cart_addon["addon_id"])
                addon_quantity = int(cart_addon["quantity"])

                if addon_quantity < 1:
                    raise ValueError("Invalid add-on quantity.")

                cursor.execute("""
                    SELECT addon_id, addon_name, price
                    FROM addons
                    WHERE addon_id = %s
                      AND category_id = %s
                      AND is_available = 1
                    FOR UPDATE
                """, (addon_id, product[5]))

                addon = cursor.fetchone()

                if not addon:
                    raise ValueError(
                        "One of your selected add-ons is unavailable."
                    )

                addon_unit_price = Decimal(str(addon[2]))

                item_addons.append({
                    "addon_id": addon[0],
                    "addon_name": addon[1],
                    "quantity": addon_quantity,
                    "unit_price": addon_unit_price
                })

                addon_total += (
                    addon_unit_price * addon_quantity
                )

            item_subtotal = (
                unit_price + addon_total
            ) * quantity

            verified_items.append({
                "variant_id": product[0],
                "product_name": product[1],
                "variant_name": product[2],
                "quantity": quantity,
                "unit_price": unit_price,
                "subtotal": item_subtotal,
                "addons": item_addons
            })

            subtotal_amount += item_subtotal

        total_amount = subtotal_amount + delivery_fee

        # Create the online order.
        cursor.execute("""
            INSERT INTO orders (
                customer_id,
                encoded_by,
                order_type,
                fulfillment_method,
                total_amount,
                order_status
            )
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            session["user_id"],
            None,
            "online",
            fulfillment_method,
            total_amount,
            "pending"
        ))

        order_id = cursor.lastrowid

        # Save order items and selected add-ons.
        for item in verified_items:

            cursor.execute("""
                INSERT INTO order_items (
                    order_id,
                    variant_id,
                    product_name,
                    variant_name,
                    quantity,
                    unit_price,
                    subtotal
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                order_id,
                item["variant_id"],
                item["product_name"],
                item["variant_name"],
                item["quantity"],
                item["unit_price"],
                item["subtotal"]
            ))

            order_item_id = cursor.lastrowid

            for addon in item["addons"]:

                cursor.execute("""
                    INSERT INTO order_item_addons (
                        order_item_id,
                        addon_id,
                        quantity,
                        unit_price
                    )
                    VALUES (%s, %s, %s, %s)
                """, (
                    order_item_id,
                    addon["addon_id"],
                    addon["quantity"],
                    addon["unit_price"]
                ))

        # Save delivery information.
        if fulfillment_method == "delivery":

            cursor.execute("""
                INSERT INTO deliveries (
                    order_id,
                    location_id,
                    delivery_address,
                    delivery_fee
                )
                VALUES (%s, %s, %s, %s)
            """, (
                order_id,
                location_id,
                delivery_address,
                delivery_fee
            ))

        # Save GCash receipt in the private upload folder.
        gcash_proof_filename = None

        if payment_method == "gcash":

            extension = allowed_extensions[file_extension]

            unique_filename = (
                f"order_{order_id}_{uuid.uuid4().hex}.{extension}"
            )

            gcash_proof_filename = secure_filename(unique_filename)

            upload_folder = app.config["UPLOAD_FOLDER"]

            os.makedirs(upload_folder, exist_ok=True)

            saved_proof_path = os.path.join(
                upload_folder,
                gcash_proof_filename
            )

            proof_file.save(saved_proof_path)

        # Save payment record.
        payment_status = (
            "pending_verification"
            if payment_method == "gcash"
            else "pending"
        )

        cursor.execute("""
            INSERT INTO payments (
                order_id,
                payment_method,
                amount,
                payment_status,
                gcash_reference_number,
                gcash_proof_image
            )
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            order_id,
            payment_method,
            total_amount,
            payment_status,
            gcash_reference_number if payment_method == "gcash" else None,
            gcash_proof_filename
        ))

        mysql.connection.commit()

        session.pop("customer_cart", None)

        flash(
            f"Your order #{order_id} has been placed successfully! "
            "Please wait for the admin to verify your payment and confirm your order.",
            "success"
        )

        return redirect(url_for("customer_dashboard"))

    except ValueError as error:

        mysql.connection.rollback()

        if saved_proof_path and os.path.exists(saved_proof_path):
            os.remove(saved_proof_path)

        flash(str(error), "error")
        return redirect(url_for("customer_checkout"))

    except Exception as error:

        mysql.connection.rollback()

        if saved_proof_path and os.path.exists(saved_proof_path):
            os.remove(saved_proof_path)

        print("Customer Place Order Error:", error)

        flash(
            "Unable to place your order. Please try again.",
            "error"
        )

        return redirect(url_for("customer_checkout"))

    finally:
        cursor.close()
        

@app.route("/customer/orders")
@login_required
@role_required("customer")
def customer_orders():
    cursor = mysql.connection.cursor()

    try:
        cursor.execute("""
            SELECT
                o.order_id,
                o.order_date,
                o.order_type,
                o.fulfillment_method,
                o.total_amount,
                o.order_status,
                p.payment_method,
                p.payment_status,
                d.delivery_status
            FROM orders o
            LEFT JOIN payments p
                ON o.order_id = p.order_id
            LEFT JOIN deliveries d
                ON o.order_id = d.order_id
            WHERE o.customer_id = %s
            ORDER BY o.order_date DESC
        """, (session["user_id"],))

        orders = cursor.fetchall()

        return render_template(
            "customer_orders.html",
            orders=orders
        )

    except Exception as error:
        print("Customer Orders Error:", error)
        flash("Unable to load your order history.", "error")
        return redirect(url_for("customer_dashboard"))

    finally:
        cursor.close()
        


@app.route("/customer/orders/<int:order_id>")
@login_required
@role_required("customer")
def customer_order_details(order_id):

    cursor = mysql.connection.cursor()

    try:
        cursor.execute("""
            SELECT
                o.order_id,
                o.order_date,
                o.order_type,
                o.fulfillment_method,
                o.total_amount,
                o.order_status,
                p.payment_method,
                p.payment_status,
                d.delivery_address,
                d.delivery_fee,
                dl.location_name,
                d.delivery_status
            FROM orders o
            LEFT JOIN payments p
                ON o.order_id = p.order_id
            LEFT JOIN deliveries d
                ON o.order_id = d.order_id
            LEFT JOIN delivery_locations dl
                ON d.location_id = dl.location_id
            WHERE o.order_id = %s
              AND o.customer_id = %s
        """, (order_id, session["user_id"]))

        order = cursor.fetchone()

        if not order:
            flash("Order not found.", "error")
            return redirect(url_for("customer_orders"))

        cursor.execute("""
            SELECT
                order_item_id,
                product_name,
                variant_name,
                quantity,
                unit_price,
                subtotal
            FROM order_items
            WHERE order_id = %s
        """, (order_id,))

        item_rows = cursor.fetchall()

        items = []
        order_items = []
        addons_by_item = {}

        for item in item_rows:

            order_item_id = item[0]

            cursor.execute("""
                SELECT
                    a.addon_id,
                    a.addon_name,
                    oia.unit_price,
                    oia.quantity
                FROM order_item_addons oia
                LEFT JOIN addons a
                    ON oia.addon_id = a.addon_id
                WHERE oia.order_item_id = %s
            """, (order_item_id,))

            addon_rows = cursor.fetchall()

            addon_objects = []
            addon_display = []

            for addon_row in addon_rows:

                addon = Addon(
                    addon_id=addon_row[0],
                    addon_name=addon_row[1] or "Unavailable Add-on",
                    unit_price=addon_row[2],
                    quantity=addon_row[3]
                )

                addon_objects.append(addon)

                addon_display.append((
                    addon.addon_name,
                    addon.quantity,
                    addon.unit_price
                ))

            order_item = OrderItem(
                product_name=item[1],
                variant_name=item[2],
                quantity=item[3],
                unit_price=item[4],
                addons=addon_objects
            )

            order_items.append(order_item)

            items.append((
                item[0],
                order_item.product_name,
                order_item.variant_name,
                order_item.quantity,
                order_item.unit_price,
                item[5]
            ))

            addons_by_item[order_item_id] = addon_display

        order_model = Order(
            order_id=order[0],
            items=order_items,
            fulfillment_method=order[3],
            delivery_fee=order[9] or 0
        )

        return render_template(
            "customer_order_details.html",
            order=order,
            items=items,
            addons_by_item=addons_by_item,
            order_model=order_model
        )

    except Exception as error:
        print("Customer Order Details Error:", error)
        flash("Unable to load order details.", "error")
        return redirect(url_for("customer_orders"))

    finally:
        cursor.close()


@app.route("/customer/profile", methods=["GET", "POST"])
@login_required
@role_required("customer")
def customer_profile():
    cursor = mysql.connection.cursor()

    try:
        if request.method == "POST":
            full_name = request.form.get("full_name", "").strip()
            email = request.form.get("email", "").strip().lower()

            if not full_name or not email:
                flash("Full name and email are required.", "error")
                return redirect(url_for("customer_profile"))

            if "@" not in email or "." not in email.split("@")[-1]:
                flash("Please enter a valid email address.", "error")
                return redirect(url_for("customer_profile"))

            cursor.execute("""
                SELECT user_id
                FROM users
                WHERE email = %s
                  AND user_id != %s
            """, (email, session["user_id"]))

            existing_email = cursor.fetchone()

            if existing_email:
                flash("That email address is already registered.", "error")
                return redirect(url_for("customer_profile"))

            cursor.execute("""
                UPDATE users
                SET full_name = %s,
                    email = %s
                WHERE user_id = %s
                  AND role = 'customer'
            """, (full_name, email, session["user_id"]))

            mysql.connection.commit()

            session["full_name"] = full_name

            flash("Your profile has been updated successfully.", "success")
            return redirect(url_for("customer_profile"))

        cursor.execute("""
            SELECT full_name, username, email, role
            FROM users
            WHERE user_id = %s
              AND role = 'customer'
        """, (session["user_id"],))

        user = cursor.fetchone()

        if not user:
            flash("Customer account not found.", "error")
            return redirect(url_for("customer_dashboard"))

        return render_template("customer_profile.html", user=user)

    except Exception as error:
        mysql.connection.rollback()
        print("Customer Profile Error:", error)
        flash("Unable to process your profile.", "error")
        return redirect(url_for("customer_dashboard"))

    finally:
        cursor.close()
        
@app.route("/customer/change-password", methods=["GET", "POST"])
@login_required
@role_required("customer")
def customer_change_password():
    cursor = mysql.connection.cursor()

    try:
        if request.method == "POST":
            current_password = request.form.get("current_password", "")
            new_password = request.form.get("new_password", "")
            confirm_password = request.form.get("confirm_password", "")

            if not current_password or not new_password or not confirm_password:
                flash("Please complete all password fields.", "error")
                return redirect(url_for("customer_change_password"))

            if len(new_password) < 8:
                flash("New password must be at least 8 characters.", "error")
                return redirect(url_for("customer_change_password"))

            if new_password != confirm_password:
                flash("New passwords do not match.", "error")
                return redirect(url_for("customer_change_password"))

            cursor.execute("""
                SELECT password_hash
                FROM users
                WHERE user_id = %s
                  AND role = 'customer'
            """, (session["user_id"],))

            user = cursor.fetchone()

            if not user or not check_password_hash(user[0], current_password):
                flash("Your current password is incorrect.", "error")
                return redirect(url_for("customer_change_password"))

            new_password_hash = generate_password_hash(new_password)

            cursor.execute("""
                UPDATE users
                SET password_hash = %s
                WHERE user_id = %s
                  AND role = 'customer'
            """, (new_password_hash, session["user_id"]))

            mysql.connection.commit()

            flash("Your password has been changed successfully.", "success")
            return redirect(url_for("customer_profile"))

        return render_template("customer_change_password.html")

    except Exception as error:
        mysql.connection.rollback()
        print("Customer Change Password Error:", error)
        flash("Unable to change your password.", "error")
        return redirect(url_for("customer_profile"))

    finally:
        cursor.close()
        
    

@app.route("/customer/cart/update/<int:item_index>", methods=["POST"])
@login_required
@role_required("customer")
def customer_update_cart_quantity(item_index):

    cart = session.get("customer_cart", [])

    try:
        quantity = int(request.form.get("quantity", 0))

        if quantity < 1:
            flash("Quantity must be at least 1.", "error")
            return redirect(url_for("customer_cart"))

        if item_index < 0 or item_index >= len(cart):
            flash("Cart item not found.", "error")
            return redirect(url_for("customer_cart"))

        item = cart[item_index]

        addon_total = sum(
            float(addon["unit_price"]) * int(addon["quantity"])
            for addon in item.get("addons", [])
        )

        item["quantity"] = quantity
        item["subtotal"] = (
            float(item["unit_price"]) + addon_total
        ) * quantity

        session["customer_cart"] = cart
        session.modified = True

        flash("Cart quantity updated successfully!", "success")

    except (ValueError, TypeError, KeyError):
        flash("Please enter a valid quantity.", "error")

    return redirect(url_for("customer_cart"))


@app.route("/customer/cart/remove/<int:item_index>", methods=["POST"])
@login_required
@role_required("customer")
def customer_remove_cart_item(item_index):

    cart = session.get("customer_cart", [])

    if item_index < 0 or item_index >= len(cart):
        flash("Cart item not found.", "error")
    else:
        cart.pop(item_index)

        session["customer_cart"] = cart
        session.modified = True

        flash("Product removed from your cart.", "success")

    return redirect(url_for("customer_cart"))
        
        
# ADMIN DELIVERY LOCATIONS

@app.route("/admin/delivery-locations", methods=["GET", "POST"])
@login_required
@role_required("admin")
def admin_delivery_locations():

    cursor = mysql.connection.cursor()

    try:

        if request.method == "POST":

            location_name = request.form.get(
                "location_name", ""
            ).strip()

            delivery_fee_input = request.form.get(
                "delivery_fee", ""
            ).strip()

            if not location_name or not delivery_fee_input:
                flash("Please complete all fields.", "error")

            else:
                delivery_fee = Decimal(delivery_fee_input)

                if delivery_fee < 0:
                    flash("Delivery fee cannot be negative.", "error")

                else:
                    cursor.execute("""
                        INSERT INTO delivery_locations
                        (location_name, delivery_fee, is_active)
                        VALUES (%s, %s, 1)
                    """, (
                        location_name,
                        delivery_fee
                    ))

                    mysql.connection.commit()

                    flash(
                        "Delivery location added successfully.",
                        "success"
                    )

                    return redirect(
                        url_for("admin_delivery_locations")
                    )

        cursor.execute("""
            SELECT
                location_id,
                location_name,
                delivery_fee,
                is_active
            FROM delivery_locations
            ORDER BY location_name
        """)

        locations = cursor.fetchall()

        return render_template(
            "admin_delivery_locations.html",
            locations=locations
        )

    except Exception as error:
        mysql.connection.rollback()
        print("Admin Delivery Locations Error:", error)

        flash(
            "Unable to process delivery locations. Please check the information.",
            "error"
        )

        return redirect(url_for("admin_delivery_locations"))

    finally:
        cursor.close()        
        
        

# UPDATE DELIVERY LOCATION

@app.route(
    "/admin/delivery-locations/update/<int:location_id>",
    methods=["POST"]
)
@login_required
@role_required("admin")
def update_delivery_location(location_id):

    cursor = mysql.connection.cursor()

    try:
        location_name = request.form.get(
            "location_name", ""
        ).strip()

        fee_input = request.form.get(
            "delivery_fee", ""
        ).strip()

        if not location_name or len(location_name) > 150:
            flash("Please enter a valid location name.", "error")
            return redirect(url_for("admin_delivery_locations"))

        try:
            delivery_fee = Decimal(fee_input)

            if not delivery_fee.is_finite() or delivery_fee < 0:
                raise ValueError

        except Exception:
            flash("Please enter a valid delivery fee.", "error")
            return redirect(url_for("admin_delivery_locations"))

        cursor.execute("""
            UPDATE delivery_locations
            SET location_name = %s,
                delivery_fee = %s
            WHERE location_id = %s
        """, (
            location_name,
            delivery_fee,
            location_id
        ))

        if cursor.rowcount == 0:
            cursor.execute("""
                SELECT location_id
                FROM delivery_locations
                WHERE location_id = %s
            """, (location_id,))

            if not cursor.fetchone():
                flash("Delivery location not found.", "error")
                return redirect(url_for("admin_delivery_locations"))

        mysql.connection.commit()

        flash("Delivery location updated successfully.", "success")

    except Exception as error:
        mysql.connection.rollback()
        print("Update Delivery Location Error:", error)

        flash(
            "Unable to update delivery location. Check if the location name already exists.",
            "error"
        )

    finally:
        cursor.close()

    return redirect(url_for("admin_delivery_locations"))



# TOGGLE DELIVERY LOCATION STATUS

@app.route(
    "/admin/delivery-locations/toggle/<int:location_id>",
    methods=["POST"]
)
@login_required
@role_required("admin")
def toggle_delivery_location(location_id):

    cursor = mysql.connection.cursor()

    try:
        cursor.execute("""
            SELECT is_active
            FROM delivery_locations
            WHERE location_id = %s
            FOR UPDATE
        """, (location_id,))

        location = cursor.fetchone()

        if not location:
            flash("Delivery location not found.", "error")
            return redirect(url_for("admin_delivery_locations"))

        new_status = 0 if location[0] == 1 else 1

        cursor.execute("""
            UPDATE delivery_locations
            SET is_active = %s
            WHERE location_id = %s
        """, (new_status, location_id))

        mysql.connection.commit()

        if new_status == 1:
            flash("Delivery location activated successfully.", "success")
        else:
            flash("Delivery location deactivated successfully.", "success")

    except Exception as error:
        mysql.connection.rollback()
        print("Toggle Delivery Location Error:", error)

        flash("Unable to update delivery location status.", "error")

    finally:
        cursor.close()

    return redirect(url_for("admin_delivery_locations"))



@app.route("/admin/deliveries/update/<int:delivery_id>", methods=["POST"])
@login_required
@role_required("admin")
def update_delivery_status(delivery_id):

    cursor = mysql.connection.cursor()

    allowed_statuses = [
        "pending",
        "preparing",
        "out_for_delivery",
        "delivered",
        "cancelled"
    ]

    try:
        mysql.connection.begin()

        new_status = request.form.get(
            "delivery_status", ""
        ).strip()

        if new_status not in allowed_statuses:
            mysql.connection.rollback()
            flash("Invalid delivery status.", "error")
            return redirect(url_for("admin_deliveries"))

        cursor.execute("""
            SELECT
                d.order_id,
                d.delivery_status,
                o.order_status,
                o.total_amount,
                p.payment_method,
                p.payment_status
            FROM deliveries d
            INNER JOIN orders o
                ON d.order_id = o.order_id
            INNER JOIN payments p
                ON o.order_id = p.order_id
            WHERE d.delivery_id = %s
            FOR UPDATE
        """, (delivery_id,))

        delivery = cursor.fetchone()

        if not delivery:
            mysql.connection.rollback()
            flash(
                "Delivery, order, or payment record not found.",
                "error"
            )
            return redirect(url_for("admin_deliveries"))

        order_id = delivery[0]
        current_delivery_status = delivery[1]
        current_order_status = delivery[2]
        total_amount = delivery[3]
        payment_method = delivery[4]
        payment_status = delivery[5]

        # Prevent changes to finalized deliveries.
        if current_delivery_status in ("delivered", "cancelled"):
            mysql.connection.rollback()
            flash(
                "This delivery has already been finalized.",
                "error"
            )
            return redirect(url_for("admin_deliveries"))

        if current_order_status in ("completed", "cancelled"):
            mysql.connection.rollback()
            flash(
                "This order can no longer be updated.",
                "error"
            )
            return redirect(url_for("admin_deliveries"))

        if new_status == current_delivery_status:
            mysql.connection.rollback()
            flash(
                "The delivery already has this status.",
                "error"
            )
            return redirect(url_for("admin_deliveries"))

        # PENDING
        if new_status == "pending":

            if current_delivery_status != "pending":
                raise ValueError(
                    "Delivery cannot return to pending."
                )

        # PREPARING
        elif new_status == "preparing":

            if current_delivery_status != "pending":
                raise ValueError(
                    "Invalid delivery status transition."
                )

            if current_order_status != "confirmed":
                raise ValueError(
                    "Please confirm the order first before preparing the delivery."
                )

            cursor.execute("""
                UPDATE orders
                SET order_status = 'preparing'
                WHERE order_id = %s
            """, (order_id,))

        # OUT FOR DELIVERY
        elif new_status == "out_for_delivery":

            if current_delivery_status != "preparing":
                raise ValueError(
                    "Delivery must be preparing before dispatch."
                )

            if current_order_status != "preparing":
                raise ValueError(
                    "Order must be preparing before dispatch."
                )

            cursor.execute("""
                UPDATE orders
                SET order_status = 'ready'
                WHERE order_id = %s
            """, (order_id,))

        # DELIVERED
        elif new_status == "delivered":

            if current_delivery_status != "out_for_delivery":
                raise ValueError(
                    "Delivery must be out for delivery first."
                )

            if current_order_status != "ready":
                raise ValueError(
                    "Order must be ready before delivery completion."
                )

            if payment_method == "gcash" and payment_status != "verified":
                raise ValueError(
                    "GCash payment must be verified before completing delivery."
                )

            # Automatically verify cash payment upon delivery.
            if payment_method == "cash":

                cursor.execute("""
                    UPDATE payments
                    SET payment_status = 'verified',
                        verified_by = %s,
                        verified_at = NOW()
                    WHERE order_id = %s
                """, (session["user_id"], order_id))

            # Check for an existing sales record.
            cursor.execute("""
                SELECT 1
                FROM sales
                WHERE order_id = %s
                LIMIT 1
            """, (order_id,))

            existing_sale = cursor.fetchone()

            # Record the sale only once.
            if not existing_sale:

                cursor.execute("""
                    INSERT INTO sales (
                        order_id,
                        total_amount,
                        sale_date
                    )
                    VALUES (%s, %s, NOW())
                """, (order_id, total_amount))

            # Mark the order as completed.
            cursor.execute("""
                UPDATE orders
                SET order_status = 'completed'
                WHERE order_id = %s
            """, (order_id,))

        # CANCELLED
        elif new_status == "cancelled":

            # Restore stock only if the order was confirmed.
            if current_order_status in (
                "confirmed",
                "preparing",
                "ready"
            ):

                cursor.execute("""
                    SELECT variant_id, quantity
                    FROM order_items
                    WHERE order_id = %s
                """, (order_id,))

                items = cursor.fetchall()

                for variant_id, quantity in items:

                    cursor.execute("""
                        SELECT stock_quantity
                        FROM product_variants
                        WHERE variant_id = %s
                        FOR UPDATE
                    """, (variant_id,))

                    variant = cursor.fetchone()

                    if not variant:
                        raise ValueError(
                            f"Product variant {variant_id} was not found."
                        )

                    cursor.execute("""
                        UPDATE product_variants
                        SET stock_quantity = stock_quantity + %s
                        WHERE variant_id = %s
                    """, (quantity, variant_id))

                    cursor.execute("""
                        INSERT INTO inventory_transactions (
                            variant_id,
                            transaction_type,
                            quantity,
                            remarks
                        )
                        VALUES (
                            %s,
                            'cancellation_restore',
                            %s,
                            %s
                        )
                    """, (
                        variant_id,
                        quantity,
                        f"Stock restored from cancelled Order #{order_id}"
                    ))

            cursor.execute("""
                UPDATE orders
                SET order_status = 'cancelled'
                WHERE order_id = %s
            """, (order_id,))

            cursor.execute("""
                UPDATE payments
                SET payment_status = 'rejected'
                WHERE order_id = %s
                  AND payment_status IN (
                      'pending',
                      'pending_verification'
                  )
            """, (order_id,))

        # Save the delivery status.
        cursor.execute("""
            UPDATE deliveries
            SET delivery_status = %s
            WHERE delivery_id = %s
        """, (new_status, delivery_id))

        mysql.connection.commit()

        flash(
            f"Delivery status updated to "
            f"{new_status.replace('_', ' ').title()}!",
            "success"
        )

    except ValueError as error:

        mysql.connection.rollback()
        flash(str(error), "error")

    except Exception as error:

        mysql.connection.rollback()
        print("Update Delivery Status Error:", error)

        flash(
            "Unable to update delivery status.",
            "error"
        )

    finally:
        cursor.close()

    return redirect(url_for("admin_deliveries"))


@app.route("/admin/deliveries", methods=["GET"])
@login_required
@role_required("admin")
def admin_deliveries():

    cursor = mysql.connection.cursor()

    try:
        # Get all delivery records
        cursor.execute("""
            SELECT
                d.delivery_id,
                d.order_id,
                u.full_name,
                dl.location_name,
                d.delivery_address,
                d.delivery_fee,
                d.delivery_status,
                d.created_at
            FROM deliveries d
            INNER JOIN orders o
                ON d.order_id = o.order_id
            INNER JOIN users u
                ON o.customer_id = u.user_id
            INNER JOIN delivery_locations dl
                ON d.location_id = dl.location_id
            ORDER BY d.created_at DESC
        """)

        deliveries = cursor.fetchall()

        # Get all available delivery locations for the map
        cursor.execute("""
            SELECT
                location_id,
                location_name,
                delivery_fee
            FROM delivery_locations
            ORDER BY location_name ASC
        """)

        locations = cursor.fetchall()

        return render_template(
            "admin_deliveries.html",
            deliveries=deliveries,
            locations=locations
        )

    except Exception as error:
        print("Admin Deliveries Error:", error)

        flash(
            "Unable to load delivery records.",
            "error"
        )

        return redirect(url_for("admin_dashboard"))

    finally:
        cursor.close()

                

# =========================
# REPORTS
# =========================


@app.route("/admin/reports")
@login_required
@role_required("admin")
def admin_reports():

    cursor = mysql.connection.cursor()

    start_date = request.args.get("start_date", "").strip()
    end_date = request.args.get("end_date", "").strip()

    conditions = []
    params = []

    try:
        # Validate date format
        if start_date:
            datetime.strptime(start_date, "%Y-%m-%d")

        if end_date:
            datetime.strptime(end_date, "%Y-%m-%d")

        # Validate date range
        if start_date and end_date and start_date > end_date:
            flash(
                "Start date cannot be later than end date.",
                "error"
            )
            return redirect(url_for("admin_reports"))

        # Date filter
        if start_date:
            conditions.append("DATE(s.sale_date) >= %s")
            params.append(start_date)

        if end_date:
            conditions.append("DATE(s.sale_date) <= %s")
            params.append(end_date)

        where_clause = ""

        if conditions:
            where_clause = "WHERE " + " AND ".join(conditions)

        # Total Sales and Transactions
        cursor.execute(f"""
            SELECT
                COUNT(*),
                COALESCE(SUM(s.total_amount), 0)
            FROM sales s
            {where_clause}
        """, tuple(params))

        summary = cursor.fetchone()

        # Best-Selling Products
        cursor.execute(f"""
            SELECT
                oi.product_name,
                oi.variant_name,
                SUM(oi.quantity) AS total_quantity
            FROM order_items oi
            INNER JOIN sales s
                ON oi.order_id = s.order_id
            {where_clause}
            GROUP BY oi.product_name, oi.variant_name
            ORDER BY total_quantity DESC, oi.product_name ASC
            LIMIT 10
        """, tuple(params))

        best_selling_products = cursor.fetchall()

        # Sales Breakdown by Date
        cursor.execute(f"""
            SELECT
                DATE(s.sale_date) AS sales_date,
                COUNT(*) AS total_transactions,
                SUM(s.total_amount) AS daily_sales
            FROM sales s
            {where_clause}
            GROUP BY DATE(s.sale_date)
            ORDER BY sales_date DESC
        """, tuple(params))

        daily_sales = cursor.fetchall()

        return render_template(
            "reports.html",
            total_transactions=summary[0],
            total_sales=summary[1],
            best_selling_products=best_selling_products,
            daily_sales=daily_sales,
            start_date=start_date,
            end_date=end_date
        )

    except ValueError:
        flash(
            "Invalid date. Please enter a valid date.",
            "error"
        )
        return redirect(url_for("admin_reports"))

    except Exception as error:
        print("Reports Error:", error)
        flash("Unable to generate reports.", "error")
        return redirect(url_for("admin_dashboard"))

    finally:
        cursor.close()


# =========================
# LOGOUT
# =========================

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("You have successfully logged out.", "success")
    return redirect(url_for("login"))



# ==============================
# ERROR HANDLERS
# ==============================

@app.errorhandler(404)
def page_not_found(error):
    return "Page not found.", 404


@app.errorhandler(500)
def internal_server_error(error):
    return "Internal server error. Please try again later.", 500



if __name__ == "__main__":
    app.run(debug=True)
