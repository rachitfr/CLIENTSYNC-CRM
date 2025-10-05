from flask import Flask, render_template, request, redirect, url_for, session, flash, abort 
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import sqlite3
import os
import random
import string
from datetime import datetime, timedelta

DATABASE = "database.db"

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def ensure_db_tables():
    """Create necessary tables if they don't exist (safe, idempotent)."""
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()

    # users
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        institution_name TEXT NOT NULL,
        university_name TEXT,
        role TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # ensure 'active' column exists (for soft-deactivate)
    cur.execute("PRAGMA table_info(users);")
    cols = [r[1] for r in cur.fetchall()]
    if 'active' not in cols:
        try:
            cur.execute("ALTER TABLE users ADD COLUMN active INTEGER DEFAULT 1;")
        except Exception:
            # older SQLite variations could fail, ignore for dev
            pass

    # institutions
    cur.execute("""
    CREATE TABLE IF NOT EXISTS institutions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        city TEXT,
        state TEXT,
        contact_email TEXT,
        contact_phone TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # contacts
    cur.execute("""
    CREATE TABLE IF NOT EXISTS contacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        role TEXT,
        email TEXT,
        phone TEXT,
        institution_id INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(institution_id) REFERENCES institutions(id)
    );
    """)

    # leads
    cur.execute("""
    CREATE TABLE IF NOT EXISTS leads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        contact_id INTEGER,
        institution_id INTEGER,
        source TEXT,
        status TEXT,
        owner_id INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME,
        FOREIGN KEY(contact_id) REFERENCES contacts(id),
        FOREIGN KEY(institution_id) REFERENCES institutions(id),
        FOREIGN KEY(owner_id) REFERENCES users(id)
    );
    """)

    # interactions (emails, calls, conversation items)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS interactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        lead_id INTEGER,
        contact_id INTEGER,
        institution_id INTEGER,
        kind TEXT,
        body TEXT,
        user_id INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(lead_id) REFERENCES leads(id),
        FOREIGN KEY(contact_id) REFERENCES contacts(id),
        FOREIGN KEY(institution_id) REFERENCES institutions(id),
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    """)

    # tasks
    cur.execute("""
    CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        due_at DATETIME,
        owner_id INTEGER,
        lead_id INTEGER,
        status TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(owner_id) REFERENCES users(id),
        FOREIGN KEY(lead_id) REFERENCES leads(id)
    );
    """)

    # billing (very small schema for MRR calc)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS billing (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id INTEGER,
        amount REAL,
        date DATE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # students (new)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS students (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        email TEXT,
        phone TEXT,
        program TEXT,
        institution_id INTEGER,
        advisor_id INTEGER,
        enrolled_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        notes TEXT,
        FOREIGN KEY(institution_id) REFERENCES institutions(id),
        FOREIGN KEY(advisor_id) REFERENCES users(id)
    );
    """)

    # persist small "seen" tables for badges (track what's been viewed by user)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS seen_followups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        lead_id INTEGER NOT NULL,
        seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, lead_id)
    );
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS seen_tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        task_id INTEGER NOT NULL,
        seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, task_id)
    );
    """)

    conn.commit()

    # --- ensure additional lead columns exist (idempotent ALTERs) ---
    cur.execute("PRAGMA table_info(leads);")
    lead_cols = [r[1] for r in cur.fetchall()]

    # desired additional columns
    additional_cols = {
        "student_name": "TEXT",
        "student_email": "TEXT",
        "student_phone": "TEXT",
        "program": "TEXT",
        "notes": "TEXT",
        "follow_up_date": "DATETIME",
        "next_step": "TEXT"
    }

    for col, col_type in additional_cols.items():
        if col not in lead_cols:
            try:
                cur.execute(f"ALTER TABLE leads ADD COLUMN {col} {col_type};")
            except Exception:
                # ignore if fails in older SQLite versions - dev only
                pass

    conn.commit()
    conn.close()

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "replace-this-with-env-secret")

    # Enable Jinja 'do' extension so templates can use {% do ... %} if present
    try:
        app.jinja_env.add_extension('jinja2.ext.do')
    except Exception:
        pass

    # ensure DB and schema
    if not os.path.exists(DATABASE):
        open(DATABASE, 'a').close()
    ensure_db_tables()

    # --- helper functions ---
    def _get_serializer():
        secret = app.config.get("SECRET_KEY")
        if not secret:
            raise RuntimeError("SECRET_KEY not configured")
        return URLSafeTimedSerializer(secret)

    def generate_reset_token(email):
        s = _get_serializer()
        return s.dumps(email, salt="password-reset-salt")

    def verify_reset_token(token, expiration=3600):
        s = _get_serializer()
        try:
            email = s.loads(token, salt="password-reset-salt", max_age=expiration)
        except SignatureExpired:
            return None
        except BadSignature:
            return None
        return email

    def send_reset_email(user_email, token):
        # dev helper: prints reset link
        reset_url = url_for("reset_password", token=token, _external=True)
        print("=== Password reset email (DEV) ===")
        print(f"To: {user_email}")
        print("Reset URL:", reset_url)
        print("==================================")

    def generate_temporary_password(length=10):
        chars = string.ascii_letters + string.digits
        return "".join(random.choice(chars) for _ in range(length))

    def admin_required(func):
        """Simple decorator requiring logged-in Admin."""
        from functools import wraps
        @wraps(func)
        def wrapper(*args, **kwargs):
            if "user_id" not in session:
                flash("Please login first.", "error")
                return redirect(url_for("login"))
            if session.get("role") != "Admin":
                flash("You do not have permission to access this page.", "error")
                return redirect(url_for("dashboard"))
            return func(*args, **kwargs)
        return wrapper

    # -------------------------
    # Small login_required decorator (used by contacts)
    # -------------------------
    from functools import wraps
    def login_required(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if "user_id" not in session:
                flash("Please login first.", "error")
                return redirect(url_for("login"))
            return func(*args, **kwargs)
        return wrapper

    # --- routes (unchanged core ones kept short) ---
    @app.route("/")
    def index():
        return render_template("index.html", year=2025, app_name="CLIENTSYNC CRM")

    @app.route("/signup", methods=["GET", "POST"])
    def signup():
        if request.method == "POST":
            full_name = request.form.get("full_name")
            email = request.form.get("email")
            password = request.form.get("password")
            confirm_password = request.form.get("confirm_password")
            institution = request.form.get("institution")
            university = request.form.get("university")
            # read role from form (new)
            role = (request.form.get("role") or "").strip()

            if not (full_name and email and password and confirm_password and institution and role):
                flash("Please fill all required fields.", "error")
                return redirect(url_for("signup"))
            if password != confirm_password:
                flash("Passwords do not match.", "error")
                return redirect(url_for("signup"))

            # validate role
            if role not in ("Admin", "Faculty", "Counsellor"):
                flash("Invalid role selected.", "error")
                return redirect(url_for("signup"))

            password_hash = generate_password_hash(password)

            # ensure tables
            ensure_db_tables()
            conn = get_db_connection()
            try:
                existing_user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            except sqlite3.OperationalError:
                conn.close()
                ensure_db_tables()
                conn = get_db_connection()
                existing_user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

            if existing_user:
                flash("Email already registered.", "error")
                conn.close()
                return redirect(url_for("signup"))

            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users (full_name, email, password_hash, institution_name, university_name, role, active) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (full_name, email, password_hash, institution, university or "", role, 1)
            )
            conn.commit()
            user_id = cur.lastrowid
            conn.close()

            # auto-login new user and redirect (respect role)
            session["user_id"] = user_id
            session["role"] = role
            session["name"] = full_name
            flash("Signup successful — you are now logged in.", "success")
            return redirect(url_for("dashboard"))

        return render_template("signup.html", app_name="CLIENTSYNC CRM")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            role = request.form.get("role")
            email = request.form.get("email")
            password = request.form.get("password")

            if not (email and password and role):
                flash("Please fill all fields (role, email, password).", "error")
                return redirect(url_for("login"))

            conn = get_db_connection()
            try:
                user = conn.execute("SELECT * FROM users WHERE email = ? AND role = ?", (email, role)).fetchone()
            except sqlite3.OperationalError:
                conn.close()
                ensure_db_tables()
                conn = get_db_connection()
                user = conn.execute("SELECT * FROM users WHERE email = ? AND role = ?", (email, role)).fetchone()

            conn.close()
            if not user:
                flash("Invalid credentials or role.", "error")
                return redirect(url_for("login"))

            # check active — sqlite3.Row doesn't have .get(), so use mapping access safely
            try:
                # prefer explicit column if available; fallback to 1
                active_val = user["active"] if ("active" in user.keys() and user["active"] is not None) else 1
            except Exception:
                active_val = 1

            try:
                if int(active_val) != 1:
                    flash("This account has been deactivated. Contact an administrator.", "error")
                    return redirect(url_for("login"))
            except (ValueError, TypeError):
                # unexpected value in DB; treat as active
                pass

            if not check_password_hash(user["password_hash"], password):
                flash("Invalid credentials.", "error")
                return redirect(url_for("login"))

            session["user_id"] = user["id"]
            session["role"] = user["role"]
            session["name"] = user["full_name"]
            flash(f"Welcome back, {user['full_name']}!", "success")
            return redirect(url_for("dashboard"))

        return render_template("login.html", app_name="CLIENTSYNC CRM")

    @app.route("/logout")
    def logout():
        session.clear()
        flash("Logged out successfully.", "success")
        return redirect(url_for("login"))

    # --- Manage Users (Admin only) ---
    @app.route("/manage-users")
    @admin_required
    def manage_users():
        conn = get_db_connection()
        rows = conn.execute("SELECT id, full_name, email, role, created_at, coalesce(active,1) as active FROM users ORDER BY created_at DESC").fetchall()
        conn.close()
        return render_template("manage_users.html", users=rows, app_name="CLIENTSYNC CRM")

    @app.route("/manage-users/create", methods=["POST"])
    @admin_required
    def manage_users_create():
        full_name = request.form.get("full_name")
        email = request.form.get("email")
        role = request.form.get("role") or "Faculty"
        institution = request.form.get("institution") or "Unknown"
        if not (full_name and email and role):
            flash("Please provide name, email and role.", "error")
            return redirect(url_for("manage_users"))

        temp_password = generate_temporary_password(10)
        password_hash = generate_password_hash(temp_password)

        conn = get_db_connection()
        try:
            conn.execute(
                "INSERT INTO users (full_name, email, password_hash, institution_name, university_name, role, active) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (full_name, email, password_hash, institution, "", role, 1)
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            flash("Email already exists.", "error")
            return redirect(url_for("manage_users"))
        conn.close()

        # For dev: print temporary password & email link; in prod, send email
        print(f"[DEV] Created user {email} with temporary password: {temp_password}")
        flash(f"User created. Temporary password printed to server console.", "success")
        return redirect(url_for("manage_users"))

    @app.route("/manage-users/toggle-active/<int:user_id>", methods=["POST"])
    @admin_required
    def manage_users_toggle_active(user_id):
        conn = get_db_connection()
        user = conn.execute("SELECT id, full_name, email, coalesce(active,1) as active FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            conn.close()
            flash("User not found.", "error")
            return redirect(url_for("manage_users"))
        new_state = 0 if user["active"] == 1 else 1
        conn.execute("UPDATE users SET active = ? WHERE id = ?", (new_state, user_id))
        conn.commit()
        conn.close()
        flash("User status updated.", "success")
        return redirect(url_for("manage_users"))

    @app.route("/manage-users/change-role", methods=["POST"])
    @admin_required
    def manage_users_change_role():
        user_id = request.form.get("user_id")
        new_role = request.form.get("role")
        if not (user_id and new_role):
            flash("Invalid input.", "error")
            return redirect(url_for("manage_users"))
        conn = get_db_connection()
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
        conn.commit()
        conn.close()
        flash("Role updated.", "success")
        return redirect(url_for("manage_users"))

    @app.route("/manage-users/reset-password", methods=["POST"])
    @admin_required
    def manage_users_reset_password():
        user_id = request.form.get("user_id")
        if not user_id:
            flash("Invalid input.", "error")
            return redirect(url_for("manage_users"))
        conn = get_db_connection()
        user = conn.execute("SELECT email FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            conn.close()
            flash("User not found.", "error")
            return redirect(url_for("manage_users"))
        temp_password = generate_temporary_password(10)
        password_hash = generate_password_hash(temp_password)
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))
        conn.commit()
        conn.close()

        # For dev: print temporary password & token
        token = generate_reset_token(user["email"])
        print(f"[DEV] Password reset for {user['email']}. Temporary password: {temp_password}")
        print(f"[DEV] Reset link (dev): {url_for('reset_password', token=token, _external=True)}")

        flash("Password reset — temporary password printed to server console.", "success")
        return redirect(url_for("manage_users"))
    
    @app.route("/delete-user/<int:user_id>", methods=["POST"])
    def delete_user(user_id):
        if "user_id" not in session or session.get("role") != "Admin":
            flash("Unauthorized.", "error")
            return redirect(url_for("login"))

        conn = get_db_connection()
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()

        flash("User deleted successfully.", "success")
        return redirect(url_for("manage_users"))

    # -------------------------
    # Institutions CRUD (new)
    # ------------------------- 
    @app.route("/institutions")
    def institutions():
        # require login to view
        if "user_id" not in session:
            flash("Please login first.", "error")
            return redirect(url_for("login"))

        conn = get_db_connection()
        try:
            rows = conn.execute("SELECT id, name, city, state, contact_email, contact_phone, created_at FROM institutions ORDER BY created_at DESC").fetchall()
        except sqlite3.OperationalError:
            rows = []
        conn.close()
        return render_template("institutions.html", institutions=rows, app_name="CLIENTSYNC CRM")

    # NOTE: allow Counsellor to create institutions (and Admin). Editing/deleting remains Admin-only.
    @app.route("/institutions/create", methods=["GET", "POST"])
    @login_required
    def institutions_create():
        # Only Admins and Counsellors may create institutions
        if session.get("role") not in ("Admin", "Counsellor"):
            flash("You do not have permission to add institutions.", "error")
            return redirect(url_for("institutions"))

        if request.method == "POST":
            name = (request.form.get("name") or "").strip()
            city = (request.form.get("city") or "").strip()
            state = (request.form.get("state") or "").strip()
            contact_email = (request.form.get("contact_email") or "").strip()
            contact_phone = (request.form.get("contact_phone") or "").strip()

            if not name:
                flash("Institution name is required.", "error")
                return redirect(url_for("institutions_create"))

            conn = get_db_connection()
            conn.execute(
                "INSERT INTO institutions (name, city, state, contact_email, contact_phone) VALUES (?, ?, ?, ?, ?)",
                (name, city, state, contact_email, contact_phone)
            )
            conn.commit()
            conn.close()
            flash("Institution created.", "success")
            return redirect(url_for("institutions"))

        # GET: show form
        return render_template("institution_form.html", institution=None, form_action=url_for("institutions_create"), app_name="CLIENTSYNC CRM")

    @app.route("/institutions/edit/<int:inst_id>", methods=["GET", "POST"])
    @admin_required
    def institutions_edit(inst_id):
        conn = get_db_connection()
        inst = conn.execute("SELECT * FROM institutions WHERE id = ?", (inst_id,)).fetchone()
        if not inst:
            conn.close()
            flash("Institution not found.", "error")
            return redirect(url_for("institutions"))
        if request.method == "POST":
            name = (request.form.get("name") or "").strip()
            city = (request.form.get("city") or "").strip()
            state = (request.form.get("state") or "").strip()
            contact_email = (request.form.get("contact_email") or "").strip()
            contact_phone = (request.form.get("contact_phone") or "").strip()

            if not name:
                flash("Institution name is required.", "error")
                return redirect(url_for("institutions_edit", inst_id=inst_id))

            conn.execute(
                "UPDATE institutions SET name = ?, city = ?, state = ?, contact_email = ?, contact_phone = ? WHERE id = ?",
                (name, city, state, contact_email, contact_phone, inst_id)
            )
            conn.commit()
            conn.close()
            flash("Institution updated.", "success")
            return redirect(url_for("institutions"))
        conn.close()
        return render_template("institution_form.html", institution=inst, form_action=url_for("institutions_edit", inst_id=inst_id), app_name="CLIENTSYNC CRM")

    @app.route("/institutions/delete/<int:inst_id>", methods=["POST"])
    @admin_required
    def institutions_delete(inst_id):
        conn = get_db_connection()
        inst = conn.execute("SELECT id FROM institutions WHERE id = ?", (inst_id,)).fetchone()
        if not inst:
            conn.close()
            flash("Institution not found.", "error")
            return redirect(url_for("institutions"))
        conn.execute("DELETE FROM institutions WHERE id = ?", (inst_id,))
        conn.commit()
        conn.close()
        flash("Institution deleted.", "success")
        return redirect(url_for("institutions"))

    # -------------------------
    # Contacts module (CRUD)
    # ------------------------- 
    @app.route("/contacts")
    @login_required
    def contacts():
        """List contacts. Optional query param: institution_id to filter, q for search."""
        institution_id = request.args.get("institution_id")
        q = (request.args.get("q") or "").strip()

        conn = get_db_connection()
        base_sql = "SELECT c.id, c.full_name, c.role, c.email, c.phone, c.institution_id, coalesce(inst.name,'—') as institution_name, c.created_at FROM contacts c LEFT JOIN institutions inst ON c.institution_id = inst.id"
        params = []
        where = []
        if institution_id:
            where.append("c.institution_id = ?")
            params.append(institution_id)
        if q:
            where.append("(c.full_name LIKE ? OR c.email LIKE ? OR c.phone LIKE ?)")
            qparam = f"%{q}%"
            params.extend([qparam, qparam, qparam])
        if where:
            base_sql += " WHERE " + " AND ".join(where)
        base_sql += " ORDER BY c.created_at DESC LIMIT 500"
        rows = conn.execute(base_sql, params).fetchall()
        conn.close()
        return render_template("contacts.html", contacts=rows, q=q, institution_id=institution_id, app_name="CLIENTSYNC CRM")

    @app.route("/contacts/create", methods=["GET", "POST"])
    @login_required
    def contacts_create():
        conn = get_db_connection()
        institutions = conn.execute("SELECT id, name FROM institutions ORDER BY name").fetchall()
        conn.close()

        if request.method == "POST":
            full_name = (request.form.get("full_name") or "").strip()
            role = (request.form.get("role") or "").strip()
            email = (request.form.get("email") or "").strip()
            phone = (request.form.get("phone") or "").strip()
            institution_id = request.form.get("institution_id") or None

            if not full_name:
                flash("Please provide contact name.", "error")
                return redirect(url_for("contacts_create"))

            conn = get_db_connection()
            conn.execute("INSERT INTO contacts (full_name, role, email, phone, institution_id) VALUES (?, ?, ?, ?, ?)",
                         (full_name, role, email, phone, institution_id))
            conn.commit()
            conn.close()
            flash("Contact created.", "success")
            return redirect(url_for("contacts"))

        return render_template("contact_form.html", institutions=institutions, contact=None, form_action=url_for("contacts_create"), app_name="CLIENTSYNC CRM")

    @app.route("/contacts/<int:contact_id>/edit", methods=["GET", "POST"])
    @login_required
    def contacts_edit(contact_id):
        conn = get_db_connection()
        contact = conn.execute("SELECT * FROM contacts WHERE id = ?", (contact_id,)).fetchone()
        institutions = conn.execute("SELECT id, name FROM institutions ORDER BY name").fetchall()
        conn.close()
        if not contact:
            flash("Contact not found.", "error")
            return redirect(url_for("contacts"))

        if request.method == "POST":
            full_name = (request.form.get("full_name") or "").strip()
            role = (request.form.get("role") or "").strip()
            email = (request.form.get("email") or "").strip()
            phone = (request.form.get("phone") or "").strip()
            institution_id = request.form.get("institution_id") or None

            if not full_name:
                flash("Please provide contact name.", "error")
                return redirect(url_for("contacts_edit", contact_id=contact_id))

            conn = get_db_connection()
            conn.execute("UPDATE contacts SET full_name = ?, role = ?, email = ?, phone = ?, institution_id = ? WHERE id = ?",
                         (full_name, role, email, phone, institution_id, contact_id))
            conn.commit()
            conn.close()
            flash("Contact updated.", "success")
            return redirect(url_for("contacts"))

        return render_template("contact_form.html", institutions=institutions, contact=contact, form_action=url_for("contacts_edit", contact_id=contact_id), app_name="CLIENTSYNC CRM")

    @app.route("/contacts/<int:contact_id>/delete", methods=["POST"])
    @login_required
    def contacts_delete(contact_id):
        conn = get_db_connection()
        conn.execute("DELETE FROM contacts WHERE id = ?", (contact_id,))
        conn.commit()
        conn.close()
        flash("Contact deleted.", "success")
        return redirect(url_for("contacts"))

    # -------------------------
    # Students module (CRUD) - new
    # -------------------------
    @app.route("/students")
    @login_required
    def students():
        """List students. Admin sees all; Faculty sees only their students."""
        q = (request.args.get("q") or "").strip()
        inst = request.args.get("institution_id") or None

        conn = get_db_connection()
        base_sql = """
            SELECT s.*, coalesce(inst.name, '—') as institution_name, u.full_name as advisor_name
            FROM students s
            LEFT JOIN institutions inst ON s.institution_id = inst.id
            LEFT JOIN users u ON s.advisor_id = u.id
        """
        where = []
        params = []
        # faculty sees only their students
        if session.get("role") == "Faculty":
            where.append("s.advisor_id = ?")
            params.append(session.get("user_id"))
        if inst:
            where.append("s.institution_id = ?")
            params.append(inst)
        if q:
            where.append("(s.full_name LIKE ? OR s.email LIKE ? OR s.phone LIKE ? OR s.program LIKE ?)")
            qparam = f"%{q}%"
            params.extend([qparam, qparam, qparam, qparam])
        if where:
            base_sql += " WHERE " + " AND ".join(where)
        base_sql += " ORDER BY s.enrolled_at DESC LIMIT 1000"

        rows = conn.execute(base_sql, params).fetchall()
        institutions = conn.execute("SELECT id, name FROM institutions ORDER BY name").fetchall()
        users = conn.execute("SELECT id, full_name FROM users WHERE role IN ('Faculty','Counsellor','Admin') ORDER BY full_name").fetchall()
        conn.close()
        return render_template("students.html", students=rows, q=q, institutions=institutions, users=users, app_name="CLIENTSYNC CRM")

    @app.route("/students/create", methods=["GET", "POST"])
    @login_required
    def students_create():
        conn = get_db_connection()
        institutions = conn.execute("SELECT id, name FROM institutions ORDER BY name").fetchall()
        advisors = conn.execute("SELECT id, full_name FROM users WHERE role = 'Faculty' ORDER BY full_name").fetchall()
        conn.close()

        if request.method == "POST":
            full_name = (request.form.get("full_name") or "").strip()
            email = (request.form.get("email") or "").strip()
            phone = (request.form.get("phone") or "").strip()
            program = (request.form.get("program") or "").strip()
            institution_id = request.form.get("institution_id") or None
            advisor_id = request.form.get("advisor_id") or None
            notes = (request.form.get("notes") or "").strip()
            if not full_name:
                flash("Please provide student name.", "error")
                return redirect(url_for("students_create"))
            # if logged-in faculty creating, default advisor to them unless explicitly set
            if session.get("role") == "Faculty" and not advisor_id:
                advisor_id = session.get("user_id")

            conn = get_db_connection()
            conn.execute(
                "INSERT INTO students (full_name, email, phone, program, institution_id, advisor_id, notes, enrolled_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (full_name, email, phone, program, institution_id if institution_id else None, advisor_id if advisor_id else None, notes, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            )
            conn.commit()
            conn.close()
            flash("Student created.", "success")
            return redirect(url_for("students"))

        return render_template("student_form.html", student=None, institutions=institutions, advisors=advisors, form_action=url_for("students_create"), app_name="CLIENTSYNC CRM")

    @app.route("/students/edit/<int:student_id>", methods=["GET", "POST"])
    @login_required
    def students_edit(student_id):
        conn = get_db_connection()
        student = conn.execute("SELECT * FROM students WHERE id = ?", (student_id,)).fetchone()
        if not student:
            conn.close()
            flash("Student not found.", "error")
            return redirect(url_for("students"))
        institutions = conn.execute("SELECT id, name FROM institutions ORDER BY name").fetchall()
        advisors = conn.execute("SELECT id, full_name FROM users WHERE role = 'Faculty' ORDER BY full_name").fetchall()
        conn.close()

        # protect: faculty may only edit their own students (unless Admin)
        if session.get("role") == "Faculty" and student["advisor_id"] != session.get("user_id"):
            flash("You are not authorized to edit this student.", "error")
            return redirect(url_for("students"))

        if request.method == "POST":
            full_name = (request.form.get("full_name") or "").strip()
            email = (request.form.get("email") or "").strip()
            phone = (request.form.get("phone") or "").strip()
            program = (request.form.get("program") or "").strip()
            institution_id = request.form.get("institution_id") or None
            advisor_id = request.form.get("advisor_id") or None
            notes = (request.form.get("notes") or "").strip()
            if not full_name:
                flash("Please provide student name.", "error")
                return redirect(url_for("students_edit", student_id=student_id))

            conn = get_db_connection()
            conn.execute(
                "UPDATE students SET full_name = ?, email = ?, phone = ?, program = ?, institution_id = ?, advisor_id = ?, notes = ? WHERE id = ?",
                (full_name, email, phone, program, institution_id if institution_id else None, advisor_id if advisor_id else None, notes, student_id)
            )
            conn.commit()
            conn.close()
            flash("Student updated.", "success")
            return redirect(url_for("students"))

        return render_template("student_form.html", student=student, institutions=institutions, advisors=advisors, form_action=url_for("students_edit", student_id=student_id), app_name="CLIENTSYNC CRM")

    @app.route("/students/delete/<int:student_id>", methods=["POST"])
    @login_required
    def students_delete(student_id):
        conn = get_db_connection()
        student = conn.execute("SELECT * FROM students WHERE id = ?", (student_id,)).fetchone()
        if not student:
            conn.close()
            flash("Student not found.", "error")
            return redirect(url_for("students"))
        # protect delete: admin or advisor
        allowed = False
        try:
            if session.get("role") == "Admin" or (session.get("role") == "Faculty" and student["advisor_id"] == session.get("user_id")):
                allowed = True
        except Exception:
            allowed = False
        if not allowed:
            conn.close()
            flash("Unauthorized.", "error")
            return redirect(url_for("students"))
        conn.execute("DELETE FROM students WHERE id = ?", (student_id,))
        conn.commit()
        conn.close()
        flash("Student deleted.", "success")
        return redirect(url_for("students"))

    @app.route("/students/<int:student_id>")
    @login_required
    def students_detail(student_id):
        conn = get_db_connection()
        s = conn.execute("""
            SELECT s.*, coalesce(inst.name,'—') as institution_name, u.full_name as advisor_name
            FROM students s
            LEFT JOIN institutions inst ON s.institution_id = inst.id
            LEFT JOIN users u ON s.advisor_id = u.id
            WHERE s.id = ?
        """, (student_id,)).fetchone()
        conn.close()
        if not s:
            flash("Student not found.", "error")
            return redirect(url_for("students"))
        # restrict view for faculty to their own students
        if session.get("role") == "Faculty" and s["advisor_id"] != session.get("user_id"):
            flash("Unauthorized to view this student's details.", "error")
            return redirect(url_for("students"))
        return render_template("student_detail.html", student=s, app_name="CLIENTSYNC CRM")

    # -------------------------
    # Leads module (CRUD) + Interactions
    # -------------------------
    @app.route("/leads")
    @login_required
    def leads():
        """List leads. Optional filters: contact_id, institution_id, q (search), status."""
        contact_id = request.args.get("contact_id")
        institution_id = request.args.get("institution_id")
        status = (request.args.get("status") or "").strip()
        q = (request.args.get("q") or "").strip()

        base_sql = """
            SELECT l.id, l.contact_id, l.institution_id, l.source, l.status, l.owner_id,
                   l.created_at, l.updated_at,
                   l.student_name, l.student_email, l.student_phone, l.program, l.notes, l.follow_up_date, l.next_step,
                   c.full_name as contact_name, c.phone as contact_phone, coalesce(inst.name, '—') as institution_name,
                   u.full_name as owner_name
            FROM leads l
            LEFT JOIN contacts c ON l.contact_id = c.id
            LEFT JOIN institutions inst ON l.institution_id = inst.id
            LEFT JOIN users u ON l.owner_id = u.id
        """
        where = []
        params = []
        if contact_id:
            where.append("l.contact_id = ?")
            params.append(contact_id)
        if institution_id:
            where.append("l.institution_id = ?")
            params.append(institution_id)
        if status:
            where.append("l.status = ?")
            params.append(status)
        if q:
            # search across student name, contact, institution, phone, source
            where.append("(l.student_name LIKE ? OR c.full_name LIKE ? OR inst.name LIKE ? OR l.student_phone LIKE ? OR l.source LIKE ?)")
            qparam = f"%{q}%"
            params.extend([qparam, qparam, qparam, qparam, qparam])

        if where:
            base_sql += " WHERE " + " AND ".join(where)

        base_sql += " ORDER BY l.created_at DESC LIMIT 500"

        conn = get_db_connection()
        rows = conn.execute(base_sql, params).fetchall()
        # fetch lists for filters/creation
        contacts = conn.execute("SELECT id, full_name FROM contacts ORDER BY full_name").fetchall()
        institutions = conn.execute("SELECT id, name FROM institutions ORDER BY name").fetchall()
        users = conn.execute("SELECT id, full_name FROM users ORDER BY full_name").fetchall()
        conn.close()
        return render_template("leads.html", leads=rows, contacts=contacts, institutions=institutions, users=users, q=q, status=status, app_name="CLIENTSYNC CRM")


    @app.route("/leads/create", methods=["GET", "POST"])
    @login_required
    def leads_create():
        conn = get_db_connection()
        contacts = conn.execute("SELECT id, full_name FROM contacts ORDER BY full_name").fetchall()
        institutions = conn.execute("SELECT id, name FROM institutions ORDER BY name").fetchall()
        users = conn.execute("SELECT id, full_name FROM users ORDER BY full_name").fetchall()
        conn.close()

        if request.method == "POST":
            # fields from the form (student-focused)
            student_name = (request.form.get("student_name") or "").strip()
            student_email = (request.form.get("student_email") or "").strip()
            student_phone = (request.form.get("student_phone") or "").strip()
            program = (request.form.get("program") or "").strip()
            source = (request.form.get("source") or "").strip()
            contact_id = request.form.get("contact_id") or None
            institution_id = request.form.get("institution_id") or None
            status = (request.form.get("status") or "New").strip()
            owner_id = request.form.get("owner_id") or session.get("user_id")
            notes = (request.form.get("notes") or "").strip()
            follow_up_date = (request.form.get("follow_up_date") or "").strip()
            next_step = (request.form.get("next_step") or "").strip()

            # minimal validation per your spec (counsellor inputs required fields)
            if not (student_name and student_email and student_phone and program and source):
                flash("Please provide Student name, Email, Phone, Program and Source.", "error")
                return redirect(url_for("leads_create"))

            # If institution_id is missing but contact_id is provided, try to infer institution_id from the contact
            try:
                if (not institution_id) and contact_id:
                    conn = get_db_connection()
                    contact_row = conn.execute("SELECT institution_id FROM contacts WHERE id = ?", (contact_id,)).fetchone()
                    if contact_row and contact_row["institution_id"]:
                        institution_id = contact_row["institution_id"]
                    conn.close()
            except Exception:
                # non-critical; proceed with None if lookup failed
                pass

            conn = get_db_connection()
            cur = conn.cursor()
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            # include optional fields in insert (use named columns)
            cur.execute(
                """INSERT INTO leads 
                   (contact_id, institution_id, source, status, owner_id, created_at, updated_at,
                    student_name, student_email, student_phone, program, notes, follow_up_date, next_step)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (contact_id, institution_id, source, status, owner_id, now, now,
                 student_name, student_email, student_phone, program, notes, follow_up_date if follow_up_date else None, next_step)
            )
            conn.commit()
            conn.close()
            flash("Lead created.", "success")
            return redirect(url_for("leads"))

        # GET: show form
        return render_template("lead_form.html", lead=None, contacts=contacts, institutions=institutions, users=users, form_action=url_for("leads_create"), app_name="CLIENTSYNC CRM")


    @app.route("/leads/edit/<int:lead_id>", methods=["GET", "POST"])
    @login_required
    def leads_edit(lead_id):
        conn = get_db_connection()
        lead = conn.execute("SELECT * FROM leads WHERE id = ?", (lead_id,)).fetchone()
        if not lead:
            conn.close()
            flash("Lead not found.", "error")
            return redirect(url_for("leads"))

        contacts = conn.execute("SELECT id, full_name FROM contacts ORDER BY full_name").fetchall()
        institutions = conn.execute("SELECT id, name FROM institutions ORDER BY name").fetchall()
        users = conn.execute("SELECT id, full_name FROM users ORDER BY full_name").fetchall()
        conn.close()

        if request.method == "POST":
            student_name = (request.form.get("student_name") or "").strip()
            student_email = (request.form.get("student_email") or "").strip()
            student_phone = (request.form.get("student_phone") or "").strip()
            program = (request.form.get("program") or "").strip()
            source = (request.form.get("source") or "").strip()
            contact_id = request.form.get("contact_id") or None
            institution_id = request.form.get("institution_id") or None
            status = (request.form.get("status") or "New").strip()
            owner_id = request.form.get("owner_id") or session.get("user_id")
            notes = (request.form.get("notes") or "").strip()
            follow_up_date = (request.form.get("follow_up_date") or "").strip()
            next_step = (request.form.get("next_step") or "").strip()

            # minimal validation
            if not (student_name and student_email and student_phone and program and source):
                flash("Please provide Student name, Email, Phone, Program and Source.", "error")
                return redirect(url_for("leads_edit", lead_id=lead_id))

            # If institution_id is missing but contact_id is provided, try to infer institution_id from the contact
            try:
                if (not institution_id) and contact_id:
                    conn = get_db_connection()
                    contact_row = conn.execute("SELECT institution_id FROM contacts WHERE id = ?", (contact_id,)).fetchone()
                    if contact_row and contact_row["institution_id"]:
                        institution_id = contact_row["institution_id"]
                    conn.close()
            except Exception:
                # non-critical; proceed with None if lookup failed
                pass

            # update
            conn = get_db_connection()
            conn.execute(
                """UPDATE leads 
                   SET contact_id = ?, institution_id = ?, source = ?, status = ?, owner_id = ?, updated_at = ?,
                       student_name = ?, student_email = ?, student_phone = ?, program = ?, notes = ?, follow_up_date = ?, next_step = ?
                   WHERE id = ?""",
                (contact_id, institution_id, source, status, owner_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                 student_name, student_email, student_phone, program, notes, follow_up_date if follow_up_date else None, next_step, lead_id)
            )
            conn.commit()
            conn.close()
            flash("Lead updated.", "success")
            return redirect(url_for("leads"))

        return render_template("lead_form.html", lead=lead, contacts=contacts, institutions=institutions, users=users, form_action=url_for("leads_edit", lead_id=lead_id), app_name="CLIENTSYNC CRM")


    @app.route("/leads/delete/<int:lead_id>", methods=["POST"])
    @login_required
    def leads_delete(lead_id):
        # allow deletion by Admin or lead owner
        conn = get_db_connection()
        lead = conn.execute("SELECT id, owner_id FROM leads WHERE id = ?", (lead_id,)).fetchone()
        if not lead:
            conn.close()
            flash("Lead not found.", "error")
            return redirect(url_for("leads"))
        allowed = False
        try:
            if session.get("role") == "Admin":
                allowed = True
            elif session.get("user_id") == lead["owner_id"]:
                allowed = True
        except Exception:
            allowed = False

        if not allowed:
            conn.close()
            flash("Unauthorized to delete this lead.", "error")
            return redirect(url_for("leads"))

        conn.execute("DELETE FROM leads WHERE id = ?", (lead_id,))
        conn.execute("DELETE FROM interactions WHERE lead_id = ?", (lead_id,))
        conn.commit()
        conn.close()
        flash("Lead and its interactions deleted.", "success")
        return redirect(url_for("leads"))


    @app.route("/leads/<int:lead_id>")
    @login_required
    def leads_detail(lead_id):
        conn = get_db_connection()
        # Show institution name by preferring lead.institution_id, and fallback to contact's institution if lead doesn't have one.
        lead = conn.execute("""
            SELECT l.*, c.full_name as contact_name, c.phone as contact_phone,
                   COALESCE(inst.name,
                            (SELECT name FROM institutions WHERE id = c.institution_id),
                            '') as institution_name,
                   u.full_name as owner_name
            FROM leads l
            LEFT JOIN contacts c ON l.contact_id = c.id
            LEFT JOIN institutions inst ON l.institution_id = inst.id
            LEFT JOIN users u ON l.owner_id = u.id
            WHERE l.id = ?
        """, (lead_id,)).fetchone()
        if not lead:
            conn.close()
            flash("Lead not found.", "error")
            return redirect(url_for("leads"))

        interactions = conn.execute("""
            SELECT i.id, i.kind, i.body, i.created_at, u.full_name as created_by
            FROM interactions i
            LEFT JOIN users u ON i.user_id = u.id
            WHERE i.lead_id = ?
            ORDER BY i.created_at DESC
            LIMIT 200
        """, (lead_id,)).fetchall()

        # provide dropdown data for adding interaction inline
        users = conn.execute("SELECT id, full_name FROM users ORDER BY full_name").fetchall()

        # If this lead has a follow_up_date and the current user is the owner,
        # mark it as "seen" so dashboard badge will decrease for this user.
        try:
            uid = session.get("user_id")
            if uid and lead["follow_up_date"] and lead["owner_id"] == uid:
                try:
                    conn.execute("INSERT OR IGNORE INTO seen_followups (user_id, lead_id, seen_at) VALUES (?, ?, ?)",
                                 (uid, lead_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                    conn.commit()
                except Exception:
                    # non-critical
                    pass
        except Exception:
            pass

        conn.close()
        return render_template("lead_detail.html", lead=lead, interactions=interactions, users=users, app_name="CLIENTSYNC CRM")

    # Interactions: create (used for notes / emails / calls attached to a lead)
    @app.route("/interactions/create", methods=["POST"])
    @login_required
    def interactions_create():
        lead_id = request.form.get("lead_id") or None
        contact_id = request.form.get("contact_id") or None
        institution_id = request.form.get("institution_id") or None
        kind = (request.form.get("kind") or "note").strip()
        body = (request.form.get("body") or "").strip()
        user_id = session.get("user_id")

        if not (body and (lead_id or contact_id or institution_id)):
            flash("Interaction must have some text and be linked to a lead/contact/institution.", "error")
            return redirect(request.referrer or url_for("dashboard"))

        conn = get_db_connection()
        conn.execute(
            "INSERT INTO interactions (lead_id, contact_id, institution_id, kind, body, user_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (lead_id, contact_id, institution_id, kind, body, user_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        conn.commit()
        conn.close()
        flash("Interaction saved.", "success")
        # redirect back to lead detail if available
        if lead_id:
            return redirect(url_for("leads_detail", lead_id=lead_id))
        return redirect(request.referrer or url_for("dashboard"))

    # -------------------------
    # Tasks module (CRUD) - new routes
    # -------------------------
    @app.route("/tasks")
    @login_required
    def tasks():
        """List tasks with optional search and owner filter."""
        q = (request.args.get("q") or "").strip()
        owner = request.args.get("owner") or None

        # Default owner-scoping: if user is Faculty or Counsellor and no explicit owner param,
        # show only their tasks by default to avoid exposing other roles' tasks.
        role = session.get("role")
        uid = session.get("user_id")
        if role in ("Faculty", "Counsellor") and not owner:
            owner = str(uid)

        base_sql = """
            SELECT t.*, u.full_name as owner_name, l.student_name
            FROM tasks t
            LEFT JOIN users u ON t.owner_id = u.id
            LEFT JOIN leads l ON t.lead_id = l.id
        """
        where = []
        params = []
        if owner:
            where.append("t.owner_id = ?")
            params.append(owner)
        if q:
            where.append("(t.title LIKE ? OR t.description LIKE ? OR l.student_name LIKE ?)")
            qparam = f"%{q}%"
            params.extend([qparam, qparam, qparam])
        if where:
            base_sql += " WHERE " + " AND ".join(where)
        base_sql += " ORDER BY COALESCE(t.due_at, t.created_at) ASC LIMIT 500"

        conn = get_db_connection()
        rows = conn.execute(base_sql, params).fetchall()
        users = conn.execute("SELECT id, full_name FROM users ORDER BY full_name").fetchall()

        # Mark open tasks for current user as "seen" when they visit the tasks page,
        # so the dashboard's open-task badge will decrease.
        try:
            uid = session.get("user_id")
            if uid:
                # insert seen records for tasks owned by this user and incomplete
                try:
                    open_tasks = conn.execute("SELECT id FROM tasks WHERE owner_id = ? AND (status IS NULL OR status != 'done')", (uid,)).fetchall()
                    for t in open_tasks:
                        try:
                            conn.execute("INSERT OR IGNORE INTO seen_tasks (user_id, task_id, seen_at) VALUES (?, ?, ?)",
                                         (uid, t["id"], datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                        except Exception:
                            pass
                    conn.commit()
                except Exception:
                    pass
        except Exception:
            pass

        conn.close()
        return render_template("tasks.html", tasks=rows, users=users, app_name="CLIENTSYNC CRM")

    @app.route("/tasks/create", methods=["GET", "POST"])
    @login_required
    def tasks_create():
        conn = get_db_connection()
        users = conn.execute("SELECT id, full_name FROM users ORDER BY full_name").fetchall()

        # --- key change: for Faculty present their students as the "leads" list in template ---
        leads = []
        try:
            if session.get("role") == "Faculty":
                uid = session.get("user_id")
                # present students as items with id and student_name so the template works unchanged
                leads = conn.execute("SELECT id, full_name as student_name FROM students WHERE advisor_id = ? ORDER BY enrolled_at DESC LIMIT 500", (uid,)).fetchall()
            else:
                leads = conn.execute("SELECT id, student_name FROM leads ORDER BY created_at DESC LIMIT 500").fetchall()
        except Exception:
            leads = []
        conn.close()

        if request.method == "POST":
            title = (request.form.get("title") or "").strip()
            description = (request.form.get("description") or "").strip()
            due_at = (request.form.get("due_at") or "").strip()  # expecting ISO-like string from datetime-local
            owner_id = request.form.get("owner_id") or session.get("user_id")
            lead_id = request.form.get("lead_id") or None
            status = (request.form.get("status") or "").strip()

            if not title:
                flash("Please provide a title for the task.", "error")
                return redirect(url_for("tasks_create"))

            conn = get_db_connection()
            conn.execute(
                "INSERT INTO tasks (title, description, due_at, owner_id, lead_id, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (title, description, due_at if due_at else None, owner_id, lead_id if lead_id else None, status if status else None, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            )
            conn.commit()
            conn.close()
            flash("Task created.", "success")
            return redirect(url_for("tasks"))

        return render_template("task_form.html", task=None, users=users, leads=leads, form_action=url_for("tasks_create"), app_name="CLIENTSYNC CRM")

    @app.route("/tasks/edit/<int:task_id>", methods=["GET", "POST"])
    @login_required
    def tasks_edit(task_id):
        conn = get_db_connection()
        task = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if not task:
            conn.close()
            flash("Task not found.", "error")
            return redirect(url_for("tasks"))

        users = conn.execute("SELECT id, full_name FROM users ORDER BY full_name").fetchall()

        # --- key change: when editing, present students to Faculty; otherwise show leads ---
        leads = []
        try:
            if session.get("role") == "Faculty":
                uid = session.get("user_id")
                leads = conn.execute("SELECT id, full_name as student_name FROM students WHERE advisor_id = ? ORDER BY enrolled_at DESC LIMIT 500", (uid,)).fetchall()
            else:
                leads = conn.execute("SELECT id, student_name FROM leads ORDER BY created_at DESC LIMIT 500").fetchall()
        except Exception:
            leads = []

        # Authorization: only Admin or the owner may edit
        allowed = False
        try:
            if session.get("role") == "Admin" or session.get("user_id") == task["owner_id"]:
                allowed = True
        except Exception:
            allowed = False

        if not allowed:
            conn.close()
            flash("You are not authorized to edit this task.", "error")
            return redirect(url_for("tasks"))

        if request.method == "POST":
            title = (request.form.get("title") or "").strip()
            description = (request.form.get("description") or "").strip()
            due_at = (request.form.get("due_at") or "").strip()
            owner_id = request.form.get("owner_id") or session.get("user_id")
            lead_id = request.form.get("lead_id") or None
            status = (request.form.get("status") or "").strip()

            if not title:
                conn.close()
                flash("Please provide a title for the task.", "error")
                return redirect(url_for("tasks_edit", task_id=task_id))

            conn.execute(
                "UPDATE tasks SET title = ?, description = ?, due_at = ?, owner_id = ?, lead_id = ?, status = ? WHERE id = ?",
                (title, description, due_at if due_at else None, owner_id, lead_id if lead_id else None, status if status else None, task_id)
            )
            conn.commit()
            conn.close()
            flash("Task updated.", "success")
            return redirect(url_for("tasks"))

        conn.close()
        return render_template("task_form.html", task=task, users=users, leads=leads, form_action=url_for("tasks_edit", task_id=task_id), app_name="CLIENTSYNC CRM")

    @app.route("/tasks/complete/<int:task_id>", methods=["POST"])
    @login_required
    def tasks_complete(task_id):
        conn = get_db_connection()
        t = conn.execute("SELECT id, owner_id FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if not t:
            conn.close()
            flash("Task not found.", "error")
            return redirect(url_for("tasks"))
        # allow completion by owner or admin
        allowed = False
        try:
            if session.get("role") == "Admin" or session.get("user_id") == t["owner_id"]:
                allowed = True
        except Exception:
            allowed = False
        if not allowed:
            conn.close()
            flash("Unauthorized.", "error")
            return redirect(url_for("tasks"))
        conn.execute("UPDATE tasks SET status = ? WHERE id = ?", ("done", task_id))
        conn.commit()
        conn.close()
        flash("Task marked as complete.", "success")
        return redirect(url_for("tasks"))

    @app.route("/tasks/delete/<int:task_id>", methods=["POST"])
    @login_required
    def tasks_delete(task_id):
        conn = get_db_connection()
        t = conn.execute("SELECT id, owner_id FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if not t:
            conn.close()
            flash("Task not found.", "error")
            return redirect(url_for("tasks"))
        # allow delete by owner or admin
        allowed = False
        try:
            if session.get("role") == "Admin" or session.get("user_id") == t["owner_id"]:
                allowed = True
        except Exception:
            allowed = False
        if not allowed:
            conn.close()
            flash("Unauthorized.", "error")
            return redirect(url_for("tasks"))
        conn.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
        conn.commit()
        conn.close()
        flash("Task deleted.", "success")
        return redirect(url_for("tasks"))

    # --- Forgot / Reset password (unchanged) ---
    @app.route("/forgot-password", methods=["GET", "POST"])
    def forgot_password():
        if request.method == "POST":
            email = (request.form.get("email") or "").strip().lower()
            if not email:
                flash("Please provide an email address.", "error")
                return redirect(url_for("forgot_password"))
            conn = get_db_connection()
            try:
                user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            except sqlite3.OperationalError:
                user = None
            conn.close()
            if user:
                token = generate_reset_token(user["email"])
                send_reset_email(user["email"], token)
            flash("If that email is registered, we have sent password reset instructions.", "info")
            return redirect(url_for("login"))
        return render_template("forgot_password.html", app_name="CLIENTSYNC CRM")

    @app.route("/reset-password/<token>", methods=["GET", "POST"])
    def reset_password(token):
        email = verify_reset_token(token)
        if not email:
            flash("The reset link is invalid or has expired. Please request a new link.", "error")
            return redirect(url_for("forgot_password"))
        conn = get_db_connection()
        try:
            user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        except sqlite3.OperationalError:
            user = None
        conn.close()
        if not user:
            flash("The reset link is invalid. Please request a new link.", "error")
            return redirect(url_for("forgot_password"))
        if request.method == "POST":
            password = request.form.get("password", "")
            confirm = request.form.get("confirm_password", "")
            if not password or password != confirm:
                flash("Passwords do not match.", "error")
                return redirect(url_for("reset_password", token=token))
            if len(password) < 8:
                flash("Password must be at least 8 characters.", "error")
                return redirect(url_for("reset_password", token=token))
            password_hash = generate_password_hash(password)
            conn = get_db_connection()
            conn.execute("UPDATE users SET password_hash = ? WHERE email = ?", (password_hash, email))
            conn.commit()
            conn.close()
            flash("Your password has been reset. Please log in with your new password.", "success")
            return redirect(url_for("login"))
        return render_template("reset_password.html", token=token, app_name="CLIENTSYNC CRM")

    # --- Dashboard (updated to render role-specific templates) ---
    @app.route("/dashboard")
    def dashboard():
        if "user_id" not in session:
            flash("Please login first.", "error")
            return redirect(url_for("login"))

        name = session.get("name") or "Chinmay Joshi"
        role = session.get("role") or "Faculty"

        # sample data / fallback values
        sample_stats = {
            "institutions": 12,
            "students": 8,
            "students_month": 2,
            "open_tasks": 3,
            "avg_response_time": "2h 10m",
            "last_sync": (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
        }

        # default sample recent activity (used as fallback if DB queries fail)
        sample_recent_activity = [
            {"time": "Today 10:00", "action": "New student enrolled", "contact": "Aarti Shah", "institution": "Green Valley School", "owner": name},
            {"time": "Yesterday 14:30", "action": "Advisor note added", "contact": "Parth Vyas", "institution": "Eastern Technical Institute", "owner": "Chinmay Joshi"},
        ]

        stats = sample_stats.copy()
        recent_activity = sample_recent_activity.copy()
        upcoming_tasks = []
        recent_contacts = []
        open_tasks_count = 0
        students_list = []
        follow_ups = []
        pipeline = {}
        cards = {}

        try:
            conn = get_db_connection()
            # counts relevant to all roles
            try:
                r = conn.execute("SELECT COUNT(*) as c FROM institutions").fetchone()
                stats["institutions"] = r["c"] if r else stats["institutions"]
            except sqlite3.OperationalError:
                pass

            # Faculty-specific stats: student counts
            try:
                if role == "Faculty":
                    uid = session.get("user_id")
                    r = conn.execute("SELECT COUNT(*) as c FROM students WHERE advisor_id = ?", (uid,)).fetchone()
                    stats["students"] = r["c"] if r and "c" in r.keys() else stats.get("students", 0)

                    # students enrolled this month (simple date filter)
                    try:
                        month_start = datetime.now().replace(day=1).strftime("%Y-%m-%d")
                        r2 = conn.execute("SELECT COUNT(*) as c FROM students WHERE advisor_id = ? AND date(enrolled_at) >= date(?)", (uid, month_start)).fetchone()
                        stats["students_month"] = r2["c"] if r2 and "c" in r2.keys() else stats.get("students_month", 0)
                    except Exception:
                        stats["students_month"] = stats.get("students_month", 0)
                else:
                    # global student count for admins/counsellors
                    r = conn.execute("SELECT COUNT(*) as c FROM students").fetchone()
                    stats["students"] = r["c"] if r and "c" in r.keys() else stats.get("students", 0)
            except Exception:
                pass

            # upcoming tasks for roles (owner-scoped for Faculty and Counsellor)
            try:
                uid = session.get("user_id")
                if role == "Faculty" or role == "Counsellor":
                    tasks = conn.execute("SELECT id, title, due_at FROM tasks WHERE owner_id = ? AND (status IS NULL OR status != 'done') ORDER BY due_at ASC LIMIT 6", (uid,)).fetchall()
                    upcoming_tasks = [{"title": t["title"], "due": t["due_at"], "id": t["id"]} for t in tasks]
                else:
                    tasks = conn.execute("SELECT title, due_at FROM tasks WHERE status IS NULL OR status != 'done' ORDER BY due_at ASC LIMIT 6").fetchall()
                    upcoming_tasks = [{"title": t["title"], "due": t["due_at"]} for t in tasks]
            except sqlite3.OperationalError:
                pass

            # recent contacts sample (non-lead based)
            try:
                recent_contacts = conn.execute("SELECT full_name as name, role, (SELECT name FROM institutions WHERE id = contacts.institution_id) as institution_name, created_at FROM contacts ORDER BY created_at DESC LIMIT 5").fetchall()
            except sqlite3.OperationalError:
                pass

            # open tasks count (owner-scoped)
            try:
                uid = session.get("user_id")
                if role == "Faculty" or role == "Counsellor":
                    r = conn.execute("SELECT COUNT(*) as c FROM tasks t WHERE t.owner_id = ? AND (t.status IS NULL OR t.status != 'done')", (uid,)).fetchone()
                    open_tasks_count = r["c"] if r and "c" in r.keys() else 0
                else:
                    r = conn.execute("SELECT COUNT(*) as c FROM tasks t WHERE (t.status IS NULL OR t.status != 'done')").fetchone()
                    open_tasks_count = r["c"] if r and "c" in r.keys() else 0
            except Exception:
                open_tasks_count = 0

            # Build recent_activity from DB but focused on students, interactions, tasks and leads.
            try:
                merged = []

                # get uid early for scoping
                uid = session.get("user_id")

                # recent student enrollments
                if role == "Faculty":
                    student_rows = conn.execute("""
                        SELECT s.id, s.enrolled_at, s.full_name, s.phone, s.program,
                               coalesce(inst.name,'—') as institution_name, u.full_name as advisor_name
                        FROM students s
                        LEFT JOIN institutions inst ON s.institution_id = inst.id
                        LEFT JOIN users u ON s.advisor_id = u.id
                        WHERE s.advisor_id = ?
                        ORDER BY s.enrolled_at DESC
                        LIMIT 6
                    """, (uid,)).fetchall()
                else:
                    student_rows = conn.execute("""
                        SELECT s.id, s.enrolled_at, s.full_name, s.phone, s.program,
                               coalesce(inst.name,'—') as institution_name, u.full_name as advisor_name
                        FROM students s
                        LEFT JOIN institutions inst ON s.institution_id = inst.id
                        LEFT JOIN users u ON s.advisor_id = u.id
                        ORDER BY s.enrolled_at DESC
                        LIMIT 6
                    """).fetchall()

                for r in student_rows:
                    ts = r["enrolled_at"] or ""
                    action = f"Student enrolled: {r['full_name'] or ('Student #' + str(r['id']))}"
                    contact_display = r["phone"] if r["phone"] else "—"
                    institution = r["institution_name"] if r["institution_name"] else "—"
                    merged.append({"time": ts, "action": action, "contact": contact_display,
                                   "institution": institution, "owner": r["advisor_name"] or "—", "student_id": r["id"], "student_name": r["full_name"]})

                # recent interactions (notes/calls/emails)
                if role == "Faculty":
                    inter_rows = conn.execute("""
                        SELECT i.id, i.created_at, i.kind, i.body, u.full_name as user_name,
                               c.full_name as contact_name, c.phone as contact_phone, inst.name as institution_name
                        FROM interactions i
                        LEFT JOIN users u ON i.user_id = u.id
                        LEFT JOIN contacts c ON i.contact_id = c.id
                        LEFT JOIN institutions inst ON i.institution_id = inst.id
                        WHERE i.user_id = ?
                        ORDER BY i.created_at DESC
                        LIMIT 6
                    """, (uid,)).fetchall()
                else:
                    inter_rows = conn.execute("""
                        SELECT i.id, i.created_at, i.kind, i.body, u.full_name as user_name,
                               c.full_name as contact_name, c.phone as contact_phone, inst.name as institution_name
                        FROM interactions i
                        LEFT JOIN users u ON i.user_id = u.id
                        LEFT JOIN contacts c ON i.contact_id = c.id
                        LEFT JOIN institutions inst ON i.institution_id = inst.id
                        ORDER BY i.created_at DESC
                        LIMIT 6
                    """).fetchall()

                for r in inter_rows:
                    ts = r["created_at"] or ""
                    snippet = (r["body"][:80] + '...') if r["body"] and len(r["body"]) > 80 else (r["body"] or '')
                    kind_label = (r["kind"].capitalize() if r["kind"] else "Interaction")
                    action = f"{kind_label}: {snippet or kind_label}"
                    if r["contact_name"]:
                        contact_display = r["contact_name"]
                        if r["contact_phone"]:
                            contact_display += f" · {r['contact_phone']}"
                    else:
                        contact_display = r["contact_phone"] if r["contact_phone"] else "—"
                    institution = r["institution_name"] if r["institution_name"] else "—"
                    merged.append({"time": ts, "action": action, "contact": contact_display,
                                   "institution": institution, "owner": r["user_name"] or "—"})

                # recent tasks - include student (via lead mapping not guaranteed)
                if role == "Faculty":
                    task_rows = conn.execute("""
                        SELECT t.id, t.created_at, t.title, t.due_at, u.full_name as owner_name
                        FROM tasks t
                        LEFT JOIN users u ON t.owner_id = u.id
                        WHERE t.owner_id = ?
                        ORDER BY t.created_at DESC
                        LIMIT 6
                    """, (uid,)).fetchall()
                else:
                    task_rows = conn.execute("""
                        SELECT t.id, t.created_at, t.title, t.due_at, u.full_name as owner_name
                        FROM tasks t
                        LEFT JOIN users u ON t.owner_id = u.id
                        ORDER BY t.created_at DESC
                        LIMIT 6
                    """).fetchall()

                for r in task_rows:
                    ts = r["created_at"] or ""
                    due = r["due_at"][:16] if r["due_at"] else None
                    action = f"Task: {r['title']}"
                    if due:
                        action += f" · due {due}"
                    merged.append({"time": ts, "action": action, "contact": "—",
                                   "institution": "—", "owner": r["owner_name"] or "—"})

                # recent leads (important for Counselors and Admins) - show newly created leads
                try:
                    # For counsellor show their leads; for faculty show their leads; for others, show global
                    uid = session.get("user_id")
                    if role == "Counsellor":
                        lead_rows = conn.execute("""
                            SELECT l.id, l.created_at, l.student_name, l.source, l.follow_up_date, c.full_name as contact_name,
                                   coalesce(inst.name, (SELECT name FROM institutions WHERE id = c.institution_id)) as institution_name, u.full_name as owner_name
                            FROM leads l
                            LEFT JOIN contacts c ON l.contact_id = c.id
                            LEFT JOIN institutions inst ON l.institution_id = inst.id
                            LEFT JOIN users u ON l.owner_id = u.id
                            WHERE l.owner_id = ?
                            ORDER BY l.created_at DESC
                            LIMIT 6
                        """, (uid,)).fetchall()
                    elif role == "Faculty":
                        lead_rows = conn.execute("""
                            SELECT l.id, l.created_at, l.student_name, l.source, l.follow_up_date, c.full_name as contact_name,
                                   coalesce(inst.name, (SELECT name FROM institutions WHERE id = c.institution_id)) as institution_name, u.full_name as owner_name
                            FROM leads l
                            LEFT JOIN contacts c ON l.contact_id = c.id
                            LEFT JOIN institutions inst ON l.institution_id = inst.id
                            LEFT JOIN users u ON l.owner_id = u.id
                            WHERE l.owner_id = ?
                            ORDER BY l.created_at DESC
                            LIMIT 6
                        """, (uid,)).fetchall()
                    else:
                        lead_rows = conn.execute("""
                            SELECT l.id, l.created_at, l.student_name, l.source, l.follow_up_date, c.full_name as contact_name,
                                   coalesce(inst.name, (SELECT name FROM institutions WHERE id = c.institution_id)) as institution_name, u.full_name as owner_name
                            FROM leads l
                            LEFT JOIN contacts c ON l.contact_id = c.id
                            LEFT JOIN institutions inst ON l.institution_id = inst.id
                            LEFT JOIN users u ON l.owner_id = u.id
                            ORDER BY l.created_at DESC
                            LIMIT 6
                        """).fetchall()
                    for r in lead_rows:
                        ts = r["created_at"] or ""
                        action = f"Lead: {r['student_name'] or '—'} · {r['source'] or '—'}"
                        contact_display = r["contact_name"] if r["contact_name"] else "—"
                        institution = r["institution_name"] if r["institution_name"] else "—"
                        merged.append({"time": ts, "action": action, "contact": contact_display,
                                       "institution": institution, "owner": r["owner_name"] or "—", "lead_id": r["id"], "follow_up_date": r.get("follow_up_date")})
                except Exception:
                    pass

                # merge and sort by time descending
                merged_sorted = sorted([m for m in merged if m.get("time")], key=lambda x: x["time"], reverse=True)

                # take top 10 and convert timestamps to friendly format
                recent_activity = []
                for m in merged_sorted[:10]:
                    t = m["time"]
                    display_time = t[:16] if t else "—"
                    recent_activity.append({
                        "time": display_time,
                        "action": m["action"],
                        "contact": m.get("contact", "—"),
                        "institution": m.get("institution", "—"),
                        "owner": m.get("owner", "—"),
                        # carry through optional fields so template can use them if present
                        "student_name": m.get("student_name"),
                        "follow_up_date": m.get("follow_up_date"),
                        "id": m.get("student_id") or m.get("lead_id") or m.get("id")
                    })

                if not recent_activity:
                    recent_activity = sample_recent_activity.copy()
            except Exception as e:
                print("Warning building recent_activity from DB failed (dashboard):", e)
                recent_activity = sample_recent_activity.copy()

            # For Faculty role — fetch their enrolled students for dashboard snapshot
            try:
                if role == "Faculty":
                    uid = session.get("user_id")
                    students_list = conn.execute("""
                        SELECT s.id, s.full_name, s.program, s.enrolled_at, coalesce(inst.name, '') as institution_name
                        FROM students s
                        LEFT JOIN institutions inst ON s.institution_id = inst.id
                        WHERE s.advisor_id = ?
                        ORDER BY s.enrolled_at DESC
                        LIMIT 6
                    """, (uid,)).fetchall()
                else:
                    students_list = []
            except Exception:
                students_list = []

            # --- Follow ups: derive from leads with follow_up_date (scoped to the user for counsellors) ---
            try:
                uid = session.get("user_id")
                if role == "Counsellor":
                    # counsellor sees only their follow ups
                    fu_rows = conn.execute("""
                        SELECT l.id, l.student_name, l.follow_up_date, l.program, l.institution_id, c.full_name as contact_name
                        FROM leads l
                        LEFT JOIN contacts c ON l.contact_id = c.id
                        WHERE l.follow_up_date IS NOT NULL AND date(l.follow_up_date) >= date('now') AND l.owner_id = ?
                        ORDER BY l.follow_up_date ASC
                        LIMIT 6
                    """, (uid,)).fetchall()
                else:
                    fu_rows = conn.execute("""
                        SELECT l.id, l.student_name, l.follow_up_date, l.program, l.institution_id, c.full_name as contact_name
                        FROM leads l
                        LEFT JOIN contacts c ON l.contact_id = c.id
                        WHERE l.follow_up_date IS NOT NULL AND date(l.follow_up_date) >= date('now')
                        ORDER BY l.follow_up_date ASC
                        LIMIT 6
                    """).fetchall()

                follow_ups = []
                for f in fu_rows:
                    inst_name = None
                    try:
                        inst_row = conn.execute("SELECT name FROM institutions WHERE id = ?", (f["institution_id"],)).fetchone()
                        inst_name = inst_row["name"] if inst_row else None
                    except Exception:
                        inst_name = None
                    follow_ups.append({
                        "id": f["id"],
                        "student_name": f["student_name"] or "—",
                        "program": f["program"] or "—",
                        "institution_name": inst_name or "—",
                        "contact_name": f["contact_name"] or "—",
                        "follow_up_date": f["follow_up_date"]
                    })
            except Exception as e:
                print("Warning building follow_ups:", e)
                follow_ups = []

            # --- Pipeline and cards: compute counts by status and simple cards ---
            try:
                # statuses we care about
                statuses = ["New", "Qualified", "Converted", "Lost"]
                # Admin: global pipeline counts, Counsellor: scoped to owner, others: global
                uid = session.get("user_id")
                pipeline_counts = {}
                where_clause = ""
                params = []
                if role == "Counsellor":
                    where_clause = "WHERE owner_id = ?"
                    params = [uid]
                else:
                    where_clause = ""
                    params = []

                # total leads (scoped)
                total_q = f"SELECT COUNT(*) as c FROM leads {where_clause}"
                r = conn.execute(total_q, params).fetchone()
                total_leads = r["c"] if r and "c" in r.keys() else 0

                # by status
                for sname in statuses:
                    if where_clause:
                        q = f"SELECT COUNT(*) as c FROM leads {where_clause} AND status = ?"
                        q_params = params + [sname]
                    else:
                        q = f"SELECT COUNT(*) as c FROM leads WHERE status = ?"
                        q_params = [sname]
                    r = conn.execute(q, q_params).fetchone()
                    pipeline_counts[sname] = r["c"] if r and "c" in r.keys() else 0

                # also compute leads this month (scoped)
                month_start = datetime.now().replace(day=1).strftime("%Y-%m-%d")
                if role == "Counsellor":
                    r = conn.execute("SELECT COUNT(*) as c FROM leads WHERE owner_id = ? AND date(created_at) >= date(?)", (uid, month_start)).fetchone()
                else:
                    r = conn.execute("SELECT COUNT(*) as c FROM leads WHERE date(created_at) >= date(?)", (month_start,)).fetchone()
                leads_this_month = r["c"] if r and "c" in r.keys() else 0

                # follow ups scheduled (scoped)
                if role == "Counsellor":
                    r = conn.execute("SELECT COUNT(*) as c FROM leads WHERE follow_up_date IS NOT NULL AND owner_id = ?", (uid,)).fetchone()
                else:
                    r = conn.execute("SELECT COUNT(*) as c FROM leads WHERE follow_up_date IS NOT NULL").fetchone()
                followups_count = r["c"] if r and "c" in r.keys() else 0

                # --- IMPORTANT: produce a flat pipeline dict that templates expect (pipeline.New, etc.)
                pipeline = pipeline_counts.copy()
                pipeline['total'] = total_leads

                # cards: small top-level stats for dashboard cards
                cards = {
                    "total_leads": total_leads,
                    "leads_this_month": leads_this_month,
                    "follow_ups": followups_count,
                    "open_tasks": open_tasks_count
                }

            except Exception as e:
                print("Warning building pipeline/cards:", e)
                pipeline = { "New": 0, "Qualified": 0, "Converted": 0, "Lost": 0, "total": 0 }
                cards = {"total_leads": 0, "leads_this_month": 0, "follow_ups": 0, "open_tasks": open_tasks_count}

            conn.close()
        except Exception as e:
            print("Warning: dashboard read failed:", e)
            # keep defaults/fallbacks already set

        # Render role-specific templates
        if role == "Admin":
            # admin: show global pipeline and cards
            return render_template("dashboard_admin.html", name=name, role=role, stats=stats,
                                   recent_activity=recent_activity, pipeline=pipeline,
                                   upcoming_tasks=upcoming_tasks, recent_contacts=recent_contacts,
                                   follow_ups=follow_ups, open_tasks_count=open_tasks_count, follow_ups_count=len(follow_ups), cards=cards, app_name="CLIENTSYNC CRM")
        elif role == "Faculty":
            # faculty: student & task focused (no leads)
            return render_template("dashboard_faculty.html", name=name, role=role, stats=stats,
                                   recent_activity=recent_activity,
                                   upcoming_tasks=upcoming_tasks, recent_contacts=recent_contacts,
                                   open_tasks_count=open_tasks_count, students=students_list, at_risk=[], app_name="CLIENTSYNC CRM")
        elif role == "Counsellor":
            # counsellor: show follow ups, personal pipeline/cards, leads and tasks scoped to counsellor
            # pass can_create_institution so template can show +New Institution button if desired
            return render_template("dashboard_counsellor.html", name=name, role=role, stats=stats,
                                   recent_activity=recent_activity,
                                   upcoming_tasks=upcoming_tasks, recent_contacts=recent_contacts,
                                   open_tasks_count=open_tasks_count, follow_ups=follow_ups, pipeline=pipeline, cards=cards, can_create_institution=True, app_name="CLIENTSYNC CRM")
        else:
            # fallback to admin-like view
            return render_template("dashboard_admin.html", name=name, role=role, stats=stats,
                                   recent_activity=recent_activity, pipeline=pipeline, upcoming_tasks=upcoming_tasks,
                                   recent_contacts=recent_contacts, follow_ups=follow_ups, open_tasks_count=open_tasks_count, follow_ups_count=len(follow_ups), cards=cards, app_name="CLIENTSYNC CRM")

    return app

if __name__ == "__main__":
    # Ensure DB file exists and tables are created
    if not os.path.exists(DATABASE):
        open(DATABASE, 'a').close()
    ensure_db_tables()

    app = create_app()
    app.run(debug=True)
