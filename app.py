from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

DATABASE = "education.db"


def get_db_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def create_table():
    connection = get_db_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_name TEXT NOT NULL,
            comment TEXT NOT NULL
        )
    """)

    # Profiles table aur default entry
    connection.execute("""
        CREATE TABLE IF NOT EXISTS profiles (
            id INTEGER PRIMARY KEY,
            email TEXT NOT NULL
        )
    """)

    connection.execute("""
        INSERT OR IGNORE INTO profiles (id, email)
        VALUES (1, 'student@example.com')
    """)

    # Users table for SQL Injection testing
    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    """)

    connection.execute("""
        INSERT OR IGNORE INTO users (id, username, password)
        VALUES (1, 'student', 'student123')
    """)

    connection.commit()
    connection.close()


@app.route("/")
def home():
    return redirect(url_for("portal", version="safe"))


@app.route("/<version>")
def portal(version):
    if version not in ["safe", "vulnerable"]:
        return "Invalid version", 404

    connection = get_db_connection()
    comments = connection.execute(
        "SELECT * FROM comments ORDER BY id DESC"
    ).fetchall()
    connection.close()

    return render_template(
        f"{version}/index.html",
        comments=comments,
        version=version
    )


# Step 6.1: Search route
@app.route("/<version>/search")
def search(version):
    if version not in ["safe", "vulnerable"]:
        return "Invalid version", 404

    query = request.args.get("q", "")

    return render_template(
        f"{version}/search.html",
        query=query,
        version=version
    )


# Step 5: SQL Injection Lab Route
@app.route("/<version>/sql-lab")
def sql_lab(version):
    if version not in ["safe", "vulnerable"]:
        return "Invalid version", 404

    query = request.args.get("q", "")
    results = []

    if query:
        connection = get_db_connection()
        if version == "vulnerable":
            sql = "SELECT id, username FROM users WHERE username = '" + query + "'"
            results = connection.execute(sql).fetchall()
        else:
            results = connection.execute(
                "SELECT id, username FROM users WHERE username = ?",
                (query,)
            ).fetchall()
        connection.close()

    return render_template(
        f"{version}/sql_lab.html",
        query=query,
        results=results,
        version=version
    )


# Step 8.4: DOM XSS route
@app.route("/<version>/dom")
def dom_test(version):
    if version not in ["safe", "vulnerable"]:
        return "Invalid version", 404

    return render_template(f"{version}/dom.html")


@app.route("/<version>/add-comment", methods=["POST"])
def add_comment(version):
    if version not in ["safe", "vulnerable"]:
        return "Invalid version", 404

    student_name = request.form.get("student_name", "").strip()
    comment = request.form.get("comment", "").strip()

    if student_name and comment:
        connection = get_db_connection()
        connection.execute(
            "INSERT INTO comments (student_name, comment) VALUES (?, ?)",
            (student_name, comment)
        )
        connection.commit()
        connection.close()

    return redirect(url_for("portal", version=version))


# Step 11.3: Login Route (SQL Injection Lab)
@app.route("/<version>/login", methods=["GET", "POST"])
def login(version):
    if version not in ["safe", "vulnerable"]:
        return "Invalid version", 404

    message = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        connection = get_db_connection()

        if version == "vulnerable":
            # Intentionally vulnerable: SQL injection lab only
            query = (
                "SELECT * FROM users WHERE username = '"
                + username
                + "' AND password = '"
                + password
                + "'"
            )
            user = connection.execute(query).fetchone()
        else:
            # Safe: parameterized query
            user = connection.execute(
                "SELECT * FROM users WHERE username = ? AND password = ?",
                (username, password)
            ).fetchone()

        connection.close()

        if user:
            message = "Login successful!"
        else:
            message = "Invalid username or password."

    return render_template(
        f"{version}/login.html",
        message=message
    )


# Step 9: Database Metadata Route
@app.route("/<version>/database-info")
def database_info(version):
    if version not in ["safe", "vulnerable"]:
        return "Invalid version", 404

    connection = get_db_connection()
    tables = connection.execute("""
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
        AND name NOT LIKE 'sqlite_%'
        ORDER BY name
    """).fetchall()

    database_info = {}
    for table in tables:
        table_name = table["name"]
        safe_table_name = table_name.replace('"', '""')
        columns = connection.execute(
            f'PRAGMA table_info("{safe_table_name}")'
        ).fetchall()
        database_info[table_name] = [
            column["name"] for column in columns
        ]

    connection.close()

    return {
        "database_tables_and_columns": database_info
    }


# Step 9.3: CSRF Routes (Profile & Update Email)
@app.route("/<version>/profile")
def profile(version):
    if version not in ["safe", "vulnerable"]:
        return "Invalid version", 404

    if version == "safe":
        session["csrf_token"] = secrets.token_hex(32)

    connection = get_db_connection()
    student = connection.execute(
        "SELECT * FROM profiles WHERE id = 1"
    ).fetchone()
    connection.close()

    return render_template(
        f"{version}/profile.html",
        student=student,
        csrf_token=session.get("csrf_token", "")
    )


@app.route("/<version>/update-email", methods=["POST"])
def update_email(version):
    if version not in ["safe", "vulnerable"]:
        return "Invalid version", 404

    if version == "safe":
        submitted_token = request.form.get("csrf_token", "")
        saved_token = session.get("csrf_token", "")

        if not saved_token or not secrets.compare_digest(
            submitted_token, saved_token
        ):
            return "CSRF validation failed", 403

    email = request.form.get("email", "").strip()

    if "@" not in email or "." not in email:
        return "Please enter a valid email address", 400

    connection = get_db_connection()
    connection.execute(
        "UPDATE profiles SET email = ? WHERE id = 1",
        (email,)
    )
    connection.commit()
    connection.close()

    return redirect(url_for("profile", version=version))


if __name__ == "__main__":
    create_table()
    app.run(debug=True)