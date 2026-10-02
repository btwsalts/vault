import os
import sqlite3
from functools import wraps
from flask import Flask, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from cryptography.fernet import Fernet, InvalidToken

app = Flask(__name__)
app.secret_key = os.environ.get("VAULT_SESSION_SECRET", "dev-only-change-me")
DB = "vault.db"

def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        encryption_key BLOB NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS secrets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        username TEXT,
        ciphertext BLOB NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    """)
    conn.close()

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def current_user():
    conn = db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    conn.close()
    return user

def log_action(user_id, action):
    conn = db()
    conn.execute("INSERT INTO audit_log(user_id, action) VALUES (?, ?)", (user_id, action))
    conn.commit()
    conn.close()

@app.route("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("login"))
    conn = db()
    secrets = conn.execute(
        "SELECT id,title,category,username,created_at FROM secrets WHERE user_id=? ORDER BY id DESC",
        (session["user_id"],)
    ).fetchall()
    conn.close()
    return render_template("dashboard.html", user=current_user(), secrets=secrets)

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        if len(username) < 3 or len(password) < 10:
            flash("Use a username of 3+ characters and a password of at least 10 characters.")
            return render_template("register.html")
        conn = db()
        try:
            conn.execute(
                "INSERT INTO users(username,password_hash,encryption_key) VALUES (?,?,?)",
                (username, generate_password_hash(password), Fernet.generate_key())
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            flash("That username is already registered.")
            return render_template("register.html")
        conn.close()
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        conn = db()
        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            log_action(user["id"], "Logged in")
            return redirect(url_for("index"))
        flash("Invalid username or password.")
    return render_template("login.html")

@app.route("/logout")
def logout():
    if "user_id" in session:
        log_action(session["user_id"], "Logged out")
    session.clear()
    return redirect(url_for("login"))

@app.route("/secret/new", methods=["GET","POST"])
@login_required
def new_secret():
    if request.method == "POST":
        title = request.form.get("title","").strip()
        category = request.form.get("category","General").strip() or "General"
        username = request.form.get("username","").strip()
        value = request.form.get("value","")
        if not title or not value:
            flash("Title and secret value are required.")
            return render_template("secret_form.html")
        user = current_user()
        token = Fernet(user["encryption_key"]).encrypt(value.encode())
        conn = db()
        conn.execute(
            "INSERT INTO secrets(user_id,title,category,username,ciphertext) VALUES (?,?,?,?,?)",
            (user["id"], title, category, username, token)
        )
        conn.commit()
        conn.close()
        log_action(user["id"], f"Created secret: {title}")
        return redirect(url_for("index"))
    return render_template("secret_form.html")

@app.route("/secret/<int:secret_id>")
@login_required
def view_secret(secret_id):
    conn = db()
    secret = conn.execute(
        "SELECT * FROM secrets WHERE id=? AND user_id=?",
        (secret_id, session["user_id"])
    ).fetchone()
    conn.close()
    if not secret:
        flash("Secret not found.")
        return redirect(url_for("index"))
    try:
        value = Fernet(current_user()["encryption_key"]).decrypt(secret["ciphertext"]).decode()
    except InvalidToken:
        flash("The stored secret could not be decrypted.")
        return redirect(url_for("index"))
    log_action(session["user_id"], f"Viewed secret: {secret['title']}")
    return render_template("view_secret.html", secret=secret, value=value)

@app.route("/secret/<int:secret_id>/delete", methods=["POST"])
@login_required
def delete_secret(secret_id):
    conn = db()
    secret = conn.execute(
        "SELECT title FROM secrets WHERE id=? AND user_id=?",
        (secret_id, session["user_id"])
    ).fetchone()
    if secret:
        conn.execute("DELETE FROM secrets WHERE id=? AND user_id=?", (secret_id, session["user_id"]))
        conn.commit()
    conn.close()
    if secret:
        log_action(session["user_id"], f"Deleted secret: {secret['title']}")
    return redirect(url_for("index"))

@app.route("/activity")
@login_required
def activity():
    conn = db()
    logs = conn.execute(
        "SELECT action,created_at FROM audit_log WHERE user_id=? ORDER BY id DESC LIMIT 50",
        (session["user_id"],)
    ).fetchall()
    conn.close()
    return render_template("activity.html", logs=logs)

if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)
