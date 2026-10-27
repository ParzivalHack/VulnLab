"""
Vuln Lab - an intentionally vulnerable Flask app built for a security
education article. Every vulnerability below is deliberate. Do not deploy
real user data, real credentials, or anything sensitive alongside this app.

Vulnerabilities included:
  /search       - Reflected XSS
  /posts        - Stored XSS
  /login + /invoice/<id> - IDOR
  /files        - Path Traversal / LFI
  /diagnostics  - OS Command Injection -> RCE
"""

import os
import subprocess

from flask import Flask, request, render_template, redirect, url_for, session

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "lab-insecure-dev-key-change-me")

# ---------------------------------------------------------------------------
# In-memory "database". Intentionally simple: it resets whenever the process
# restarts, which doubles as free cleanup for anything visitors plant here.
# ---------------------------------------------------------------------------

USERS = {
    1: {"name": "Alice"},
    2: {"name": "Bob"},
    3: {"name": "Carol"},
}

INVOICES = {
    1: {"owner_id": 1, "amount": "$128.40", "note": "Monthly subscription"},
    2: {"owner_id": 2, "amount": "$54.10", "note": "One-time purchase"},
    3: {"owner_id": 3, "amount": "$999.00", "note": "Annual plan renewal"},
}

PRODUCTS = ["Blue Mug", "Red Notebook", "Green Backpack", "Black Umbrella"]

POSTS = [
    {"author": "lab-admin", "message": "Welcome to the guestbook. Be nice."}
]

LAB_FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lab_files")


@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# Reflected XSS: the search term is echoed straight back into the page
# without escaping.
# ---------------------------------------------------------------------------
@app.route("/search")
def search():
    q = request.args.get("q", "")
    results = [p for p in PRODUCTS if q.lower() in p.lower()] if q else []
    return render_template("search.html", results=results, raw_q=q)


# ---------------------------------------------------------------------------
# Stored XSS: guestbook posts are saved as-is and rendered as-is for every
# future visitor.
# ---------------------------------------------------------------------------
@app.route("/posts", methods=["GET", "POST"])
def posts():
    if request.method == "POST":
        author = request.form.get("author", "anonymous")
        message = request.form.get("message", "")
        POSTS.append({"author": author, "message": message})
        return redirect(url_for("posts"))
    return render_template("posts.html", posts=POSTS)


# ---------------------------------------------------------------------------
# IDOR: logging in only sets a session, it doesn't gate which invoice ID
# you're allowed to request.
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user_id = int(request.form.get("user_id"))
        session["user_id"] = user_id
        return redirect(url_for("dashboard"))
    return render_template("login.html", users=USERS)


@app.route("/dashboard")
def dashboard():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=USERS[user_id], user_id=user_id)


@app.route("/invoice/<int:invoice_id>")
def invoice(invoice_id):
    if not session.get("user_id"):
        return redirect(url_for("login"))
    # Vulnerable: never checks invoice["owner_id"] against session["user_id"].
    inv = INVOICES.get(invoice_id)
    if not inv:
        return "Invoice not found", 404
    return render_template("invoice.html", invoice=inv, invoice_id=invoice_id)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/reset")
def reset():
    # Convenience for local testing: wipe anything planted in the guestbook
    # without having to restart the server. Harmless here since this is a
    # single-player local instance, not a shared one.
    POSTS.clear()
    POSTS.append({"author": "lab-admin", "message": "Welcome to the guestbook. Be nice."})
    return redirect(url_for("posts"))


# ---------------------------------------------------------------------------
# Path Traversal / LFI: the filename is joined onto a base directory with no
# validation, so "../" walks straight out of it.
# ---------------------------------------------------------------------------
@app.route("/files")
def files_view():
    filename = request.args.get("file", "")
    content = None
    error = None
    if filename:
        target_path = os.path.join(LAB_FILES_DIR, filename)
        try:
            with open(target_path, "r", errors="replace") as f:
                content = f.read()
        except Exception as e:
            error = f"Could not read file: {e}"
    return render_template("files.html", filename=filename, content=content, error=error)


# ---------------------------------------------------------------------------
# Command Injection -> RCE: the host field is dropped straight into a shell
# command with nothing else added. Whatever separator the reader appends is
# interpreted by the OS's own shell before "ping" ever sees its argument:
# ";", "&&", "|", or backticks on Linux/Mac (/bin/sh), "&" or "&&" on
# Windows (cmd.exe, which subprocess uses there, not PowerShell).
# ---------------------------------------------------------------------------
@app.route("/diagnostics", methods=["GET", "POST"])
def diagnostics():
    output = None
    host = ""
    if request.method == "POST":
        host = request.form.get("host", "")
        command = f"ping {host}"
        try:
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=5
            )
            output = (result.stdout or "") + (result.stderr or "")
        except subprocess.TimeoutExpired:
            output = "Request timed out."
        except Exception as e:
            output = f"Error: {e}"
    return render_template("diagnostics.html", output=output, host=host)


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
