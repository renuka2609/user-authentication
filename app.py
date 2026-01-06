from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from database import get_db_connection
from models import create_tables

app = Flask(__name__)
app.secret_key = "secure_secret_key"

create_tables()

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            return redirect("/profile")

    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = generate_password_hash(request.form["password"])

        conn = get_db_connection()
        conn.execute(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
            (name, email, password)
        )
        conn.commit()
        conn.close()
        return redirect("/")

    return render_template("register.html")

@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "user_id" not in session:
        return redirect("/")

    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()

    if request.method == "POST":
        name = request.form["name"]
        conn.execute("UPDATE users SET name=? WHERE id=?", (name, session["user_id"]))
        conn.commit()

    conn.close()
    return render_template("profile.html", user=user)

@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    if request.method == "POST":
        new_password = generate_password_hash(request.form["new_password"])
        conn = get_db_connection()
        conn.execute("UPDATE users SET password=? WHERE id=?", (new_password, session["user_id"]))
        conn.commit()
        conn.close()
        return redirect("/profile")

    return render_template("change_password.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)
