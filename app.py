from flask import Flask, render_template, request, redirect, url_for, session
import pickle
import re
import sqlite3
import random
import smtplib
from email.mime.text import MIMEText
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
# prefer using an environment variable for the secret key in production
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "supersecretkey")


# ================= DATABASE SETUP =================
def init_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


init_db()


# ================= LOAD MODEL =================
vectorizer = pickle.load(open("vectorizer_updated1.pkl", "rb"))
model = pickle.load(open("phishing_updated1.pkl", "rb"))


# per-user history and OTP storage
history = {}
otp_storage = {}


# ================= EMAIL OTP FUNCTION =================
def send_otp_email(to_email, otp):
    sender_email = os.environ.get("SENDER_EMAIL")
    sender_password = os.environ.get("EMAIL_APP_PASSWORD")

    if not sender_email or not sender_password:
        print("Email not sent: SENDER_EMAIL or EMAIL_APP_PASSWORD not set in environment")
        return False

    subject = "Your OTP Verification Code"
    body = f"Your OTP is: {otp}"

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = to_email

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print("Email Error:", e)
        return False


# ================= LOGIN =================
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[0], password):
            session["user"] = username
            return redirect(url_for("home"))
        else:
            return render_template("login.html", error="Invalid Credentials")

    return render_template("login.html")


# ================= SIGNUP (email OTP) =================
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        email_pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        password_pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$'

        if not re.match(email_pattern, username):
            return render_template("signup.html", error="Enter a valid email")

        if password != confirm_password:
            return render_template("signup.html", error="Passwords do not match")

        if not re.match(password_pattern, password):
            return render_template("signup.html", error="Password must be 8+ chars with Uppercase, Lowercase & Number")

        otp = random.randint(100000, 999999)

        otp_storage[username] = {
            "otp": str(otp),
            "password": password
        }

        send_otp_email(username, otp)

        return render_template("verify_otp.html", username=username)

    return render_template("signup.html")


# ================= VERIFY OTP =================
@app.route("/verify_otp", methods=["POST"])
def verify_otp():
    username = request.form["username"]
    entered_otp = request.form["otp"]

    if username in otp_storage and otp_storage[username]["otp"] == entered_otp:

        password = otp_storage[username]["password"]
        hashed_password = generate_password_hash(password)

        try:
            conn = sqlite3.connect("users.db")
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                           (username, hashed_password))
            conn.commit()
            conn.close()

            otp_storage.pop(username, None)

            return redirect(url_for("login"))

        except Exception:
            return render_template("signup.html", error="Account already exists")

    return render_template("verify_otp.html", username=username, error="Invalid OTP")


# ================= HOME =================
@app.route("/home", methods=["GET", "POST"])
def home():

    if "user" not in session:
        return redirect(url_for("login"))

    result = ""

    if request.method == "POST":
        url = request.form["url"]

        cleaned_url = re.sub(r'^https?://(www\.)?', '', url.lower())
        features = vectorizer.transform([cleaned_url])
        pred = model.predict(features)[0]

        if pred == 1 or pred == "bad":
            result = "⚠️ Website may be unsafe"
        else:
            result = "✅ Website is secure"

        user = session["user"]

        if user not in history:
            history[user] = []

        history[user].append({"url": cleaned_url, "result": result})

    return render_template("index.html", predict=result)


# ================= DETECTION HISTORY =================
@app.route("/detection")
def detection():

    if "user" not in session:
        return redirect(url_for("login"))

    user = session["user"]
    user_history = history.get(user, [])

    return render_template("detection.html", history=user_history)


# # ================= ABOUT PAGE =================
# @app.route("/about")
# def about():
#     if "user" not in session:
#         return redirect(url_for("login"))
#     user = session["user"]
#     user_history = history.get(user, [])
#     return render_template("about.html", history=user_history)


# ================= LOGOUT =================
@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
