from flask import Flask, render_template, request, redirect, url_for, session
import pickle
import re
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "supersecretkey"

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

# STORE DETECTION HISTORY
history = []


# ================= LOGIN PAGE =================
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


# ================= SIGNUP PAGE =================
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        email_pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        mobile_pattern = r'^\d{10}$'
        password_pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$'

        # Username validation
        if not (re.match(email_pattern, username) or re.match(mobile_pattern, username)):
            return render_template("signup.html",
                                   error="Enter valid Email or 10-digit Mobile")

        # Password match
        if password != confirm_password:
            return render_template("signup.html",
                                   error="Passwords do not match")

        # Password strength
        if not re.match(password_pattern, password):
            return render_template("signup.html",
                                   error="Password must be 8+ chars with Uppercase, Lowercase & Number")

        hashed_password = generate_password_hash(password)

        try:
            conn = sqlite3.connect("users.db")
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                           (username, hashed_password))
            conn.commit()
            conn.close()

            return redirect(url_for("login"))

        except:
            return render_template("signup.html",
                                   error="Account already exists")

    return render_template("signup.html")


# ================= HOME PAGE =================
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
            result = "⚠️ Security Alert: This website may be unsafe or fraudulent"
        elif pred == 0 or pred == "good":
            result = "✅ No phishing indicators detected — website is secure"
        else:
            result = "⚠️ Unable to classify the website"

        history.append({
            "url": url,
            "result": result
        })

    return render_template("index.html", predict=result)


# ================= DETECTION HISTORY =================
@app.route("/detection")
def detection():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("detection.html", history=history)


# ================= ABOUT PAGE =================
@app.route("/about")
def about():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("about.html")


# ================= LOGOUT =================
@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))


# ================= RUN APP =================
if __name__ == "__main__":
    app.run(debug=True)
