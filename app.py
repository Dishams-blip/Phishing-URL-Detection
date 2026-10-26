# ============================================
# PHISHDETECT - PHISHING URL DETECTION WEBSITE
# ============================================

from flask import Flask, render_template, request, redirect, session, flash
import mysql.connector
import pandas as pd
import pickle
import re
from urllib.parse import urlparse
from datetime import datetime
import requests
import socket
import tldextract   # pip install tldextract

# ---------------------- Flask Setup ----------------------
app = Flask(__name__)
app.secret_key = "super_secret_key"

# ---------------------- MySQL Connection Helper ----------------------
def get_db_connection():
    """Return a fresh MySQL connection (per request)."""
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="dishadb",
        database="phishdetect"
    )

# ---------------------- Load Trained Model ----------------------
model = pickle.load(open("phishing_model.pkl", "rb"))

# ---------------------- Whitelisted Domains ----------------------
WHITELIST_REG = {
    "google.com", "instagram.com", "facebook.com", "microsoft.com",
    "wikipedia.org", "amazon.in", "github.com", "twitter.com", "bing.com"
}

# Official brand → official domain
OFFICIAL_BRANDS = {
    "paypal": "paypal.com",
    "google": "google.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "microsoft": "microsoft.com",
    "bankofamerica": "bankofamerica.com"
}

PHISH_WORDS = ["login", "verify", "secure", "account", "update", "bank", "signin"]

def registrable(host: str) -> str:
    ext = tldextract.extract(host)
    return f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else host.lower()

def is_whitelisted(host: str) -> bool:
    return registrable(host) in WHITELIST_REG

def has_brand_mismatch(url: str, host: str) -> bool:
    reg = registrable(host)
    low = url.lower()
    for kw, official in OFFICIAL_BRANDS.items():
        if kw in low:
            if reg != official and not reg.endswith("." + official):
                return True
    return False

# ---------------------- Feature Extraction ----------------------
def extract_features(url):
    parsed = urlparse(str(url))
    host = parsed.netloc.lower() or ""
    lower_url = url.lower()

    return {
        'url_length': len(lower_url),
        'domain_length': len(host),
        'num_dots': lower_url.count('.'),
        'num_hyphens': lower_url.count('-'),
        'num_slashes': lower_url.count('/'),
        'num_digits': sum(c.isdigit() for c in lower_url),
        'has_https': 1 if parsed.scheme == 'https' else 0,
        'has_at_symbol': 1 if '@' in lower_url else 0,
        'has_ip_address': 1 if re.search(r'(\d{1,3}\.){3}\d{1,3}', host) else 0,
        'num_subdomains': len(host.split('.')) - 2 if len(host.split('.')) > 2 else 0,
        'has_suspicious_word': 1 if re.search(
            r'login|secure|account|update|verify|bank|free|confirm|signin',
            lower_url) else 0,
        'has_long_domain': 1 if len(host) > 30 else 0
    }

# ---------------------- Reachability Check ----------------------
def url_exists_loose(url, timeout=4):
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        resp = requests.head(url, headers=headers, timeout=timeout, allow_redirects=True)
        if resp.status_code < 400 or resp.status_code in (403, 405):
            return True
    except requests.RequestException:
        pass
    try:
        resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        if resp.status_code < 400 or resp.status_code in (403, 405):
            return True
    except requests.RequestException:
        pass
    try:
        parsed = urlparse(str(url))
        host = parsed.netloc.split(':')[0] or parsed.path
        if host:
            socket.gethostbyname(host)
            return False  # DNS resolves but HTTP unreachable
    except Exception:
        pass
    return False

# ---------------------- Prediction Function ----------------------
# ---------------------- Prediction Function ----------------------
def predict_url(url):
    """Predict Safe / Phishing / Non-existing with brand-mismatch and whitelist logic."""
    try:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        parsed = urlparse(url)
        host = parsed.netloc.lower()
        reg = registrable(host)
        reachable = url_exists_loose(url)

        # ✅ Global safe patterns
        SAFE_TLDS = (".edu", ".ac.in", ".gov", ".gov.in", ".edu.in", ".org.in")

        # ✅ Whitelisted domains
        if reg in WHITELIST_REG or host.endswith(SAFE_TLDS):
            print(f"[DEBUG] {url} → ✅ Safe (whitelisted or academic/government domain)")
            return "Safe"

        # ⚠️ Brand mismatch (phishing)
        if has_brand_mismatch(url, host):
            print(f"[DEBUG] {url} → ⚠️ Phishing (brand mismatch)")
            return "Phishing"

        # Count phishing keywords
        kw_count = sum(w in url.lower() for w in PHISH_WORDS)

        # ❌ Non-existing
        if not reachable and kw_count == 0:
            print(f"[DEBUG] {url} → ❌ Non-existing")
            return "Non-existing"

        # ML model
        f = pd.DataFrame([extract_features(url)])
        expected = getattr(model, "feature_names_in_", None)
        if expected is not None:
            for col in expected:
                if col not in f:
                    f[col] = 0
            f = f[list(expected)]

        proba = float(model.predict_proba(f)[0][1])
        phishing = (proba > 0.7) or (kw_count >= 2 and proba > 0.3)

        result = "Phishing" if phishing else "Safe"
        print(f"[DEBUG] {url} → {result} (prob={proba:.2f}, reachable={reachable})")
        return result

    except Exception as e:
        print("Prediction error:", e)
        return "Error"

# ---------------------- ROUTES ----------------------

@app.route('/')
def home():
    return redirect('/login')

# ---------- SIGNUP ----------
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        if cursor.fetchone():
            flash("Email already registered!", "error")
            cursor.close(); conn.close()
            return redirect('/login')

        cursor.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)", (username, email, password))
        conn.commit()
        cursor.close(); conn.close()

        session['email'] = email
        session['username'] = username
        flash("Signup successful! Welcome!", "success")
        return redirect('/dashboard')
    return render_template('signup.html')

# ---------- LOGIN ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    # 🧹 Clear old flash messages (e.g. history deletion messages)
    session.pop('_flashes', None)

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email=%s AND password=%s", (email, password))
        user = cursor.fetchone()
        cursor.close(); conn.close()

        if user:
            session['email'] = user['email']
            session['username'] = user['username']
            flash("Welcome back!", "success")
            return redirect('/dashboard')
        else:
            flash("Invalid credentials! Try again.", "error")
            return redirect('/login')

    return render_template('login.html')


# ---------- DASHBOARD ----------
@app.route('/dashboard')
def dashboard():
    if 'email' not in session:
        return redirect('/login')

    email = session['email']
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cursor.fetchone()

    cursor.execute("SELECT id, url, result, checked_at FROM user_history WHERE email=%s ORDER BY checked_at DESC", (email,))
    history = cursor.fetchall()

    cursor.execute("""
        SELECT COUNT(*) AS total,
               SUM(CASE WHEN result LIKE '%Phishing%' THEN 1 ELSE 0 END) AS phishing_count,
               SUM(CASE WHEN result LIKE '%Safe%' THEN 1 ELSE 0 END) AS safe_count,
               SUM(CASE WHEN result LIKE '%Non-existing%' THEN 1 ELSE 0 END) AS non_existing_count
        FROM user_history WHERE email=%s
    """, (email,))
    stats = cursor.fetchone()
    cursor.close(); conn.close()

    return render_template('dashboard.html', user=user, history=history, stats=stats)

# ---------- CHECK URL ----------
@app.route('/check', methods=['GET', 'POST'])
def check_url():
    if 'email' not in session:
        return redirect('/login')

    prediction, color = None, None
    if request.method == 'POST':
        url = request.form['url']
        result = predict_url(url)

        if result == "Phishing":
            prediction, color = "⚠️ This website is PHISHING!", "red"
        elif result == "Safe":
            prediction, color = "✅ This website is SAFE.", "green"
        elif result == "Non-existing":
            prediction, color = "❌ The website is Non-existing or unreachable.", "gray"
        else:
            prediction, color = "❌ Error while checking URL.", "gray"

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("INSERT INTO user_history (email, url, result, checked_at) VALUES (%s, %s, %s, %s)",
                       (session['email'], url, result, datetime.now()))
        conn.commit()
        cursor.close(); conn.close()

    return render_template('check_url.html', prediction=prediction, color=color)

# ---------- DELETE HISTORY ----------
@app.route('/delete_history/<int:row_id>', methods=['POST'])
def delete_history(row_id):
    if 'email' not in session:
        flash("Please login first.", "error")
        return redirect('/login')
    email = session['email']
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("DELETE FROM user_history WHERE id=%s AND email=%s", (row_id, email))
    conn.commit()
    cursor.close(); conn.close()
    flash("History entry deleted.", "success")
    return redirect('/dashboard')

@app.route('/delete_all_history', methods=['POST'])
def delete_all_history():
    if 'email' not in session:
        flash("Please login first.", "error")
        return redirect('/login')
    email = session['email']
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("DELETE FROM user_history WHERE email=%s", (email,))
    conn.commit()
    cursor.close(); conn.close()
    flash("All history deleted successfully!", "success")
    return redirect('/dashboard')

# ---------- LOGOUT ----------
@app.route('/logout')
def logout():
    session.clear()
    flash("You have logged out successfully.", "success")
    return redirect('/login')

# ---------------------- RUN APP ----------------------
if __name__ == "__main__":
    app.run(debug=True)
