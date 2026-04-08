import sqlite3
import os
import pyotp
import qrcode
import io
import base64
import csv
from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response, send_from_directory

app = Flask(__name__)
app.secret_key = "alstandesign_secure_key_2026"

# --- DATABASE LOGIC ---
DB_PATH = os.path.join(os.path.dirname(__file__), 'alstandesign.db')
VIDEOS_DIR = os.path.join(os.path.dirname(__file__), 'videos')
VIDEO_ASSETS = {
    "semiconductors": {
        "filename": "WhatsApp Video 2026-04-04 at 1.41.49 PM.mp4",
        "title": "AI Signal Scaffold",
        "description": "Early-stage AI signal processing stack for semiconductor metrology.",
        "badge": "AI R&D"
    },
    "cloud": {
        "filename": "Next-Gen Cloud Infrastructure Demo_720p_caption.mp4",
        "title": "Cloud Infrastructure Demo",
        "description": "Walkthrough of our resilient multi-region fabric with orchestration telemetry.",
        "badge": "Cloud Systems"
    },
    "process": {
        "filename": "Cyan Precision Automation_720p_caption.mp4",
        "title": "Physics-Control Automation",
        "description": "Real-time automation showcase from our labs, highlighting sensor-to-actuator loops.",
        "badge": "Automation"
    }
}

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    print("--- INITIALIZING DATABASE: GOOGLE AUTH ENABLED ---")
    try:
        conn = get_db_connection()
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                otp_secret TEXT, 
                is_verified INTEGER DEFAULT 0
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS inquiries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                message TEXT NOT NULL,
                status TEXT DEFAULT 'PENDING'
            )
        ''')
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"DATABASE ERROR: {e}")

init_db()

# --- ROUTES ---

@app.route('/')
def index():
    user_name = session.get('user') 
    card_videos = {
        key: {**asset, "url": url_for('serve_video', filename=asset['filename'])}
        for key, asset in VIDEO_ASSETS.items()
    }
    return render_template('index.html', name=user_name, card_videos=card_videos)


@app.route('/videos/<path:filename>')
def serve_video(filename):
    return send_from_directory(VIDEOS_DIR, filename)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        email = request.form.get('email').strip()
        password = request.form.get('password')
        otp_secret = pyotp.random_base32()
        
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, email, password, otp_secret) VALUES (?, ?, ?, ?)',
                         (username, email, password, otp_secret))
            conn.commit()
            return redirect(url_for('setup_2fa', username=username))
        except sqlite3.IntegrityError:
            flash("Email already registered. Please login.", "danger")
            return redirect(url_for('login'))
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/setup_2fa/<username>')
def setup_2fa(username):
    conn = get_db_connection()
    user = conn.execute('SELECT otp_secret, is_verified FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()

    if not user: 
        return redirect(url_for('index'))
    if user['is_verified'] == 1:
        flash("Account already verified.", "info")
        return redirect(url_for('login'))

    totp = pyotp.TOTP(user['otp_secret'])
    provisioning_url = totp.provisioning_uri(name=username, issuer_name="AlstanDesign")
    
    img = qrcode.make(provisioning_url)
    buf = io.BytesIO()
    img.save(buf)
    qr_b64 = base64.b64encode(buf.getvalue()).decode()
    
    return render_template('verify.html', qr_code=qr_b64, username=username)

@app.route('/verify/<username>', methods=['POST'])
def verify_otp(username):
    user_code = request.form.get('otp')
    conn = get_db_connection()
    user = conn.execute('SELECT otp_secret FROM users WHERE username = ?', (username,)).fetchone()
    
    if user:
        totp = pyotp.TOTP(user['otp_secret'])
        if totp.verify(user_code):
            conn.execute('UPDATE users SET is_verified = 1 WHERE username = ?', (username,))
            conn.commit()
            conn.close()
            return render_template('welcome.html', message="Synchronization Complete!") 
    
    if conn: conn.close()
    flash("Invalid verification code. Please try again.", "danger")
    return redirect(url_for('setup_2fa', username=username))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email').strip()
        password = request.form.get('password')
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ? AND password = ?',
                            (email, password)).fetchone()
        conn.close()
        
        if user:
            if user['is_verified'] == 0:
                return redirect(url_for('setup_2fa', username=user['username']))
            return render_template('login_otp.html', username=user['username'])
            
        flash("Invalid email or password.", "danger")
    return render_template('login.html')

@app.route('/login_verify', methods=['POST'])
def login_verify():
    username = request.form.get('username')
    user_code = request.form.get('otp')
    
    conn = get_db_connection()
    user = conn.execute('SELECT otp_secret FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    
    if user:
        totp = pyotp.TOTP(user['otp_secret'])
        if totp.verify(user_code):
            session['user'] = username
            return redirect(url_for('index'))
    
    flash("Authentication failed. Please restart login.", "danger")
    return redirect(url_for('login'))

@app.route('/submit', methods=['POST'])
def submit_inquiry():
    email = request.form.get('email')
    message = request.form.get('message')
    
    if not email or not message:
        flash("All fields are required.", "warning")
        return redirect(url_for('index'))

    conn = get_db_connection()
    conn.execute('INSERT INTO inquiries (email, message) VALUES (?, ?)', (email, message))
    conn.commit()
    conn.close()
    return render_template('welcome.html', message="Inquiry Received Successfully!")

@app.route('/admin')
def admin_panel():
    if 'user' not in session: 
        flash("Please login first.", "danger")
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    users = conn.execute('SELECT id, username, email, is_verified FROM users').fetchall()
    inquiries = conn.execute('SELECT id, email, message, status FROM inquiries').fetchall()
    conn.close()
    return render_template('admin.html', users=users, inquiries=inquiries)

@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    # Updated: Now allows any logged in user to delete, matching your admin panel logic
    if 'user' not in session:
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    flash("User deleted successfully.", "success")
    return redirect(url_for('admin_panel'))

@app.route('/export_inquiries')
def export_inquiries():
    # Updated: Removed the strict "admin" check so it works for you
    if 'user' not in session:
        flash("Unauthorized Access. Please login.", "danger")
        return redirect(url_for('index'))

    conn = get_db_connection()
    inquiries = conn.execute('SELECT email, message, status FROM inquiries').fetchall()
    conn.close()

    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['Email', 'Message', 'Status']) 
    for row in inquiries:
        status = row['status'] if row['status'] else "PENDING"
        cw.writerow([row['email'], row['message'], status])

    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=alstandesign_inquiries.csv"
    output.headers["Content-type"] = "text/csv"
    return output

@app.route('/resolve_inquiry/<int:id>')
def resolve_inquiry(id):
    if 'user' not in session:
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    conn.execute("UPDATE inquiries SET status = 'REPLIED' WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    flash("Inquiry marked as replied.", "success")
    return redirect(url_for('admin_panel'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
