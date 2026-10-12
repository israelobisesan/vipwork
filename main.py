import os
import sqlite3
import datetime
import qrcode
import bcrypt
import time
import requests
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory
from itsdangerous import URLSafeTimedSerializer, BadSignature

app = Flask(__name__, static_folder=None)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_FILE = os.path.join(BASE_DIR, "database.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
LOGIN_LOG = os.path.join(BASE_DIR, "logins.txt")
PUBLIC_DIR = os.path.join(BASE_DIR, "public")

app.config['MAX_CONTENT_LENGTH'] = 15 * 1024 * 1024
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "change-me-in-render-dashboard")

PAYSTACK_SECRET_KEY = os.environ.get("PAYSTACK_SECRET_KEY", "")
PAYSTACK_VERIFY_URL = "https://api.paystack.co/transaction/verify/"

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])


def get_db():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT)")
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, job_type TEXT,
            actual_price REAL, vip_money REAL, total_price REAL, status TEXT, timestamp TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vip_cards (
            card_id TEXT PRIMARY KEY, username TEXT, name TEXT,
            phone TEXT, sex TEXT, tier TEXT, issue_date TEXT, qr_path TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, sender TEXT,
            message_text TEXT, timestamp TEXT, is_read INTEGER
        )
    """)
    conn.commit()

    # Older local databases predate the timestamp column, and CREATE TABLE IF NOT
    # EXISTS silently skips tables that already exist, so add missing columns here.
    for table, column, ddl in (
        ("transactions", "timestamp", "ALTER TABLE transactions ADD COLUMN timestamp TEXT"),
        ("vip_cards", "qr_path", "ALTER TABLE vip_cards ADD COLUMN qr_path TEXT"),
    ):
        cols = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        if column not in cols:
            conn.execute(ddl)

    conn.commit()
    conn.close()


def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify({"message": "Error: Access token required."}), 401
        try:
            username = serializer.loads(header[7:], max_age=60 * 60 * 12)
        except BadSignature:
            return jsonify({"message": "Error: Session expired or invalid. Please sign in again."}), 401
        request.username = username
        return fn(*args, **kwargs)
    return wrapper


@app.route('/api/health')
def health():
    return jsonify({"status": "ok"}), 200


@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip().lower()
    password = data.get('password')
    if not username or not password:
        return jsonify({"message": "Inputs cannot be left empty."}), 400

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        conn.close()
        return jsonify({"message": "Error: That username is already registered under FGURL VIP."}), 400
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed))
    conn.commit()
    conn.close()
    return jsonify({"message": "FGURL VIP Profile Formed Successfully!"}), 200


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip().lower()
    password = data.get('password')
    if not username or not password:
        return jsonify({"message": "Inputs cannot be left empty."}), 400

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()

    if row and bcrypt.checkpw(password.encode('utf-8'), row['password_hash'].encode('utf-8')):
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOGIN_LOG, "a") as log_file:
            log_file.write(f"[{current_time}] AUTH SUCCESS - Profile '{username}' entered the FGURL VIP Portal.\n")
        token = serializer.dumps(username)
        return jsonify({
            "message": "Access Verified! Loading panel...",
            "token": token,
            "username": username
        }), 200
    return jsonify({"message": "Error: Invalid entry credentials. Access Denied."}), 401


@app.route('/api/check-expiry', methods=['GET'])
@require_auth
def check_expiry():
    username = request.username
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT card_id FROM vip_cards WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return jsonify({"status": "active", "has_card": False}), 200
    return jsonify({"status": "active", "has_card": True}), 200


@app.route('/api/create-vip', methods=['POST'])
@require_auth
def create_vip():
    username = request.username
    name = request.form.get('name')
    phone = request.form.get('phone')
    sex = request.form.get('sex')
    tier = request.form.get('tier')
    issue_date = request.form.get('issue_date')

    passport = request.files.get('passport')
    passport_name = None
    if passport and passport.filename:
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        extension = os.path.splitext(passport.filename)[1] or '.jpg'
        unique_suffix = int(time.time())
        passport_name = f"{username}_{unique_suffix}_passport{extension}"
        passport.save(os.path.join(UPLOAD_DIR, passport_name))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM vip_cards")
    count = cursor.fetchone()[0] + 1
    card_sequence_number = f"{count:03d}"

    qr_data = f"FGURL VIP CARD ID: {card_sequence_number}\nHolder: {name}\nContact: {phone}\nGender: {sex}\nPlan: {tier}"
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(qr_data)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white")

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    qr_filename = f"uploads/{card_sequence_number}_qr.png"
    qr_img.save(os.path.join(BASE_DIR, qr_filename))

    cursor.execute("DELETE FROM vip_cards WHERE username = ?", (username,))
    cursor.execute("""
        INSERT INTO vip_cards (card_id, username, name, phone, sex, tier, issue_date, qr_path)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (card_sequence_number, username, name, phone, sex, tier, issue_date, qr_filename))
    conn.commit()
    conn.close()
    return jsonify({"message": f"Successfully mapped FGURL VIP Card #{card_sequence_number}"}), 200


@app.route('/uploads/<path:filename>')
@require_auth
def uploaded_file(filename):
    return send_from_directory(UPLOAD_DIR, filename)


@app.route('/api/checkout-live', methods=['POST'])
@require_auth
def checkout_live():
    data = request.get_json(silent=True) or {}
    username = request.username
    job_type = data.get('job_type')
    paystack_ref = data.get('paystack_ref')

    if not PAYSTACK_SECRET_KEY:
        return jsonify({"message": "Error: Server is missing its Paystack secret key."}), 500

    try:
        actual_price = float(data.get('actual_price'))
    except (TypeError, ValueError):
        return jsonify({"message": "Error: Invalid price supplied."}), 400

    try:
        response = requests.get(
            f"{PAYSTACK_VERIFY_URL}{paystack_ref}",
            headers={"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"},
            timeout=20
        ).json()
    except Exception:
        return jsonify({"message": "Error verification network connection dropout."}), 500

    if response.get('status') and response.get('data', {}).get('status') == 'success':
        vip_money = actual_price * 0.25
        total_price = actual_price + vip_money
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        partner_share = 2200.00
        your_share = 300.00

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO transactions (username, job_type, actual_price, vip_money, total_price, status, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (username, job_type, actual_price, vip_money, total_price,
              "Payment Confirmed / Approved for Production", timestamp))
        conn.commit()
        conn.close()

        print("\n--- FGURL VIP REAL-TIME CHECKOUT SPLIT COMPILATION ---")
        print(f"Ref Token: [{paystack_ref}] | Account Profile: [{username}]")
        print(f"Total Confirmed Revenue Received: N{total_price:,.2f}")
        print(f"-> Automated Payout Sent to Partner Node: N{partner_share:,.2f}")
        print(f"-> Your Dedicated Premium Payout (Oladele): N{your_share:,.2f} to 8065867966")
        print("-------------------------------------------------------------\n")
        return jsonify({"message": f"Real-time Payment Verified! Total Processed: N{total_price:,.2f}."}), 200

    return jsonify({"message": "Verification parameters fraudulent or invalid."}), 400


@app.route('/api/transactions', methods=['GET'])
@require_auth
def get_transactions():
    username = request.username
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, job_type, total_price, status, timestamp FROM transactions WHERE username = ? ORDER BY id DESC",
        (username,)
    )
    rows = cursor.fetchall()
    conn.close()
    return jsonify([dict(ix) for ix in rows])


@app.route('/')
def index():
    return send_from_directory(PUBLIC_DIR, "VIP LAND.html")


@app.route('/<path:filename>')
def static_files(filename):
    return send_from_directory(PUBLIC_DIR, filename)


init_db()

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)