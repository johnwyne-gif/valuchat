from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, send_from_directory
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import sqlite3
import os
import base64
import secrets
import json
from datetime import datetime
import uuid
from werkzeug.utils import secure_filename
import mimetypes
from dotenv import load_dotenv

try:
    from flask_wtf.csrf import CSRFProtect
except ImportError:
    print("=" * 60)
    print("ERROR: Flask-WTF is not installed!")
    print("=" * 60)
    print()
    print("Run this command to install all dependencies:")
    print("  pip install -r requirements.txt")
    print()
    print("Or install just the missing packages:")
    print("  pip install Flask-WTF==1.2.1 python-dotenv==1.0.0")
    print("=" * 60)
    raise

try:
    from dotenv import load_dotenv
except ImportError:
    print("=" * 60)
    print("ERROR: python-dotenv is not installed!")
    print("=" * 60)
    print()
    print("Run this command:")
    print("  pip install python-dotenv==1.0.0")
    print("=" * 60)
    raise

from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import sqlite3
import os
import base64
import secrets
import json
from datetime import datetime
import uuid
from werkzeug.utils import secure_filename
import mimetypes

# Load .env from the same folder as this script
script_dir = os.path.dirname(os.path.abspath(__file__))
env_path = os.path.join(script_dir, '.env')
load_dotenv(dotenv_path=env_path)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
if not app.config['SECRET_KEY']:
    print("=" * 60)
    print("ERROR: SECRET_KEY not found!")
    print("=" * 60)
    print()
    print("You need to create a .env file in this folder:")
    print("  " + os.path.join(script_dir, '.env'))
    print()
    print("Put this inside the .env file:")
    print("  SECRET_KEY=your-super-secret-key-here-min-32-chars")
    print("  FLASK_ENV=development")
    print()
    print("Or set it as an environment variable before running:")
    print("  Windows CMD:    set SECRET_KEY=your-secret-key")
    print('  Windows PowerShell: $env:SECRET_KEY="your-secret-key"')
    print("  Linux/Mac:      export SECRET_KEY=your-secret-key")
    print("=" * 60)
    raise RuntimeError('SECRET_KEY environment variable must be set')

app.config['DATABASE'] = os.path.join(os.path.dirname(__file__), 'database', 'valuchat.db')
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size
app.config['WTF_CSRF_ENABLED'] = True
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# CSRF Protection
csrf = CSRFProtect(app)

# Exempt API routes that use JSON (not HTML forms) from CSRF
# SocketIO events handle their own auth via session
csrf.exempt('app.add_contact')
csrf.exempt('app.accept_message_request')
csrf.exempt('app.decline_message_request')
csrf.exempt('app.block_from_request')
csrf.exempt('app.manage_blocked_users')
csrf.exempt('app.upload_file')
csrf.exempt('app.upload_chat_file')
csrf.exempt('app.upload_message_file')

# Allowed file extensions
ALLOWED_EXTENSIONS = {
    'image': {'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'svg'},
    'video': {'mp4', 'webm', 'ogg', 'mov', 'avi', 'mkv'},
    'audio': {'mp3', 'wav', 'ogg', 'm4a', 'flac'},
    'document': {'pdf', 'doc', 'docx', 'txt', 'rtf', 'xls', 'xlsx', 'ppt', 'pptx'},
    'archive': {'zip', 'rar', '7z', 'tar', 'gz'},
    'code': {'py', 'js', 'html', 'css', 'java', 'cpp', 'c', 'h', 'php', 'rb', 'go', 'rs', 'json', 'xml', 'sql'}
}

def get_file_type(filename):
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    for ftype, exts in ALLOWED_EXTENSIONS.items():
        if ext in exts:
            return ftype
    return 'other'

def allowed_file(filename):
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    all_exts = set()
    for exts in ALLOWED_EXTENSIONS.values():
        all_exts.update(exts)
    return ext in all_exts

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# SocketIO for real-time messaging
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Track online users: user_id -> last_seen_timestamp
online_users = {}

# ==================== DATABASE ====================
def get_db():
    db_path = app.config['DATABASE']
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            display_name TEXT,
            public_key TEXT,
            private_key_encrypted TEXT,
            salt TEXT,
            avatar_url TEXT DEFAULT 'default',
            status TEXT DEFAULT 'offline',
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_admin INTEGER DEFAULT 0,
            is_active INTEGER DEFAULT 1
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            encrypted_content TEXT,
            nonce TEXT,
            salt TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_read INTEGER DEFAULT 0,
            message_type TEXT DEFAULT 'text',
            file_url TEXT,
            file_name TEXT,
            file_size INTEGER,
            file_type TEXT,
            FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages(receiver_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(sender_id, receiver_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp)")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            contact_id INTEGER NOT NULL,
            nickname TEXT,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (contact_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(user_id, contact_id)
        )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_contacts_user ON contacts(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_contacts_contact ON contacts(contact_id)")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            ip_address TEXT,
            user_agent TEXT,
            login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            success INTEGER DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS message_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            encrypted_content TEXT,
            nonce TEXT,
            salt TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'pending',
            file_url TEXT,
            file_name TEXT,
            file_size INTEGER,
            file_type TEXT,
            FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_requests_receiver ON message_requests(receiver_id, status)")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocked_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            blocked_id INTEGER NOT NULL,
            blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (blocked_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(user_id, blocked_id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS file_attachments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id INTEGER,
            request_id INTEGER,
            filename TEXT NOT NULL,
            original_name TEXT NOT NULL,
            file_type TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            mime_type TEXT,
            file_path TEXT NOT NULL,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE,
            FOREIGN KEY (request_id) REFERENCES message_requests(id) ON DELETE CASCADE,
            CHECK (message_id IS NOT NULL OR request_id IS NOT NULL)
        )
    """)

    # Create default admin with random password if not exists
    cursor.execute("SELECT id FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        admin_password = secrets.token_urlsafe(16)
        admin_hash = generate_password_hash(admin_password)
        cursor.execute("""
            INSERT INTO users (username, email, password_hash, display_name, is_admin)
            VALUES (?, ?, ?, ?, ?)
        """, ('admin', 'admin@valuchat.com', admin_hash, 'System Admin', 1))
        print(f"=" * 60)
        print(f"DEFAULT ADMIN CREATED")
        print(f"Username: admin")
        print(f"Password: {admin_password}")
        print(f"=" * 60)

    conn.commit()
    conn.close()

# ==================== ENCRYPTION ====================
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())

def generate_key_pair():
    return secrets.token_hex(32)

def encrypt_message(message: str, key: bytes) -> dict:
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, message.encode(), None)
    return {
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'nonce': base64.b64encode(nonce).decode(),
        'salt': secrets.token_hex(16)
    }

def decrypt_message(ciphertext_b64: str, nonce_b64: str, key: bytes) -> str:
    aesgcm = AESGCM(key)
    ciphertext = base64.b64decode(ciphertext_b64)
    nonce = base64.b64decode(nonce_b64)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()

# ==================== HELPER: BROADCAST STATUS ====================
def broadcast_user_status(user_id, status):
    """Broadcast user status change to all contacts"""
    conn = get_db()
    cursor = conn.cursor()

    # Find all users who have this user as a contact
    cursor.execute("SELECT user_id FROM contacts WHERE contact_id = ?", (user_id,))
    contact_users = cursor.fetchall()
    conn.close()

    for row in contact_users:
        socketio.emit('user_status_change', {
            'user_id': user_id,
            'status': status,
            'last_seen': datetime.now().isoformat()
        }, room=f"user_{row['user_id']}")

# ==================== ROUTES ====================
@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? AND is_active = 1", (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']

            cursor.execute("""
                INSERT INTO login_logs (user_id, ip_address, user_agent, success)
                VALUES (?, ?, ?, ?)
            """, (user['id'], request.remote_addr, request.user_agent.string, 1))

            cursor.execute("UPDATE users SET status = 'online', last_seen = CURRENT_TIMESTAMP WHERE id = ?", (user['id'],))
            conn.commit()
            conn.close()

            return redirect(url_for('chat'))
        else:
            cursor.execute("""
                INSERT INTO login_logs (user_id, ip_address, user_agent, success)
                VALUES (?, ?, ?, ?)
            """, (user['id'] if user else None, request.remote_addr, request.user_agent.string, 0))
            conn.commit()
            conn.close()
            flash('Invalid username or password', 'error')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        display_name = request.form.get('display_name', '').strip()

        if len(password) < 8:
            flash('Password must be at least 8 characters', 'error')
            return render_template('register.html')
        if not any(c.isupper() for c in password):
            flash('Password must contain at least one uppercase letter', 'error')
            return render_template('register.html')
        if not any(c.islower() for c in password):
            flash('Password must contain at least one lowercase letter', 'error')
            return render_template('register.html')
        if not any(c.isdigit() for c in password):
            flash('Password must contain at least one digit', 'error')
            return render_template('register.html')

        password_hash = generate_password_hash(password)
        salt = secrets.token_hex(16)
        private_key = generate_key_pair()
        public_key = generate_key_pair()

        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, display_name, public_key, private_key_encrypted, salt)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (username, email, password_hash, display_name or username, public_key, private_key, salt))
            conn.commit()
            flash('Account created successfully! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists', 'error')
        finally:
            conn.close()

    return render_template('register.html')

@app.route('/chat')
def chat():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('chat.html')

@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    if user_id:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET status = 'offline', last_seen = CURRENT_TIMESTAMP WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        # Broadcast offline status to contacts
        broadcast_user_status(user_id, 'offline')
    session.clear()
    return redirect(url_for('landing'))

# Serve uploaded files
@app.route('/static/uploads/<path:filename>')
def serve_upload(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ==================== API ROUTES ====================
@app.route('/api/user')
def get_user():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, display_name, email, status, avatar_url, public_key FROM users WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    conn.close()

    if user:
        return jsonify({
            'id': user['id'],
            'username': user['username'],
            'display_name': user['display_name'],
            'email': user['email'],
            'status': user['status'],
            'avatar_url': user['avatar_url'],
            'public_key': user['public_key']
        })
    return jsonify({'error': 'User not found'}), 404

@app.route('/api/contacts')
def get_contacts():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT u.id, u.username, u.display_name, u.status, u.last_seen, u.public_key, c.nickname
        FROM contacts c
        JOIN users u ON c.contact_id = u.id
        WHERE c.user_id = ? AND u.is_active = 1
    """, (session['user_id'],))
    contacts = cursor.fetchall()
    conn.close()

    return jsonify([{
        'id': c['id'],
        'username': c['username'],
        'display_name': c['nickname'] or c['display_name'],
        'status': c['status'],
        'last_seen': c['last_seen'],
        'public_key': c['public_key']
    } for c in contacts])

@app.route('/api/search-users')
def search_users():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    query = request.args.get('q', '').strip()
    if not query or len(query) < 2:
        return jsonify([])

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, username, display_name, status, public_key 
        FROM users 
        WHERE (username LIKE ? OR display_name LIKE ?) 
        AND id != ? AND is_active = 1
        LIMIT 10
    """, (f'%{query}%', f'%{query}%', session['user_id']))
    users = cursor.fetchall()
    conn.close()

    return jsonify([{
        'id': u['id'],
        'username': u['username'],
        'display_name': u['display_name'],
        'status': u['status'],
        'public_key': u['public_key']
    } for u in users])

@app.route('/api/add-contact', methods=['POST'])
def add_contact():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    contact_id = data.get('contact_id')
    nickname = data.get('nickname', '')

    if not contact_id:
        return jsonify({'error': 'Contact ID required'}), 400

    if int(contact_id) == session['user_id']:
        return jsonify({'error': 'Cannot add yourself'}), 400

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO contacts (user_id, contact_id, nickname)
            VALUES (?, ?, ?)
        """, (session['user_id'], contact_id, nickname or None))
        conn.commit()
        return jsonify({'success': True, 'message': 'Contact added'})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Contact already exists'}), 400
    finally:
        conn.close()

@app.route('/api/messages/<int:contact_id>')
def get_messages(contact_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT m.*, s.username as sender_name, s.display_name as sender_display
        FROM messages m
        JOIN users s ON m.sender_id = s.id
        WHERE (m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?)
        ORDER BY m.timestamp ASC
        LIMIT 100
    """, (session['user_id'], contact_id, contact_id, session['user_id']))
    messages = cursor.fetchall()

    result = []
    for m in messages:
        cursor.execute("""
            SELECT * FROM file_attachments WHERE message_id = ?
        """, (m['id'],))
        files = cursor.fetchall()

        msg_dict = {
            'id': m['id'],
            'sender_id': m['sender_id'],
            'sender_name': m['sender_display'] or m['sender_name'],
            'encrypted_content': m['encrypted_content'],
            'nonce': m['nonce'],
            'salt': m['salt'],
            'timestamp': m['timestamp'],
            'is_read': m['is_read'],
            'message_type': m['message_type'],
            'file_url': m['file_url'],
            'file_name': m['file_name'],
            'file_size': m['file_size'],
            'file_type': m['file_type'],
            'files': [{
                'id': f['id'],
                'filename': f['filename'],
                'original_name': f['original_name'],
                'file_type': f['file_type'],
                'file_size': f['file_size'],
                'mime_type': f['mime_type'],
                'url': f"/static/uploads/{f['file_type']}s/{f['filename']}"
            } for f in files]
        }
        result.append(msg_dict)

    cursor.execute("""
        UPDATE messages SET is_read = 1 
        WHERE sender_id = ? AND receiver_id = ? AND is_read = 0
    """, (contact_id, session['user_id']))
    conn.commit()
    conn.close()

    return jsonify(result)

# ==================== SOCKET.IO EVENTS ====================
@socketio.on('connect')
def handle_connect(auth=None):
    if 'user_id' in session:
        user_id = session['user_id']
        join_room(f"user_{user_id}")

        # Mark user as online in DB
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET status = 'online', last_seen = CURRENT_TIMESTAMP WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()

        # Track in memory
        online_users[user_id] = datetime.now()

        # Broadcast online status to contacts
        broadcast_user_status(user_id, 'online')

        emit('connected', {'status': 'connected', 'user_id': user_id})

@socketio.on('disconnect')
def handle_disconnect(auth=None):
    if 'user_id' in session:
        user_id = session['user_id']
        leave_room(f"user_{user_id}")

        # Remove from online tracking
        if user_id in online_users:
            del online_users[user_id]

        # Mark as offline in DB
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET status = 'offline', last_seen = CURRENT_TIMESTAMP WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()

        # Broadcast offline status to contacts
        broadcast_user_status(user_id, 'offline')

@socketio.on('heartbeat')
def handle_heartbeat(data):
    """Client sends heartbeat every 30s to keep status online"""
    if 'user_id' in session:
        user_id = session['user_id']
        online_users[user_id] = datetime.now()

        # Ensure DB status is online
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET status = 'online', last_seen = CURRENT_TIMESTAMP WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()

@socketio.on('send_message')
def handle_send_message(data):
    if 'user_id' not in session:
        emit('error', {'message': 'Not authenticated'})
        return

    receiver_id = data.get('receiver_id')
    encrypted_content = data.get('encrypted_content')
    nonce = data.get('nonce')
    salt = data.get('salt')

    if not all([receiver_id, encrypted_content, nonce, salt]):
        emit('error', {'message': 'Missing message data'})
        return

    try:
        decoded = base64.b64decode(encrypted_content)
        if len(decoded) > 1024 * 1024:
            emit('error', {'message': 'Message too large'})
            return
    except Exception:
        emit('error', {'message': 'Invalid message format'})
        return

    receiver_id = int(receiver_id)
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id FROM blocked_users 
        WHERE user_id = ? AND blocked_id = ?
    """, (receiver_id, session['user_id']))
    if cursor.fetchone():
        conn.close()
        emit('error', {'message': 'You have been blocked by this user'})
        return

    cursor.execute("""
        SELECT id FROM contacts 
        WHERE user_id = ? AND contact_id = ?
    """, (receiver_id, session['user_id']))
    is_contact = cursor.fetchone() is not None

    if is_contact:
        cursor.execute("""
            INSERT INTO messages (sender_id, receiver_id, encrypted_content, nonce, salt)
            VALUES (?, ?, ?, ?, ?)
        """, (session['user_id'], receiver_id, encrypted_content, nonce, salt))
        message_id = cursor.lastrowid
        conn.commit()

        cursor.execute("SELECT username, display_name FROM users WHERE id = ?", (session['user_id'],))
        sender = cursor.fetchone()
        conn.close()

        message_data = {
            'id': message_id,
            'sender_id': session['user_id'],
            'sender_name': sender['display_name'] or sender['username'],
            'receiver_id': receiver_id,
            'encrypted_content': encrypted_content,
            'nonce': nonce,
            'salt': salt,
            'timestamp': datetime.now().isoformat(),
            'is_request': False
        }

        socketio.emit('new_message', message_data, room=f"user_{receiver_id}")
        emit('message_sent', message_data)
    else:
        cursor.execute("""
            INSERT INTO message_requests (sender_id, receiver_id, encrypted_content, nonce, salt)
            VALUES (?, ?, ?, ?, ?)
        """, (session['user_id'], receiver_id, encrypted_content, nonce, salt))
        request_id = cursor.lastrowid
        conn.commit()

        cursor.execute("SELECT username, display_name FROM users WHERE id = ?", (session['user_id'],))
        sender = cursor.fetchone()
        conn.close()

        request_data = {
            'id': request_id,
            'sender_id': session['user_id'],
            'sender_name': sender['display_name'] or sender['username'],
            'receiver_id': receiver_id,
            'encrypted_content': encrypted_content,
            'nonce': nonce,
            'salt': salt,
            'timestamp': datetime.now().isoformat(),
            'is_request': True
        }

        socketio.emit('new_message_request', request_data, room=f"user_{receiver_id}")
        emit('message_request_sent', request_data)

@socketio.on('typing')
def handle_typing(data):
    if 'user_id' in session:
        receiver_id = data.get('receiver_id')
        socketio.emit('user_typing', {
            'user_id': session['user_id'],
            'username': session['username']
        }, room=f"user_{receiver_id}")

# ==================== MESSAGE REQUEST ROUTES ====================
@app.route('/api/message-requests')
def get_message_requests():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT mr.*, u.username, u.display_name, u.status
        FROM message_requests mr
        JOIN users u ON mr.sender_id = u.id
        WHERE mr.receiver_id = ? AND mr.status = 'pending'
        ORDER BY mr.timestamp DESC
    """, (session['user_id'],))
    requests = cursor.fetchall()
    conn.close()

    return jsonify([{
        'id': r['id'],
        'sender_id': r['sender_id'],
        'sender_name': r['display_name'] or r['username'],
        'sender_username': r['username'],
        'encrypted_content': r['encrypted_content'],
        'nonce': r['nonce'],
        'salt': r['salt'],
        'timestamp': r['timestamp'],
        'status': r['status'],
        'file_url': r['file_url'],
        'file_name': r['file_name'],
        'file_size': r['file_size'],
        'file_type': r['file_type']
    } for r in requests])


@app.route('/api/message-requests/count')
def get_message_request_count():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT COUNT(*) as count FROM message_requests
        WHERE receiver_id = ? AND status = 'pending'
    """, (session['user_id'],))
    count = cursor.fetchone()['count']
    conn.close()

    return jsonify({'count': count})


@app.route('/api/message-requests/<int:request_id>/accept', methods=['POST'])
def accept_message_request(request_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM message_requests WHERE id = ? AND receiver_id = ? AND status = 'pending'
    """, (request_id, session['user_id']))
    req = cursor.fetchone()

    if not req:
        conn.close()
        return jsonify({'error': 'Request not found'}), 404

    cursor.execute("""
        INSERT OR IGNORE INTO contacts (user_id, contact_id, nickname)
        VALUES (?, ?, ?)
    """, (session['user_id'], req['sender_id'], None))

    cursor.execute("""
        INSERT OR IGNORE INTO contacts (user_id, contact_id, nickname)
        VALUES (?, ?, ?)
    """, (req['sender_id'], session['user_id'], None))

    cursor.execute("""
        INSERT INTO messages (sender_id, receiver_id, encrypted_content, nonce, salt, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (req['sender_id'], session['user_id'], req['encrypted_content'], 
          req['nonce'], req['salt'], req['timestamp']))

    cursor.execute("""
        UPDATE message_requests SET status = 'accepted' WHERE id = ?
    """, (request_id,))

    conn.commit()
    conn.close()

    socketio.emit('request_accepted', {
        'accepted_by': session['user_id'],
        'accepted_by_name': 'User',
        'sender_id': req['sender_id']
    }, room=f"user_{req['sender_id']}")

    return jsonify({'success': True, 'message': 'Request accepted'})


@app.route('/api/message-requests/<int:request_id>/decline', methods=['POST'])
def decline_message_request(request_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE message_requests SET status = 'declined' 
        WHERE id = ? AND receiver_id = ? AND status = 'pending'
    """, (request_id, session['user_id']))

    if cursor.rowcount == 0:
        conn.close()
        return jsonify({'error': 'Request not found'}), 404

    conn.commit()
    conn.close()

    return jsonify({'success': True, 'message': 'Request declined'})


@app.route('/api/message-requests/<int:request_id>/block', methods=['POST'])
def block_from_request(request_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT sender_id FROM message_requests 
        WHERE id = ? AND receiver_id = ? AND status = 'pending'
    """, (request_id, session['user_id']))
    req = cursor.fetchone()

    if not req:
        conn.close()
        return jsonify({'error': 'Request not found'}), 404

    cursor.execute("""
        INSERT OR IGNORE INTO blocked_users (user_id, blocked_id)
        VALUES (?, ?)
    """, (session['user_id'], req['sender_id']))

    cursor.execute("""
        UPDATE message_requests SET status = 'declined' WHERE id = ?
    """, (request_id,))

    conn.commit()
    conn.close()

    return jsonify({'success': True, 'message': 'User blocked'})


@app.route('/api/blocked-users', methods=['GET', 'POST', 'DELETE'])
def manage_blocked_users():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    conn = get_db()
    cursor = conn.cursor()

    if request.method == 'GET':
        cursor.execute("""
            SELECT b.blocked_id, u.username, u.display_name
            FROM blocked_users b
            JOIN users u ON b.blocked_id = u.id
            WHERE b.user_id = ?
        """, (session['user_id'],))
        blocked = cursor.fetchall()
        conn.close()
        return jsonify([{
            'id': b['blocked_id'],
            'username': b['username'],
            'display_name': b['display_name']
        } for b in blocked])

    elif request.method == 'POST':
        data = request.get_json()
        blocked_id = data.get('blocked_id')
        if not blocked_id:
            return jsonify({'error': 'blocked_id required'}), 400

        cursor.execute("""
            INSERT OR IGNORE INTO blocked_users (user_id, blocked_id)
            VALUES (?, ?)
        """, (session['user_id'], blocked_id))
        conn.commit()
        conn.close()
        return jsonify({'success': True})

    elif request.method == 'DELETE':
        data = request.get_json()
        blocked_id = data.get('blocked_id')
        if not blocked_id:
            return jsonify({'error': 'blocked_id required'}), 400

        cursor.execute("""
            DELETE FROM blocked_users WHERE user_id = ? AND blocked_id = ?
        """, (session['user_id'], blocked_id))
        conn.commit()
        conn.close()
        return jsonify({'success': True})


# ==================== FILE UPLOAD ROUTES ====================
@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400

    original_name = secure_filename(file.filename)
    ext = original_name.rsplit('.', 1)[1].lower() if '.' in original_name else ''
    unique_name = f"{uuid.uuid4().hex}.{ext}" if ext else f"{uuid.uuid4().hex}"

    file_type = get_file_type(original_name)
    type_folder = os.path.join(app.config['UPLOAD_FOLDER'], file_type + 's')
    os.makedirs(type_folder, exist_ok=True)

    file_path = os.path.join(type_folder, unique_name)
    file.save(file_path)

    file_size = os.path.getsize(file_path)
    mime_type, _ = mimetypes.guess_type(original_name)

    return jsonify({
        'success': True,
        'filename': unique_name,
        'original_name': original_name,
        'file_type': file_type,
        'file_size': file_size,
        'mime_type': mime_type,
        'url': f"/static/uploads/{file_type}s/{unique_name}"
    })


@app.route('/api/upload-chat-file', methods=['POST'])
def upload_chat_file():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    receiver_id = request.form.get('receiver_id')
    if not receiver_id:
        return jsonify({'error': 'Receiver ID required'}), 400

    receiver_id = int(receiver_id)

    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400

    original_name = secure_filename(file.filename)
    ext = original_name.rsplit('.', 1)[1].lower() if '.' in original_name else ''
    unique_name = f"{uuid.uuid4().hex}.{ext}" if ext else f"{uuid.uuid4().hex}"

    file_type = get_file_type(original_name)
    upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], file_type + 's')
    os.makedirs(upload_dir, exist_ok=True)

    file_path = os.path.join(upload_dir, unique_name)
    file.save(file_path)

    file_size = os.path.getsize(file_path)
    file_url = f"/static/uploads/{file_type}s/{unique_name}"

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM blocked_users WHERE user_id = ? AND blocked_id = ?", (receiver_id, session['user_id']))
    if cursor.fetchone():
        conn.close()
        return jsonify({'error': 'You have been blocked by this user'}), 403

    cursor.execute("SELECT id FROM contacts WHERE user_id = ? AND contact_id = ?", (receiver_id, session['user_id']))
    is_contact = cursor.fetchone() is not None

    if is_contact:
        cursor.execute("""
            INSERT INTO messages (sender_id, receiver_id, encrypted_content, nonce, salt, message_type, file_url, file_name, file_size, file_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (session['user_id'], receiver_id, '', '', '', file_type, file_url, original_name, file_size, file_type))
        message_id = cursor.lastrowid
        conn.commit()

        cursor.execute("SELECT username, display_name FROM users WHERE id = ?", (session['user_id'],))
        sender = cursor.fetchone()
        conn.close()

        message_data = {
            'id': message_id,
            'sender_id': session['user_id'],
            'sender_name': sender['display_name'] or sender['username'],
            'receiver_id': receiver_id,
            'encrypted_content': '',
            'nonce': '',
            'salt': '',
            'timestamp': datetime.now().isoformat(),
            'is_request': False,
            'message_type': file_type,
            'file_url': file_url,
            'file_name': original_name,
            'file_size': file_size,
            'file_type': file_type
        }

        socketio.emit('new_message', message_data, room=f"user_{receiver_id}")
        return jsonify({'success': True, 'message': 'File sent', 'data': message_data})
    else:
        cursor.execute("""
            INSERT INTO message_requests (sender_id, receiver_id, encrypted_content, nonce, salt, file_url, file_name, file_size, file_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (session['user_id'], receiver_id, '', '', '', file_url, original_name, file_size, file_type))
        request_id = cursor.lastrowid
        conn.commit()

        cursor.execute("SELECT username, display_name FROM users WHERE id = ?", (session['user_id'],))
        sender = cursor.fetchone()
        conn.close()

        request_data = {
            'id': request_id,
            'sender_id': session['user_id'],
            'sender_name': sender['display_name'] or sender['username'],
            'receiver_id': receiver_id,
            'encrypted_content': '',
            'nonce': '',
            'salt': '',
            'timestamp': datetime.now().isoformat(),
            'is_request': True,
            'file_url': file_url,
            'file_name': original_name,
            'file_size': file_size,
            'file_type': file_type
        }

        socketio.emit('new_message_request', request_data, room=f"user_{receiver_id}")
        return jsonify({'success': True, 'message': 'File request sent', 'data': request_data})


# ==================== ADMIN ROUTES ====================
@app.route('/admin')
def admin_dashboard():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    return render_template('admin.html')

@app.route('/api/admin/stats')
def admin_stats():
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 403

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as total FROM users")
    total_users = cursor.fetchone()['total']

    cursor.execute("SELECT COUNT(*) as online FROM users WHERE status = 'online'")
    online_users = cursor.fetchone()['online']

    cursor.execute("SELECT COUNT(*) as total FROM messages")
    total_messages = cursor.fetchone()['total']

    cursor.execute("SELECT COUNT(*) as today FROM messages WHERE date(timestamp) = date('now')")
    today_messages = cursor.fetchone()['today']

    cursor.execute("SELECT COUNT(*) as failed FROM login_logs WHERE success = 0 AND date(login_time) = date('now')")
    failed_logins = cursor.fetchone()['failed']

    conn.close()

    return jsonify({
        'total_users': total_users,
        'online_users': online_users,
        'total_messages': total_messages,
        'today_messages': today_messages,
        'failed_logins': failed_logins
    })

@app.route('/api/admin/users')
def admin_users():
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 403

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, username, email, display_name, status, last_seen, created_at, is_active, is_admin
        FROM users ORDER BY created_at DESC
    """)
    users = cursor.fetchall()
    conn.close()

    return jsonify([{
        'id': u['id'],
        'username': u['username'],
        'email': u['email'],
        'display_name': u['display_name'],
        'status': u['status'],
        'last_seen': u['last_seen'],
        'created_at': u['created_at'],
        'is_active': u['is_active'],
        'is_admin': u['is_admin']
    } for u in users])

# ==================== MAIN ====================
if __name__ == '__main__':
    init_db()
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
