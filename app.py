from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session, flash
import os
import requests
import sqlite3
import mimetypes
import io
import uuid
from datetime import datetime
from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image  # For thumbnail generation

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['DATABASE'] = 'files.db'
app.secret_key = 'your_secret_key_here'  # Change this for production!

# Telegram Configuration
TELEGRAM_BOT_TOKEN = '7824643790:AAHEUacWhMqzxpQIFwqNo2pd6vJZkqHB5rY'
TELEGRAM_CHANNEL_ID = '-1002447886434'
TELEGRAM_API_URL = f'https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}'

# Create required directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
THUMBNAIL_FOLDER = 'thumbnails'
os.makedirs(THUMBNAIL_FOLDER, exist_ok=True)

def get_file_type_icon(filename):
    mime_type, _ = mimetypes.guess_type(filename)
    if mime_type:
        if 'image' in mime_type:
            return 'image'
        elif 'video' in mime_type:
            return 'video'
        elif 'audio' in mime_type:
            return 'audio'
        elif 'pdf' in mime_type:
            return 'pdf'
        elif 'text' in mime_type:
            return 'text'
        elif 'spreadsheet' in mime_type or 'excel' in mime_type:
            return 'spreadsheet'
        elif 'presentation' in mime_type or 'powerpoint' in mime_type:
            return 'presentation'
    return 'document'

def get_db():
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    return db

def init_db():
    with get_db() as conn:
        # Create users table if it doesn't exist
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        # Check if "is_admin" column exists; if not, add it.
        cursor = conn.execute("PRAGMA table_info(users)")
        user_columns = [row["name"] for row in cursor.fetchall()]
        if "is_admin" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
        
        # Create files table if it doesn't exist (added thumbnail_filename column)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                filename TEXT NOT NULL,
                original_filename TEXT NOT NULL,
                telegram_file_id TEXT,
                telegram_message_id TEXT,
                upload_date TEXT NOT NULL,
                file_size INTEGER,
                file_type TEXT,
                mime_type TEXT,
                thumbnail_filename TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        # Check if "user_id" and "thumbnail_filename" columns exist; if not, add them.
        cursor = conn.execute("PRAGMA table_info(files)")
        file_columns = [row["name"] for row in cursor.fetchall()]
        if "user_id" not in file_columns:
            conn.execute("ALTER TABLE files ADD COLUMN user_id INTEGER")
        if "thumbnail_filename" not in file_columns:
            conn.execute("ALTER TABLE files ADD COLUMN thumbnail_filename TEXT")
        
        # Create share_links table for public sharing
        conn.execute('''
            CREATE TABLE IF NOT EXISTS share_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER NOT NULL,
                token TEXT NOT NULL UNIQUE,
                expiration TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(file_id) REFERENCES files(id)
            )
        ''')
        
        # Create a default admin user if it doesn't exist
        cur = conn.execute("SELECT * FROM users WHERE username = ?", ("admin",))
        if not cur.fetchone():
            admin_password = generate_password_hash("admin123")
            conn.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)", ("admin", admin_password, 1))
            print("Default admin account created (username: admin, password: admin123)")

@app.before_first_request
def before_first_request():
    init_db()

# ---------------------------
# Decorators
# ---------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('login'))
        with get_db() as db:
            user = db.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
            if not user or user["is_admin"] != 1:
                flash("You do not have permission to access this page.", "danger")
                return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# ---------------------------
# Authentication Routes
# ---------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        if not username or not password:
            flash("Username and password are required", "danger")
            return redirect(url_for('register'))
        hashed_pw = generate_password_hash(password)
        try:
            with get_db() as db:
                db.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username already exists", "danger")
            return redirect(url_for('register'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        with get_db() as db:
            user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['is_admin'] = user['is_admin']
                flash("Logged in successfully", "success")
                return redirect(url_for('index'))
            else:
                flash("Invalid username or password", "danger")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully", "success")
    return redirect(url_for('login'))

# ---------------------------
# Main App Routes
# ---------------------------
@app.route('/')
@login_required
def index():
    return render_template('index.html', username=session.get('username'))

@app.route('/api/files', methods=['GET'])
@login_required
def get_files():
    try:
        with get_db() as db:
            files = db.execute('SELECT * FROM files WHERE user_id = ? ORDER BY upload_date DESC', 
                               (session['user_id'],)).fetchall()
            return jsonify([dict(file) for file in files])
    except sqlite3.Error as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/storage', methods=['GET'])
@login_required
def get_storage():
    try:
        with get_db() as db:
            total = db.execute('SELECT SUM(file_size) as total FROM files WHERE user_id = ?', (session['user_id'],)).fetchone()
            used = total['total'] if total['total'] is not None else 0
            return jsonify({'used_bytes': used})
    except sqlite3.Error as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    files = request.files.getlist('file')
    if not files:
        return jsonify({'error': 'No file selected'}), 400

    responses = []
    for file in files:
        if file.filename == '':
            continue
        try:
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S%f')
            saved_filename = f"{timestamp}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], saved_filename)
            file.save(filepath)
            file_size = os.path.getsize(filepath)
            mime_type, _ = mimetypes.guess_type(filename)
            file_type = get_file_type_icon(filename)
            
            # Generate low-resolution thumbnail for images
            thumbnail_filename = None
            if mime_type and mime_type.startswith('image'):
                try:
                    with Image.open(filepath) as img:
                        img.thumbnail((200, 200))
                        thumbnail_filename = f"thumb_{saved_filename}"
                        thumbnail_path = os.path.join(THUMBNAIL_FOLDER, thumbnail_filename)
                        img.save(thumbnail_path, optimize=True, quality=50)
                except Exception as thumb_err:
                    print(f"Thumbnail generation failed for {filename}: {thumb_err}")

            # Upload file to Telegram
            with open(filepath, 'rb') as f:
                files_data = {'document': f}
                caption = f"📄 File: {filename}\n📦 Size: {file_size/1024/1024:.2f}MB\n🔤 Type: {mime_type or 'Unknown'}"
                response = requests.post(
                    f'{TELEGRAM_API_URL}/sendDocument',
                    data={'chat_id': TELEGRAM_CHANNEL_ID, 'caption': caption},
                    files=files_data
                )
            if response.status_code != 200:
                os.remove(filepath)
                responses.append({'error': f'Failed to upload {filename} to Telegram'})
                continue
            result = response.json()['result']
            telegram_file_id = result['document']['file_id']
            telegram_message_id = result['message_id']
            with get_db() as db:
                db.execute('''
                    INSERT INTO files (
                        user_id, filename, original_filename, telegram_file_id, telegram_message_id,
                        upload_date, file_size, file_type, mime_type, thumbnail_filename
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    session['user_id'], saved_filename, filename, telegram_file_id, telegram_message_id,
                    datetime.now().isoformat(), file_size, file_type, mime_type, thumbnail_filename
                ))
            # Remove any temporary file
            os.remove(filepath)
            responses.append({
                'message': f'{filename} uploaded successfully',
                'filename': filename,
                'size': file_size,
                'type': file_type,
                'mime_type': mime_type
            })
        except Exception as e:
            if os.path.exists(filepath):
                os.remove(filepath)
            responses.append({'error': f'Error uploading {filename}: {str(e)}'})
    if any('error' in resp for resp in responses):
        return jsonify(responses), 207  # Multi-status if some errors occurred
    return jsonify(responses)

@app.route('/api/thumbnail/<int:file_id>')
@login_required
def get_thumbnail(file_id):
    try:
        with get_db() as db:
            file = db.execute('SELECT * FROM files WHERE id = ? AND user_id = ?', (file_id, session['user_id'])).fetchone()
            if not file:
                return jsonify({'error': 'Thumbnail not found'}), 404
            if file['thumbnail_filename']:
                thumbnail_path = os.path.join(THUMBNAIL_FOLDER, file['thumbnail_filename'])
                if os.path.exists(thumbnail_path):
                    return send_file(thumbnail_path, mimetype=file['mime_type'])
            return redirect(url_for('download_file', file_id=file_id))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/download/<int:file_id>')
@login_required
def download_file(file_id):
    try:
        with get_db() as db:
            file = db.execute('SELECT * FROM files WHERE id = ? AND user_id = ?', (file_id, session['user_id'])).fetchone()
            if not file:
                return jsonify({'error': 'File not found'}), 404

            response = requests.get(
                f'{TELEGRAM_API_URL}/getFile',
                params={'file_id': file['telegram_file_id']}
            )
            if response.status_code != 200:
                return jsonify({'error': 'Failed to get file from Telegram'}), 500

            file_path = response.json()['result']['file_path']
            file_url = f'https://api.telegram.org/file/bot{TELEGRAM_BOT_TOKEN}/{file_path}'
            return redirect(file_url)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/delete/<int:file_id>', methods=['DELETE'])
@login_required
def delete_file(file_id):
    try:
        with get_db() as db:
            file = db.execute('SELECT * FROM files WHERE id = ? AND user_id = ?', (file_id, session['user_id'])).fetchone()
            if not file:
                return jsonify({'error': 'File not found'}), 404

            response = requests.post(
                f'{TELEGRAM_API_URL}/deleteMessage',
                data={
                    'chat_id': TELEGRAM_CHANNEL_ID,
                    'message_id': file['telegram_message_id']
                }
            )
            # Remove any share links for this file
            db.execute('DELETE FROM share_links WHERE file_id = ?', (file_id,))
            db.execute('DELETE FROM files WHERE id = ?', (file_id,))
            if file['thumbnail_filename']:
                thumbnail_path = os.path.join(THUMBNAIL_FOLDER, file['thumbnail_filename'])
                if os.path.exists(thumbnail_path):
                    os.remove(thumbnail_path)
            if response.status_code != 200:
                print(f"Warning: Failed to delete Telegram message: {response.text}")
        return jsonify({'message': 'File deleted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/delete_many', methods=['POST'])
@login_required
def delete_many_files():
    try:
        file_ids = request.json.get('file_ids')
        if not file_ids:
            return jsonify({'error': 'No file ids provided'}), 400

        for file_id in file_ids:
            with get_db() as db:
                file = db.execute('SELECT * FROM files WHERE id = ? AND user_id = ?', (file_id, session['user_id'])).fetchone()
                if file:
                    response = requests.post(
                        f'{TELEGRAM_API_URL}/deleteMessage',
                        data={'chat_id': TELEGRAM_CHANNEL_ID, 'message_id': file['telegram_message_id']}
                    )
                    db.execute('DELETE FROM share_links WHERE file_id = ?', (file_id,))
                    db.execute('DELETE FROM files WHERE id = ?', (file_id,))
                    if file['thumbnail_filename']:
                        thumbnail_path = os.path.join(THUMBNAIL_FOLDER, file['thumbnail_filename'])
                        if os.path.exists(thumbnail_path):
                            os.remove(thumbnail_path)
        return jsonify({'message': 'Selected files deleted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ---------------------------
# Share Link Endpoints
# ---------------------------
@app.route('/api/share/create', methods=['POST'])
@login_required
def create_share_link():
    data = request.json
    file_id = data.get('file_id')
    expiration = data.get('expiration')  # Expected as ISO string or null
    if not file_id:
        return jsonify({'error': 'File ID required'}), 400
    with get_db() as db:
        file = db.execute('SELECT * FROM files WHERE id = ? AND user_id = ?', (file_id, session['user_id'])).fetchone()
        if not file:
            return jsonify({'error': 'File not found'}), 404
        token = str(uuid.uuid4())
        created_at = datetime.now().isoformat()
        db.execute('INSERT INTO share_links (file_id, token, expiration, created_at) VALUES (?, ?, ?, ?)',
                   (file_id, token, expiration, created_at))
    share_url = request.host_url + 'share/' + token
    return jsonify({'message': 'Share link created', 'share_url': share_url, 'token': token, 'expiration': expiration})

@app.route('/api/share/list', methods=['GET'])
@login_required
def list_share_links():
    with get_db() as db:
        links = db.execute('''
            SELECT sl.id, sl.token, sl.expiration, sl.created_at, f.original_filename, f.id as file_id
            FROM share_links sl
            JOIN files f ON sl.file_id = f.id
            WHERE f.user_id = ?
            ORDER BY sl.created_at DESC
        ''', (session['user_id'],)).fetchall()
        result = []
        for link in links:
            share_url = request.host_url + 'share/' + link['token']
            result.append({
                'id': link['id'],
                'file_id': link['file_id'],
                'original_filename': link['original_filename'],
                'share_url': share_url,
                'expiration': link['expiration'],
                'created_at': link['created_at']
            })
    return jsonify(result)

@app.route('/api/share/expire/<int:share_id>', methods=['POST'])
@login_required
def expire_share_link(share_id):
    with get_db() as db:
        link = db.execute('''
            SELECT sl.*, f.user_id FROM share_links sl
            JOIN files f ON sl.file_id = f.id
            WHERE sl.id = ? AND f.user_id = ?
        ''', (share_id, session['user_id'])).fetchone()
        if not link:
            return jsonify({'error': 'Share link not found'}), 404
        now_iso = datetime.now().isoformat()
        db.execute('UPDATE share_links SET expiration = ? WHERE id = ?', (now_iso, share_id))
    return jsonify({'message': 'Share link expired', 'share_id': share_id})

@app.route('/api/share/delete/<int:share_id>', methods=['DELETE'])
@login_required
def delete_share_link(share_id):
    with get_db() as db:
        link = db.execute('''
            SELECT sl.*, f.user_id FROM share_links sl
            JOIN files f ON sl.file_id = f.id
            WHERE sl.id = ? AND f.user_id = ?
        ''', (share_id, session['user_id'])).fetchone()
        if not link:
            return jsonify({'error': 'Share link not found'}), 404
        db.execute('DELETE FROM share_links WHERE id = ?', (share_id,))
    return jsonify({'message': 'Share link deleted', 'share_id': share_id})

# Public endpoint to access shared file
@app.route('/share/<token>')
def access_share_link(token):
    with get_db() as db:
        link = db.execute('SELECT * FROM share_links WHERE token = ?', (token,)).fetchone()
        if not link:
            return "Invalid or expired link", 404
        expiration = link['expiration']
        if expiration:
            if datetime.fromisoformat(expiration) < datetime.now():
                return "This link has expired", 410
        file = db.execute('SELECT * FROM files WHERE id = ?', (link['file_id'],)).fetchone()
        if not file:
            return "File not found", 404
        response = requests.get(
            f'{TELEGRAM_API_URL}/getFile',
            params={'file_id': file['telegram_file_id']}
        )
        if response.status_code != 200:
            return "Failed to retrieve file", 500
        file_path = response.json()['result']['file_path']
        file_url = f'https://api.telegram.org/file/bot{TELEGRAM_BOT_TOKEN}/{file_path}'
        return redirect(file_url)

# ---------------------------
# Admin Endpoints (unchanged)
# ---------------------------
def format_bytes(size):
    if size < 1024:
        return f"{size} Bytes"
    elif size < 1024 * 1024:
        return f"{size/1024:.2f} KB"
    elif size < 1024 * 1024 * 1024:
        return f"{size/(1024*1024):.2f} MB"
    else:
        return f"{size/(1024*1024*1024):.2f} GB"

@app.route('/admin')
@admin_required
def admin_panel():
    return render_template('admin.html')

@app.route('/api/admin/users', methods=['GET'])
@admin_required
def get_users():
    try:
        with get_db() as db:
            users = db.execute("SELECT id, username, is_admin FROM users ORDER BY id ASC").fetchall()
            data = []
            for user in users:
                total = db.execute("SELECT SUM(file_size) as total FROM files WHERE user_id = ?", (user["id"],)).fetchone()
                used = total["total"] if total["total"] is not None else 0
                data.append({
                    "id": user["id"],
                    "username": user["username"],
                    "used": used,
                    "used_formatted": format_bytes(used),
                    "is_admin": user["is_admin"]
                })
            return jsonify(data)
    except sqlite3.Error as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/user/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    try:
        with get_db() as db:
            if user_id == session.get("user_id"):
                return jsonify({'error': "You cannot delete your own account"}), 400

            user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            if not user:
                return jsonify({'error': 'User not found'}), 404

            files = db.execute("SELECT * FROM files WHERE user_id = ?", (user_id,)).fetchall()
            for file in files:
                resp = requests.post(
                    f'{TELEGRAM_API_URL}/deleteMessage',
                    data={
                        'chat_id': TELEGRAM_CHANNEL_ID,
                        'message_id': file['telegram_message_id']
                    }
                )
            db.execute("DELETE FROM share_links WHERE file_id IN (SELECT id FROM files WHERE user_id = ?)", (user_id,))
            db.execute("DELETE FROM files WHERE user_id = ?", (user_id,))
            db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        return jsonify({'message': 'User and associated files deleted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
