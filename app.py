from flask import Flask, render_template, request, jsonify, send_file
import os
import json
import requests
from werkzeug.utils import secure_filename
from datetime import datetime
import sqlite3
import threading
import mimetypes
import io

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['DATABASE'] = 'files.db'

# Telegram Configuration
TELEGRAM_BOT_TOKEN = '7824643790:AAHEUacWhMqzxpQIFwqNo2pd6vJZkqHB5rY'
TELEGRAM_CHANNEL_ID = '-1002447886434'
TELEGRAM_API_URL = f'https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}'

# Create required directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

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

def init_db():
    with sqlite3.connect(app.config['DATABASE']) as conn:
        # Only create table if it doesn't exist
        conn.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                original_filename TEXT NOT NULL,
                telegram_file_id TEXT,
                telegram_message_id TEXT,
                upload_date TEXT NOT NULL,
                file_size INTEGER,
                file_type TEXT,
                mime_type TEXT
            )
        ''')

def get_db():
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    return db

@app.before_first_request
def before_first_request():
    init_db()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/files', methods=['GET'])
def get_files():
    try:
        with get_db() as db:
            files = db.execute('SELECT * FROM files ORDER BY upload_date DESC').fetchall()
            return jsonify([dict(file) for file in files])
    except sqlite3.Error as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    try:
        # Save file locally
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        saved_filename = f"{timestamp}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], saved_filename)
        file.save(filepath)

        # Get file information
        file_size = os.path.getsize(filepath)
        mime_type, _ = mimetypes.guess_type(filename)
        file_type = get_file_type_icon(filename)

        # Upload to Telegram
        with open(filepath, 'rb') as f:
            files = {'document': f}
            caption = f"📄 File: {filename}\n📦 Size: {file_size/1024/1024:.2f}MB\n🔤 Type: {mime_type or 'Unknown'}"
            response = requests.post(
                f'{TELEGRAM_API_URL}/sendDocument',
                data={'chat_id': TELEGRAM_CHANNEL_ID, 'caption': caption},
                files=files
            )

        if response.status_code != 200:
            os.remove(filepath)
            return jsonify({'error': 'Failed to upload to Telegram'}), 500

        result = response.json()['result']
        telegram_file_id = result['document']['file_id']
        telegram_message_id = result['message_id']

        # Save file info to database
        with get_db() as db:
            db.execute('''
                INSERT INTO files (
                    filename, original_filename, telegram_file_id, telegram_message_id,
                    upload_date, file_size, file_type, mime_type
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                saved_filename, filename, telegram_file_id, telegram_message_id,
                datetime.now().isoformat(), file_size, file_type, mime_type
            ))

        # Clean up local file after successful upload
        os.remove(filepath)

        return jsonify({
            'message': 'File uploaded successfully',
            'filename': filename,
            'size': file_size,
            'type': file_type,
            'mime_type': mime_type
        })

    except Exception as e:
        if os.path.exists(filepath):
            os.remove(filepath)
        return jsonify({'error': str(e)}), 500

@app.route('/api/download/<int:file_id>')
def download_file(file_id):
    try:
        with get_db() as db:
            file = db.execute('SELECT * FROM files WHERE id = ?', (file_id,)).fetchone()
            if not file:
                return jsonify({'error': 'File not found'}), 404

            # Get file from Telegram
            response = requests.get(
                f'{TELEGRAM_API_URL}/getFile',
                params={'file_id': file['telegram_file_id']}
            )
            
            if response.status_code != 200:
                return jsonify({'error': 'Failed to get file from Telegram'}), 500

            file_path = response.json()['result']['file_path']
            file_url = f'https://api.telegram.org/file/bot{TELEGRAM_BOT_TOKEN}/{file_path}'
            
            # Download file from Telegram
            response = requests.get(file_url)
            if response.status_code != 200:
                return jsonify({'error': 'Failed to download file from Telegram'}), 500

            # Create BytesIO object from response content
            file_data = io.BytesIO(response.content)
            file_data.seek(0)

            return send_file(
                file_data,
                download_name=file['original_filename'],
                as_attachment=True,
                mimetype=file['mime_type']
            )

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/delete/<int:file_id>', methods=['DELETE'])
def delete_file(file_id):
    try:
        with get_db() as db:
            file = db.execute('SELECT * FROM files WHERE id = ?', (file_id,)).fetchone()
            if not file:
                return jsonify({'error': 'File not found'}), 404

            # Delete from Telegram channel
            response = requests.post(
                f'{TELEGRAM_API_URL}/deleteMessage',
                data={
                    'chat_id': TELEGRAM_CHANNEL_ID,
                    'message_id': file['telegram_message_id']
                }
            )

            # Delete from database regardless of Telegram response
            db.execute('DELETE FROM files WHERE id = ?', (file_id,))
            
            # Check Telegram response after database deletion
            if response.status_code != 200:
                # Log the error but don't fail the request
                print(f"Warning: Failed to delete message from Telegram: {response.text}")

        return jsonify({'message': 'File deleted successfully'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)