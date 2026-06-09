from flask import Flask, request, jsonify, send_file, session, redirect, url_for
from datetime import timedelta, datetime
import io
import os
from flask_cors import CORS
import hashlib
import json
from functools import wraps
from flask_pymongo import PyMongo
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message

app = Flask(__name__)
CORS(app, supports_credentials=True) # Allow frontend to make cross-origin requests
app.secret_key = os.getenv("FLASK_SECRET", "supersecretkey123")

# ─── Extensions Configuration ────────────────────────────────────────────────
app.config['MONGO_URI'] = os.getenv('MONGO_URI', 'mongodb://localhost:27017/cloudstore')

app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'true').lower() in ['true', '1', 't']
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

mongo = PyMongo(app)
mail = Mail(app)

# Token Serializer for password resets
s = URLSafeTimedSerializer(app.secret_key)

# User Store is now managed by MongoDB.

MAX_FILE_SIZE_MB = 2048
app.config['MAX_CONTENT_LENGTH'] = 2048 * 1024 * 1024

from services import supabase_storage
import uuid

# ─── Helpers ─────────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

def _is_image(filename: str) -> bool:
    return filename.lower().rsplit(".", 1)[-1] in {"jpg", "jpeg", "png", "gif", "webp"}

# ─── Auth Routes ─────────────────────────────────────────────────────────────

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username", "").strip().lower()
    password = data.get("password", "")
    hashed = hashlib.sha256(password.encode()).hexdigest()
    
    user = mongo.db.users.find_one({"username": username})
    if user and user.get("password_hash") == hashed:
        session["user"] = username
        return jsonify({"message": f"Welcome, {username}!", "user": username})
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/api/signup", methods=["POST"])
def signup():
    data = request.get_json()
    username = data.get("username", "").strip().lower()
    password = data.get("password", "")
    email = data.get("email", "").strip()
    
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    
    existing_user = mongo.db.users.find_one({"username": username})
    if existing_user:
        return jsonify({"error": "User already exists"}), 400
    
    hashed = hashlib.sha256(password.encode()).hexdigest()
    mongo.db.users.insert_one({
        "username": username,
        "password_hash": hashed,
        "email": email if email else None
    })
    
    # Send Welcome Email
    if email and app.config.get('MAIL_USERNAME'):
        try:
            msg = Message("Welcome to CloudStore!", recipients=[email])
            msg.body = f"Hello {username},\n\nWelcome to CloudStore! Your account has been created successfully."
            mail.send(msg)
            print(f"Welcome email sent to {email}")
        except Exception as e:
            print(f"Failed to send email: {e}")
    
    session["user"] = username
    return jsonify({"message": "Account created successfully", "user": username})

@app.route("/api/forgot-password", methods=["POST"])
def forgot_password():
    data = request.get_json()
    email = data.get("email", "").strip()
    if not email:
        return jsonify({"error": "Email is required"}), 400
        
    user = mongo.db.users.find_one({"email": email})
    if not user:
        # Prevent email enumeration by returning a generic success message
        return jsonify({"message": "If an account with that email exists, a reset link has been sent."})
        
    token = s.dumps(email, salt='password-reset-salt')
    # Generate link to the frontend where the token will be parsed
    frontend_url = request.headers.get("Origin", "https://cloudstore-one.vercel.app")
    reset_link = f"{frontend_url}/?reset_token={token}"
    
    try:
        msg = Message("Password Reset Request", recipients=[email])
        msg.body = f"Hello {user['username']},\n\nTo reset your password, click the following link (valid for 1 hour):\n{reset_link}\n\nIf you did not request this, please ignore this email."
        mail.send(msg)
        return jsonify({"message": "If an account with that email exists, a reset link has been sent."})
    except Exception as e:
        return jsonify({"error": "Failed to send reset email"}), 500

@app.route("/api/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json()
    token = data.get("token")
    new_password = data.get("password")
    
    if not token or not new_password:
        return jsonify({"error": "Token and new password are required"}), 400
    if len(new_password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
        
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except Exception as e:
        return jsonify({"error": "The reset link is invalid or has expired"}), 400
        
    hashed = hashlib.sha256(new_password.encode()).hexdigest()
    mongo.db.users.update_one({"email": email}, {"$set": {"password_hash": hashed}})
    
    return jsonify({"message": "Password has been successfully updated"})

@app.route("/api/logout", methods=["POST"])
def logout():
    session.pop("user", None)
    return jsonify({"message": "Logged out"})

@app.route("/api/me")
def me():
    if "user" in session:
        return jsonify({"user": session["user"]})
    return jsonify({"user": None})

# ─── File Routes ─────────────────────────────────────────────────────────────

@app.route("/api/upload", methods=["POST"])
@login_required
def upload():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    folder = request.form.get("folder", "").strip().strip("/")
    user = session["user"]

    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    # Size check
    file.seek(0, 2)
    size = file.tell()
    file.seek(0)
    if size > MAX_FILE_SIZE_MB * 1024 * 1024:
        return jsonify({"error": f"File exceeds {MAX_FILE_SIZE_MB}MB limit"}), 413

    content_type = file.content_type or "application/octet-stream"
    file_id = str(uuid.uuid4())
    storage_key = f"users/{user}/{file_id}"
    full_folder = f"{folder}/" if folder else ""
    display_name = f"{full_folder}{file.filename}"

    try:
        encrypted_size = supabase_storage.upload_file(storage_key, file.stream, content_type)
        
        # Save metadata to MongoDB
        mongo.db.files.insert_one({
            "fileId": file_id,
            "userId": user,
            "fileName": display_name,
            "originalName": file.filename,
            "fileSize": size,
            "encryptedSize": encrypted_size,
            "contentType": content_type,
            "uploadDate": datetime.utcnow().isoformat(),
            "storageKey": storage_key,
            "encrypted": True,
            "bucket": "cloudstore-default" # Keep for frontend compatibility
        })
        
        return jsonify({
            "message": "Upload successful",
            "file": display_name,
            "bucket": "cloudstore-default",
            "size": size,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/files")
@login_required
def list_files():
    user = session["user"]
    is_admin = (user == "admin")
    
    query = {} if is_admin else {"userId": user}
    files_cursor = mongo.db.files.find(query)
    
    result = []
    for f in files_cursor:
        result.append({
            "name": f["fileName"],
            "full_path": f["fileId"], # We use fileId as the path for download/delete
            "size": f["fileSize"],
            "last_modified": f["uploadDate"],
            "bucket": f.get("bucket", "cloudstore-default"),
            "is_image": _is_image(f["originalName"]),
            "owner": f["userId"]
        })

    return jsonify(result)


@app.route("/api/download/<bucket>/<path:filename>")
@login_required
def download(bucket, filename):
    # 'filename' here is actually our fileId
    user = session["user"]
    file_record = mongo.db.files.find_one({"fileId": filename})
    
    if not file_record:
        return jsonify({"error": "File not found"}), 404
        
    if user != "admin" and file_record["userId"] != user:
        return jsonify({"error": "Access denied"}), 403
    
    # Return a URL that the frontend can use to stream the decrypted file
    stream_url = url_for('stream_file', file_id=filename, _external=True)
    return jsonify({"url": stream_url})


@app.route("/api/stream/<file_id>")
def stream_file(file_id):
    """Actual endpoint to stream the decrypted file bytes."""
    # Security: Ensure session exists or token is provided
    if "user" not in session:
        return "Unauthorized", 401
        
    user = session["user"]
    file_record = mongo.db.files.find_one({"fileId": file_id})
    if not file_record:
        return "Not found", 404
        
    if user != "admin" and file_record["userId"] != user:
        return "Forbidden", 403
        
    try:
        file_stream = supabase_storage.download_file(file_record["storageKey"])
        return send_file(
            file_stream, 
            as_attachment=True, 
            download_name=file_record["originalName"],
            mimetype=file_record["contentType"]
        )
    except Exception as e:
        return str(e), 500


@app.route("/api/delete/<bucket>/<path:filename>", methods=["DELETE"])
@login_required
def delete(bucket, filename):
    user = session["user"]
    file_record = mongo.db.files.find_one({"fileId": filename})
    
    if not file_record:
        return jsonify({"error": "File not found"}), 404
        
    if user != "admin" and file_record["userId"] != user:
        return jsonify({"error": "Access denied"}), 403

    try:
        supabase_storage.delete_file(file_record["storageKey"])
        mongo.db.files.delete_one({"fileId": filename})
        return jsonify({"message": f"'{file_record['originalName']}' deleted successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/preview/<bucket>/<path:filename>")
@login_required
def preview(bucket, filename):
    """Return URL for image preview."""
    # We use the stream endpoint for previews as well, so it gets decrypted
    user = session["user"]
    file_record = mongo.db.files.find_one({"fileId": filename})
    
    if not file_record:
        return jsonify({"error": "File not found"}), 404
        
    if user != "admin" and file_record["userId"] != user:
        return jsonify({"error": "Access denied"}), 403
        
    if not _is_image(file_record["originalName"]):
        return jsonify({"error": "Not an image"}), 400

    stream_url = url_for('stream_file', file_id=filename, _external=True)
    return jsonify({"url": stream_url})


@app.route("/api/folder/create", methods=["POST"])
@login_required
def create_folder():
    """Create a virtual folder (metadata only) or empty object."""
    data = request.get_json()
    folder_name = data.get("folder", "").strip().strip("/")
    user = session["user"]

    if not folder_name:
        return jsonify({"error": "Folder name required"}), 400

    # In our new metadata system, we can just insert a metadata record for the folder
    file_id = str(uuid.uuid4())
    storage_key = f"users/{user}/{file_id}"
    display_name = f"{folder_name}/"
    
    # Upload an empty encrypted file to Supabase just to hold the place, or just metadata
    try:
        supabase_storage.upload_file(storage_key, io.BytesIO(b""), "application/x-directory")
        mongo.db.files.insert_one({
            "fileId": file_id,
            "userId": user,
            "fileName": display_name,
            "originalName": display_name,
            "fileSize": 0,
            "encryptedSize": 0,
            "contentType": "application/x-directory",
            "uploadDate": datetime.utcnow().isoformat(),
            "storageKey": storage_key,
            "encrypted": True,
            "bucket": "cloudstore-default"
        })
        return jsonify({"message": f"Folder '{folder_name}' created", "bucket": "cloudstore-default"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/stats")
@login_required
def stats():
    """Return storage stats from MongoDB."""
    user = session["user"]
    is_admin = (user == "admin")
    
    query = {} if is_admin else {"userId": user}
    files = mongo.db.files.find(query)
    
    total_size = 0
    count = 0
    for f in files:
        total_size += f.get("fileSize", 0)
        count += 1
        
    return jsonify({
        "all": {"count": count, "total_size": total_size}
    })

@app.route("/api/health")
def health():
    status = {"status": "ok", "mongodb": "disconnected", "r2": "disconnected"}
    try:
        mongo.db.command('ping')
        status["mongodb"] = "connected"
    except:
        pass
        
    if supabase_storage.supabase_client:
        status["supabase"] = "connected"
        
    return jsonify(status)


# ─── Startup ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    with app.app_context():
        # Create default admin if not exists
        try:
            if not mongo.db.users.find_one({"username": "admin"}):
                admin_hash = hashlib.sha256("admin123".encode()).hexdigest()
                mongo.db.users.insert_one({"username": "admin", "password_hash": admin_hash})
        except Exception as e:
            print(f"Warning: Could not initialize MongoDB admin user. Error: {e}")
            
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)


