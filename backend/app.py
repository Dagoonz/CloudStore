from flask import Flask, request, jsonify, send_file, session, redirect, url_for
from datetime import datetime
import io
import os
from flask_cors import CORS
import hashlib
import json
import socket
from functools import wraps
from flask_pymongo import PyMongo

app = Flask(__name__)
CORS(app, supports_credentials=True) # Allow frontend to make cross-origin requests
app.secret_key = os.getenv("FLASK_SECRET", "supersecretkey123")

# ─── Extensions Configuration ────────────────────────────────────────────────
app.config['MONGO_URI'] = os.getenv('MONGO_URI', 'mongodb://localhost:27017/cloudstore').strip('"').strip("'")

mongo = PyMongo(app)
if mongo.db is None:
    mongo.db = mongo.cx["cloudstore"]

# User Store is now managed by MongoDB.

MAX_FILE_SIZE_MB = 2048
app.config['MAX_CONTENT_LENGTH'] = 2048 * 1024 * 1024

from services import supabase_storage
import uuid

# ─── Helpers ─────────────────────────────────────────────────────────────────

@app.errorhandler(Exception)
def handle_exception(e):
    import traceback
    return jsonify({"error": str(e), "traceback": traceback.format_exc()}), 500

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

@app.before_request
def initialize_admin():
    if not getattr(app, '_admin_initialized', False):
        try:
            # We store username as 'admin' because login uses .lower()
            if not mongo.db.users.find_one({"username": "admin"}):
                admin_hash = hashlib.sha256("@Admin123".encode()).hexdigest()
                mongo.db.users.insert_one({
                    "username": "admin", 
                    "password_hash": admin_hash, 
                    "email": "admin@cloudstore.com",
                    "role": "admin"
                })
            app._admin_initialized = True
        except Exception as e:
            pass

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
    
    if not username or not password or not email:
        return jsonify({"error": "Username, email, and password required"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    
    existing_user = mongo.db.users.find_one({"username": username})
    if existing_user:
        return jsonify({"error": "Username already taken"}), 400
        
    existing_email = mongo.db.users.find_one({"email": email})
    if existing_email:
        return jsonify({"error": "Email already in use"}), 400

    hashed = hashlib.sha256(password.encode()).hexdigest()

    mongo.db.users.insert_one({
        "username": username,
        "password_hash": hashed,
        "email": email
    })

    return jsonify({"message": "Account created successfully", "user": username})

@app.route("/api/logout", methods=["POST"])
def logout():
    session.pop("user", None)
    return jsonify({"message": "Logged out"})

@app.route("/api/me")
def me():
    if "user" in session:
        return jsonify({"user": session["user"]})
    return jsonify({"user": None})

# ─── Admin Routes ────────────────────────────────────────────────────────────

@app.route("/api/admin/users")
@login_required
def admin_users():
    user = session["user"]
    if user != "admin":
        return jsonify({"error": "Forbidden"}), 403
        
    users = list(mongo.db.users.find({}, {"_id": 0, "password_hash": 0}))
    
    # Aggregate file counts and sizes per user
    pipeline = [
        {"$group": {
            "_id": "$userId", 
            "fileCount": {"$sum": 1},
            "totalSize": {"$sum": "$fileSize"}
        }}
    ]
    file_stats = list(mongo.db.files.aggregate(pipeline))
    stats_map = {stat["_id"]: stat for stat in file_stats}
    
    for u in users:
        stat = stats_map.get(u["username"], {"fileCount": 0, "totalSize": 0})
        u["fileCount"] = stat["fileCount"]
        u["totalSize"] = stat["totalSize"]
        
    return jsonify(users)

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
    
    query = {"userId": user}
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
    stream_url = url_for('stream_file', file_id=filename)
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

    stream_url = url_for('stream_file', file_id=filename)
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
    
    query = {"userId": user}
    files = mongo.db.files.find(query)
    
    total_size = 0
    count = 0
    for f in files:
        total_size += f.get("fileSize", 0)
        count += 1
        
    return jsonify({
        "all": {"count": count, "total_size": total_size}
    })

# ─── Settings Routes ─────────────────────────────────────────────────────────

@app.route("/api/settings/password", methods=["POST"])
@login_required
def change_password():
    data = request.get_json()
    old_password = data.get("old_password", "")
    new_password = data.get("new_password", "")
    user = session["user"]
    
    if len(new_password) < 6:
        return jsonify({"error": "New password must be at least 6 characters"}), 400
        
    db_user = mongo.db.users.find_one({"username": user})
    if not db_user:
        return jsonify({"error": "User not found"}), 404
        
    old_hashed = hashlib.sha256(old_password.encode()).hexdigest()
    if db_user.get("password_hash") != old_hashed:
        return jsonify({"error": "Incorrect current password"}), 400
        
    new_hashed = hashlib.sha256(new_password.encode()).hexdigest()
    mongo.db.users.update_one({"username": user}, {"$set": {"password_hash": new_hashed}})
    return jsonify({"message": "Password changed successfully"})

@app.route("/api/settings/username", methods=["POST"])
@login_required
def change_username():
    data = request.get_json()
    new_username = data.get("new_username", "").strip().lower()
    old_username = session["user"]
    
    if not new_username:
        return jsonify({"error": "Username is required"}), 400
    if new_username == old_username:
        return jsonify({"error": "New username must be different"}), 400
        
    if mongo.db.users.find_one({"username": new_username}):
        return jsonify({"error": "Username already taken"}), 400
        
    # Update users
    mongo.db.users.update_one({"username": old_username}, {"$set": {"username": new_username}})
    
    # Update files ownership (Supabase storage paths remain the same to avoid expensive moves)
    mongo.db.files.update_many({"userId": old_username}, {"$set": {"userId": new_username}})
    
    session["user"] = new_username
    return jsonify({"message": "Username changed successfully", "user": new_username})

@app.route("/api/settings/account", methods=["DELETE"])
@login_required
def delete_account():
    user = session["user"]
    
    # Optional: Delete all files from Supabase
    user_files = list(mongo.db.files.find({"userId": user}))
    for f in user_files:
        try:
            supabase_storage.delete_file(f["storageKey"])
        except Exception:
            pass # Ignore deletion errors to ensure the account gets deleted
            
    mongo.db.files.delete_many({"userId": user})
    mongo.db.users.delete_one({"username": user})
    
    session.pop("user", None)
    return jsonify({"message": "Account deleted successfully"})

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
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)


