# ☁ CloudStore — MinIO Storage Clone
A pro-grade, full-stack cloud storage web app built with Python Flask + MinIO (local S3 alternative).

---

## 🚀 Quick Start

### Step 1 — Install Docker Desktop
Download from: https://www.docker.com/products/docker-desktop
- Windows/Mac: run the installer
- Verify: `docker --version`

### Step 2 — Start MinIO
In the project folder, run:
```bash
docker-compose up -d
```
- **Web Console:** http://localhost:9001 (login: `minioadmin` / `minioadmin`)

### Step 3 — Install Python Dependencies
```bash
pip install -r requirements.txt
```

### Step 4 — Run the App
```bash
python app.py
```
Open **http://localhost:5000** in your browser.

---

## 🔑 Default Credentials
| Username | Password   |
|----------|------------|
| admin    | admin123   |

---

## 🛡️ "Heroic Status" Features
This project has been leveled up with advanced "Enterprise" functionality:

- ✅ **AES-256 Symmetric Encryption**: All files are encrypted-at-rest. The storage provider (MinIO) only sees garbled data.
- ✅ **2GB Storage Capacity**: Support for large file uploads up to 2.0GB.
- ✅ **Multi-User Isolation**: Secure Signup/Login system. Users cannot see each other's files.
- ✅ **Admin Dashboard**: Global overview for admin users to manage all stored objects.
- ✅ **Dynamic Backgrounds**: Premium UI with animated morphing blobs and glassmorphism.

---

## 📁 Project Structure
```
minio_project/
│
├── app.py              ← Advanced Flask backend + Encryption logic
├── minio_client.py     ← S3 connection factory
├── requirements.txt    ← Dependencies (flask, minio, cryptography)
├── docker-compose.yml  ← Infrastructure (MinIO service)
├── .env                ← App configuration
├── users.json          ← Persistent encrypted user store
└── templates/
    └── index.html      ← Premium SPA (Single Page Application)
```

---

## 🔧 Environment Variables (.env)

| Variable         | Description              |
|------------------|--------------------------|
| MINIO_ENDPOINT   | Local S3 Endpoint (localhost:9000) |
| ENCRYPTION_KEY   | Fernet Symmetric Master Key |
| FLASK_SECRET     | Session signing secret |

---

## 📚 Core API Endpoints

| Method | Endpoint                        | Description             |
|--------|---------------------------------|-------------------------|
| POST   | /api/signup                     | Create a new private account |
| POST   | /api/login                      | Authenticated session start |
| POST   | /api/upload                     | Secure Encrypted Upload |
| GET    | /api/list                       | Filtered Object Listing |
| GET    | /api/download                   | On-the-fly Decryption stream |
| GET    | /api/stats                      | Live Storage Analytics |
