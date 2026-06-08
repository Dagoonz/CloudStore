import os
import io
from supabase import create_client, Client
from cryptography.fernet import Fernet

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
SUPABASE_BUCKET_NAME = os.getenv("SUPABASE_BUCKET_NAME", "cloudstore")
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")

def get_client() -> Client:
    if not SUPABASE_URL or not SUPABASE_KEY:
        return None
    return create_client(SUPABASE_URL, SUPABASE_KEY)

supabase_client = get_client()

def _get_fernet():
    if not ENCRYPTION_KEY:
        # Generate a placeholder if missing for development, but warn loudly
        print("WARNING: ENCRYPTION_KEY missing. Using temporary key. Files will be lost on restart!")
        return Fernet(Fernet.generate_key())
    return Fernet(ENCRYPTION_KEY.encode() if isinstance(ENCRYPTION_KEY, str) else ENCRYPTION_KEY)

# Initialize global fernet locally so it doesn't fail on import if key is missing
_fernet = None
def get_cipher():
    global _fernet
    if _fernet is None:
        _fernet = _get_fernet()
    return _fernet

def encrypt_data(data: bytes) -> bytes:
    return get_cipher().encrypt(data)

def decrypt_data(data: bytes) -> bytes:
    return get_cipher().decrypt(data)

def upload_file(storage_key: str, file_stream, content_type: str) -> int:
    """Uploads file to Supabase with encryption. Returns the encrypted size."""
    if not supabase_client:
        raise Exception("Supabase client not initialized. Check environment variables.")
        
    data = file_stream.read()
    encrypted_data = encrypt_data(data)
    
    supabase_client.storage.from_(SUPABASE_BUCKET_NAME).upload(
        path=storage_key,
        file=encrypted_data,
        file_options={"content-type": content_type}
    )
    return len(encrypted_data)

def download_file(storage_key: str) -> io.BytesIO:
    """Downloads and decrypts file from Supabase. Returns a BytesIO stream."""
    if not supabase_client:
        raise Exception("Supabase client not initialized.")
        
    res = supabase_client.storage.from_(SUPABASE_BUCKET_NAME).download(storage_key)
    # res is bytes returned by download()
    decrypted_data = decrypt_data(res)
    return io.BytesIO(decrypted_data)

def delete_file(storage_key: str):
    """Deletes file from Supabase."""
    if not supabase_client:
        raise Exception("Supabase client not initialized.")
    supabase_client.storage.from_(SUPABASE_BUCKET_NAME).remove([storage_key])
