import os
import boto3
from botocore.config import Config
from cryptography.fernet import Fernet
import io

R2_ACCOUNT_ID = os.getenv("R2_ACCOUNT_ID")
R2_ACCESS_KEY_ID = os.getenv("R2_ACCESS_KEY_ID")
R2_SECRET_ACCESS_KEY = os.getenv("R2_SECRET_ACCESS_KEY")
R2_BUCKET_NAME = os.getenv("R2_BUCKET_NAME", "cloudstore")
R2_ENDPOINT = os.getenv("R2_ENDPOINT", f"https://{R2_ACCOUNT_ID}.r2.cloudflarestorage.com" if R2_ACCOUNT_ID else None)
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")

def get_client():
    if not R2_ENDPOINT or not R2_ACCESS_KEY_ID or not R2_SECRET_ACCESS_KEY:
        return None
    return boto3.client(
        's3',
        endpoint_url=R2_ENDPOINT,
        aws_access_key_id=R2_ACCESS_KEY_ID,
        aws_secret_access_key=R2_SECRET_ACCESS_KEY,
        config=Config(signature_version='s3v4')
    )

s3_client = get_client()

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
    """Uploads file to R2 with encryption. Returns the encrypted size."""
    if not s3_client:
        raise Exception("R2 Client not initialized. Check environment variables.")
        
    data = file_stream.read()
    encrypted_data = encrypt_data(data)
    
    s3_client.put_object(
        Bucket=R2_BUCKET_NAME,
        Key=storage_key,
        Body=encrypted_data,
        ContentType=content_type
    )
    return len(encrypted_data)

def download_file(storage_key: str) -> io.BytesIO:
    """Downloads and decrypts file from R2. Returns a BytesIO stream."""
    if not s3_client:
        raise Exception("R2 Client not initialized.")
        
    response = s3_client.get_object(Bucket=R2_BUCKET_NAME, Key=storage_key)
    encrypted_data = response['Body'].read()
    decrypted_data = decrypt_data(encrypted_data)
    return io.BytesIO(decrypted_data)

def delete_file(storage_key: str):
    """Deletes file from R2."""
    if not s3_client:
        raise Exception("R2 Client not initialized.")
    s3_client.delete_object(Bucket=R2_BUCKET_NAME, Key=storage_key)

def get_file_metadata(storage_key: str):
    """Gets raw metadata from R2 object."""
    if not s3_client:
        raise Exception("R2 Client not initialized.")
    return s3_client.head_object(Bucket=R2_BUCKET_NAME, Key=storage_key)
