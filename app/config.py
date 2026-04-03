import os
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

_BACKEND_ROOT = Path(__file__).resolve().parent.parent


@lru_cache
def get_settings():
    default_sqlite = _BACKEND_ROOT / "tamilnadu_products.db"
    sqlite_path = os.getenv("SQLITE_PATH", str(default_sqlite))
    sqlite_url = os.getenv("DATABASE_URL", "").strip()
    if sqlite_url and not (sqlite_url.startswith("sqlite+") or sqlite_url.startswith("sqlite:///")):
        sqlite_url = ""
    return {
        "sqlite_path": sqlite_path,
        "sqlite_url": sqlite_url,
        "jwt_secret": os.getenv("JWT_SECRET", "your-secret-key"),
        "frontend_url": os.getenv("FRONTEND_URL", "http://localhost:5173"),
        "port": int(os.getenv("PORT", "5000")),
        "env": os.getenv("NODE_ENV", os.getenv("ENV", "development")),
        "razorpay_key_id": os.getenv("RAZORPAY_KEY_ID"),
        "razorpay_key_secret": os.getenv("RAZORPAY_KEY_SECRET"),
        "max_file_size": int(os.getenv("MAX_FILE_SIZE", str(5 * 1024 * 1024))),
        "upload_dir": os.getenv("UPLOAD_PATH", "uploads"),
    }
