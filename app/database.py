import os
import time
from typing import Optional
# pyrefly: ignore [missing-import]
from pymongo import MongoClient
# pyrefly: ignore [missing-import]
from pymongo.collection import Collection
# pyrefly: ignore [missing-import]
from pymongo.database import Database

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "data_leak_detector")

client: MongoClient = MongoClient(MONGO_URI, serverSelectionTimeoutMS=800)
db: Database = client[DB_NAME]
leaks_collection: Collection = db["leaks"]

_db_status_cache: Optional[bool] = None
_db_status_last_checked: float = 0.0


def check_db_connection() -> bool:
    """Verifies MongoDB connectivity with a 30s cache to avoid blocking requests when offline."""
    global _db_status_cache, _db_status_last_checked
    now = time.time()
    if _db_status_cache is not None and (now - _db_status_last_checked) < 30.0:
        return _db_status_cache
    try:
        client.admin.command("ping")
        _db_status_cache = True
    except Exception:
        _db_status_cache = False
    _db_status_last_checked = now
    return _db_status_cache
