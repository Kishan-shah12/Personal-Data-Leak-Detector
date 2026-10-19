import os
# pyrefly: ignore [missing-import]
from pymongo import MongoClient
# pyrefly: ignore [missing-import]
from pymongo.collection import Collection
# pyrefly: ignore [missing-import]
from pymongo.database import Database

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "data_leak_detector")

client: MongoClient = MongoClient(MONGO_URI, serverSelectionTimeoutMS=2000)
db: Database = client[DB_NAME]
leaks_collection: Collection = db["leaks"]


def check_db_connection() -> bool:
    """Verifies MongoDB connectivity."""
    try:
        client.admin.command("ping")
        return True
    except Exception:
        return False
