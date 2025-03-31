import os
from dotenv import load_dotenv
from pymongo import MongoClient

# Load environment variables from .env file
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

# MongoDB Configuration
MONGO_URI = os.getenv("MONGO_URI")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME")

# Connect to MongoDB
client = MongoClient(MONGO_URI)
db = client[MONGO_DB_NAME]
LOG_TYPES = ["System", "Application", "Security"]

collections = {}
for log_type in LOG_TYPES:
    collections[f"{log_type.lower()}_critical_logs"] = db[f"{log_type.lower()}_critical_logs"]
    collections[f"{log_type.lower()}_other_logs"] = db[f"{log_type.lower()}_other_logs"]
    collections[f"{log_type.lower()}_blockchain_hashes"] = db[f"{log_type.lower()}_blockchain_hashes"]

def ensure_collection_exists(collection_name):
    if collection_name not in db.list_collection_names():
        db.create_collection(collection_name)
        print(f"Created collection: {collection_name}")

for collection in collections.values():
    ensure_collection_exists(collection.name)

print("Connected to MongoDB successfully!")
