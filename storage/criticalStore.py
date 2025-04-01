from config.mongo_confing import collections
import hashlib
import json

def store_critical_logs(logs, type):
    if not isinstance(logs, list) or not all(isinstance(log, dict) for log in logs):
        raise ValueError("Logs must be a list of dictionaries")

    hashes = [{"hash": log["hash"]} for log in logs if "hash" in log]
    
    if not hashes:
        raise ValueError("At least one log must contain a 'hash' key")

    # Insert hashes first
    collections[f"{type}_blockchain_hashes"].insert_many(hashes)
        
    # Remove `_id` from logs before inserting
    for log in logs:
        log.pop("_id", None)
        
    # Insert logs with reference to hashes
    collections[f"{type}_critical_logs"].insert_many(logs)
    
    print(f"{len(logs)} logs stored in 'critical_logs_collection' with hashes.")

def store_block_hash(hash, type):
    if not isinstance(hash, str):
        raise ValueError("Hash must be a string")

    collections[f"{type}_blockchain_hashes"].insert_one({"hash": hash})

def store_critical_log(log, type):
    if not isinstance(log, dict):
        raise ValueError("Log must be a dictionary")

    if "hash" not in log:
        raise ValueError("Log must contain a 'hash' key")

    log.pop("_id", None)
    # print(log)
    collections[f"{type}_critical_logs"].insert_one(log)

def delete_critical_log(log, type):
    if not isinstance(log, dict):
        raise ValueError("Log must be a dictionary")

    if "hash" not in log:
        raise ValueError("Log must contain a 'hash' key")

    hash_value = log["hash"]

    # Step 1: Delete the log first
    log_deleted = collections[f"{type}_critical_logs"].delete_one({"hash": hash_value})

    if log_deleted.deleted_count == 1:
        # Step 2: Now delete the hash since no log references it
        hash_deleted = collections[f"{type}_blockchain_hashes"].delete_one({"hash": hash_value})

        if hash_deleted.deleted_count == 1:
            print(f"Log with hash {hash_value} and its reference deleted successfully.")
        else:
            print(f"Log deleted, but hash {hash_value} was not found in hashes_collection.")
    else:
        print(f"Log with hash {hash_value} not found, deletion failed.")

def fetch_verified_logs(type):
    logs = list(collections[f"{type}_critical_logs"].find())
    verified_logs = []

    for log in logs:
        if "hash" not in log:
            log["verified"] = False
            log["modified"] = True  # If no hash, treat as modified
            verified_logs.append(log)
            continue  

        log_hash = log["hash"]
        
        # Recalculate hash from log data (excluding hash field itself)
        recalculated_hash = hashlib.sha256(json.dumps(
            {k: v for k, v in log.items() if k != "hash"}, sort_keys=True).encode()).hexdigest()

        # Fetch stored hash from hashes_collection
        stored_hash_entry = collections[f"{type}_blockchain_hashes"].find_one({"hash": log_hash})

        # Check integrity
        log["verified"] = stored_hash_entry and stored_hash_entry["hash"] == recalculated_hash
        log["modified"] = not log["verified"]  # If verification fails, mark as modified

        verified_logs.append(log)

    return verified_logs
