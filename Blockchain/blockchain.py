import hashlib
import datetime
import json
import time
import threading
from pymongo import MongoClient

class Blockchain:
    def __init__(self):
        # Connect to MongoDB
        self.client = MongoClient("mongodb://localhost:27017/")
        self.db = self.client["SIEM_Tool"]
        self.logs_collection = self.db["logs"]
        self.critical_logs_index = self.db["critical_logs_index"]

        self.chain = []
        self.create_block(proof=1, previous_hash='0')

        # Start auto-cleanup thread
        self.start_cleanup_thread()

    def create_block(self, proof, previous_hash):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': str(datetime.datetime.now()),
            'proof': proof,
            'previous_hash': previous_hash,
            'logs': []
        }
        self.chain.append(block)
        return block

    def get_previous_block(self):
        return self.chain[-1]

    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False
        while not check_proof:
            hash_operation = hashlib.sha256(
                str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] == '0000':
                check_proof = True
            else:
                new_proof += 1
        return new_proof

    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def add_log(self, log, is_critical=False, permanent=False, delete_after_days=5):
        expiry_time = None if permanent else datetime.datetime.now() + datetime.timedelta(days=delete_after_days)

        log_entry = {
            "timestamp": log["timestamp"],
            "level": log["level"],
            "source": log["source"],
            "message": log["message"],
            "type": log.get("type", "unknown"),
            "is_critical": is_critical,
            "permanent": permanent,
            "expiry_time": expiry_time
        }
        log_id = self.logs_collection.insert_one(log_entry).inserted_id

        if is_critical:
            log_hash = hashlib.sha256(json.dumps(log, sort_keys=True).encode()).hexdigest()
            previous_block = self.get_previous_block()
            proof = self.proof_of_work(previous_block['proof'])
            previous_hash = self.hash(previous_block)
            block = self.create_block(proof, previous_hash)
            block['logs'].append({"log_id": str(log_id), **log})

            self.critical_logs_index.insert_one({
                "log_id": str(log_id),
                "block_index": block["index"],
                "log_hash": log_hash,
                "expiry_time": expiry_time
            })

        return log_entry

    def get_critical_log(self, log_id):
        indexed_log = self.critical_logs_index.find_one({"log_id": log_id})
        if not indexed_log:
            return None

        block_index = indexed_log["block_index"]
        log_hash = indexed_log["log_hash"]

        for block in self.chain:
            if block["index"] == block_index:
                for log in block["logs"]:
                    if hashlib.sha256(json.dumps(log, sort_keys=True).encode()).hexdigest() == log_hash:
                        return log
        return None

    def delete_expired_logs(self):
        now = datetime.datetime.now()

        expired_logs = self.logs_collection.find({"expiry_time": {"$lte": now}, "permanent": False})
        for log in expired_logs:
            log_id = str(log["_id"])
            self.logs_collection.delete_one({"_id": log["_id"]})
            indexed_log = self.critical_logs_index.find_one({"log_id": log_id})

            if indexed_log:
                block_index = indexed_log["block_index"]
                self.critical_logs_index.delete_one({"log_id": log_id})

                for block in self.chain:
                    if block["index"] == block_index:
                        block["logs"] = [l for l in block["logs"] if l["log_id"] != log_id]
                        
                        # If block is empty, remove it
                        if not block["logs"]:
                            self.chain.remove(block)
                        break

    def delete_log_now(self, log_id):
        self.logs_collection.delete_one({"_id": log_id})
        indexed_log = self.critical_logs_index.find_one({"log_id": str(log_id)})

        if indexed_log:
            block_index = indexed_log["block_index"]
            self.critical_logs_index.delete_one({"log_id": str(log_id)})

            for block in self.chain:
                if block["index"] == block_index:
                    block["logs"] = [l for l in block["logs"] if l["log_id"] != str(log_id)]
                    
                    # If block becomes empty, remove it
                    if not block["logs"]:
                        self.chain.remove(block)
                    break

    def start_cleanup_thread(self):
        def cleanup():
            while True:
                self.delete_expired_logs()
                time.sleep(3600)  # Check every hour

        thread = threading.Thread(target=cleanup, daemon=True)
        thread.start()
