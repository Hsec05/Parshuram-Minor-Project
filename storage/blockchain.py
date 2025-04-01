import hashlib
import datetime
import json
from storage.criticalStore import store_critical_logs, store_block_hash, store_critical_log 
from config.mongo_confing import collections

class Blockchain:
    def __init__(self, type):
        self.log_type = type.lower()
        self.hash_collection = collections[f"{self.log_type}_blockchain_hashes"]  
        self.previous_hash = self.load_previous_hash()  # Store only the last block's hash in memory

    def load_previous_hash(self):
        """Fetches the last stored block's hash from 'hashes_collection'."""
        last_hash_entry = self.hash_collection.find_one({}, sort=[("_id", -1)])
        return last_hash_entry["hash"] if last_hash_entry else "0"  # If no hash, return '0' (genesis)

    def create_genesis_block(self):
        """Creates and stores the first block (genesis block)."""
        genesis_block = {
            "eventID": "GENESIS",
            "time": str(datetime.datetime.now()),
            "threats": "None",
            "previous_hash": "0",  # Genesis block has no previous hash
        }

        # Compute the hash of the genesis block
        block_hash = self.compute_hash(genesis_block)
        genesis_block["hash"] = block_hash 

        store_critical_logs([genesis_block], self.log_type)
        

        self.previous_hash = block_hash

    def compute_hash(self, block):
        """Computes SHA-256 hash of a block (excluding _id if present)."""
        block_copy = block.copy()
        # block_copy.pop("_id", None)  # Remove MongoDB's _id field if present
        encoded_block = json.dumps(block_copy, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def process_logs(self, logs):
        """
        Processes logs into blockchain blocks.
        Each log becomes a block linked to the previous hash.
        """
        if not isinstance(logs, list) or not all(isinstance(log, dict) for log in logs):
            raise ValueError("Logs must be a list of dictionaries")

        # processed_logs = []

        for log in logs:
            block = {
                "eventID": log["EventID"],
                "time": log["TimeCreated"],
                "threats": log["threats"],
                "previous_hash": self.previous_hash,  
            }

            # Generate block hash
            block_hash = self.compute_hash(block)
            log["hash"] = block_hash 
            log["previous_hash"] = self.previous_hash

            self.previous_hash = block_hash
            # processed_logs.append(block)
            store_block_hash(block_hash, self.log_type.lower())
            store_critical_log(log, self.log_type.lower())

        # store_critical_logs(processed_logs)
        return True  

# Initialize Blockchain (create genesis block if needed)
system_blockchain = Blockchain("system")
application_blockchain = Blockchain("application")
security_blockchain = Blockchain("security")

# **Ensure Genesis Block exists**
if system_blockchain.previous_hash == "0":
    system_blockchain.create_genesis_block()

if application_blockchain.previous_hash == "0":
    application_blockchain.create_genesis_block()

if security_blockchain.previous_hash == "0":
    security_blockchain.create_genesis_block()

def store_critical_logs_bulk(logs, log_type):
    """
    Calls the appropriate blockchain instance to process logs.
    """
    log_type = log_type.lower()
    if log_type == "system":
        return system_blockchain.process_logs(logs)
    elif log_type == "application":
        return application_blockchain.process_logs(logs)
    elif log_type == "security":
        return security_blockchain.process_logs(logs)
    else:
        raise ValueError("Invalid log type. Choose from 'system', 'application', or 'security'.")
