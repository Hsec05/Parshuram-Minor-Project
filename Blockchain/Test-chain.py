from blockchain import Blockchain
import time

# Initialize blockchain instance
blockchain = Blockchain()

# Sample logs
log1 = {
    "level": "Info",
    "timestamp": "19-02-2025 15:41:58",
    "source": "System",
    "message": "System startup completed successfully.",
    "type": "System"
}

log2 = {
    "level": "Warning",
    "timestamp": "19-02-2025 16:00:00",
    "source": "Security",
    "message": "Multiple failed login attempts detected!",
    "type": "Security"
}

log3 = {
    "level": "Critical",
    "timestamp": "19-02-2025 16:30:00",
    "source": "Firewall",
    "message": "Unauthorized access attempt detected.",
    "type": "Security"
}

print("\n🚀 **TEST: Adding Logs**")
log_entry_1 = blockchain.add_log(log1, is_critical=False, permanent=False, delete_after_days=2)
log_entry_2 = blockchain.add_log(log2, is_critical=True, permanent=False, delete_after_days=3)
log_entry_3 = blockchain.add_log(log3, is_critical=True, permanent=True)  # Permanent

print(f"✅ Log 1 added (MongoDB only) - ID: {log_entry_1['_id']}")
print(f"🚨 Log 2 added (Blockchain) - ID: {log_entry_2['_id']}")
print(f"🔒 Log 3 added (Blockchain, Permanent) - ID: {log_entry_3['_id']}")

# Retrieve Critical Logs
print("\n🔍 **TEST: Retrieving Critical Logs**")
critical_log_2 = blockchain.get_critical_log(log_entry_2["_id"])
critical_log_3 = blockchain.get_critical_log(log_entry_3["_id"])

print(f"🚨 Retrieved Critical Log 2: {critical_log_2}")
print(f"🔒 Retrieved Critical Log 3 (Permanent): {critical_log_3}")

# Simulate Auto-Deletion of Logs (Simulating 3 days passed)
print("\n🗑️ **TEST: Auto-Deleting Expired Logs (Simulating Time Pass)**")
time.sleep(2)  # Replace with actual wait in production (time.sleep(86400 * days) for real testing)
blockchain.delete_expired_logs()

# Try fetching deleted logs
deleted_log_2 = blockchain.get_critical_log(log_entry_2["_id"])
print(f"❌ Log 2 after deletion attempt: {deleted_log_2}")  # Should be None

# Manually delete a log
print("\n🗑️ **TEST: Manual Deletion**")
blockchain.delete_log_now(log_entry_1["_id"])
deleted_log_1 = blockchain.get_critical_log(log_entry_1["_id"])
print(f"❌ Log 1 after manual deletion attempt: {deleted_log_1}")  # Should be None

# Display final blockchain state
print("\n🔗 **TEST: Final Blockchain State**")
for block in blockchain.chain:
    print(f"Block {block['index']} → Logs: {block['logs']}")

print("\n✅ **TEST COMPLETED SUCCESSFULLY** 🎉")
