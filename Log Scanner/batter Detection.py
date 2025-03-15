import json
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest

# Define severity levels
high_severity_levels = {"Error", "Critical"}  # Logs with these levels go to blockchain

# Load logs from JSON file
def load_logs(json_file):
    with open(json_file, "r") as file:
        logs = json.load(file)
    return logs

# Rule-based threat detection
def detect_threats(log_entry):
    threats = []
    
    if "failed login" in log_entry["Description"].lower():
        threats.append("Brute-force attack detected")
    if "access denied" in log_entry["Description"].lower():
        threats.append("Unauthorized access attempt")
    if "malware" in log_entry["Description"].lower():
        threats.append("Possible malware infection")
    
    return threats if threats else None

# Statistical anomaly detection
def detect_anomalies(event_counts):
    event_frequencies = np.array(list(event_counts.values()))
    if len(event_frequencies) == 0:
        return {}
    
    threshold = np.mean(event_frequencies) + 2 * np.std(event_frequencies)
    anomalies = {
        event_id: "High event occurrence anomaly"
        for event_id, count in event_counts.items() if count > threshold
    }
    return anomalies

# ML-based anomaly detection
def ml_anomaly_detection(log_data):
    model = IsolationForest(contamination=0.01)
    log_features = pd.get_dummies(pd.DataFrame(log_data))
    model.fit(log_features)
    predictions = model.predict(log_features)
    
    anomalies = {}
    for i, pred in enumerate(predictions):
        if pred == -1:
            event_id = str(log_data[i]["Event ID"])
            anomalies[event_id] = "ML-detected anomaly"
    
    return anomalies

# Process logs in batches of 5
def process_logs_in_batches(logs, batch_size=5):
    blockchain_logs = []
    mongodb_logs = []
    event_counts = {}
    
    for i in range(0, len(logs), batch_size):
        batch = logs[i:i + batch_size]  # Get a batch of logs
        batch_df = pd.DataFrame(batch)  # Convert batch to DataFrame
        
        for log_entry in batch:
            log_entry["threats"] = detect_threats(log_entry)
            event_id = log_entry["Event ID"]
            event_counts[event_id] = event_counts.get(event_id, 0) + 1
            
            if log_entry["Level"] in high_severity_levels or log_entry["threats"]:
                blockchain_logs.append(log_entry)
            else:
                mongodb_logs.append(log_entry)
        
        # Detect statistical anomalies
        anomalies = detect_anomalies(event_counts)
        for log in mongodb_logs:
            if log["Event ID"] in anomalies:
                log["anomaly"] = anomalies[log["event_id"]]
        
        # Detect ML anomalies
        ml_anomalies = ml_anomaly_detection(batch)
        for log in mongodb_logs[:]:
            if log["Event ID"] in ml_anomalies:
                log["anomaly"] = ml_anomalies[log["Event ID"]]
                blockchain_logs.append(log)
                mongodb_logs.remove(log)
    
    return blockchain_logs, mongodb_logs

# Load logs and process them
logs = load_logs("logs.json")  # Replace with real-time log collection later
blockchain_logs, mongodb_logs = process_logs_in_batches(logs)

# Save results
with open("blockchain_logs.json", "w") as bc_file:
    json.dump(blockchain_logs, bc_file, indent=4)

with open("mongodb_logs.json", "w") as mongo_file:
    json.dump(mongodb_logs, mongo_file, indent=4)

print("Logs processed in batches and categorized successfully.")
