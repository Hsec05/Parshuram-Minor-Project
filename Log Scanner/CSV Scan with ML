import pandas as pd
import json
import numpy as np
from sklearn.ensemble import IsolationForest

# Load CSV file
file_path = "Administrative-Events.csv"
df = pd.read_csv(file_path)

# Define severity levels
high_severity_levels = {"Error", "Critical"}  # These logs go to blockchain

# Rule-based threat detection
def detect_threats(log_entry):
    threats = []

    if "failed login" in log_entry["message"].lower():
        threats.append("Brute-force attack detected")

    if "access denied" in log_entry["message"].lower():
        threats.append("Unauthorized access attempt")

    if "malware" in log_entry["message"].lower():
        threats.append("Possible malware infection")

    return threats if threats else None

# Statistical anomaly detection (event frequency spikes)
def detect_anomalies(event_counts):
    event_frequencies = np.array(list(event_counts.values()))  # Convert dict values to array
    if len(event_frequencies) == 0:
        return {}  # No anomalies if there's no event data

    threshold = np.mean(event_frequencies) + 2 * np.std(event_frequencies)  # 2-sigma rule
    anomalies = {
        event_id: "High event occurrence anomaly"
        for event_id, count in event_counts.items() if count > threshold
    }
    return anomalies


# Machine Learning-based anomaly detection with specific labels

def ml_anomaly_detection(log_data):
    model = IsolationForest(contamination=0.01)  # Assume 1% anomalies
    log_features = pd.get_dummies(log_data)  # Convert categorical to numeric
    model.fit(log_features)
    predictions = model.predict(log_features)

    anomalies = {}
    for i, pred in enumerate(predictions):
        if pred == -1:  # If an anomaly is detected
            event_id = str(log_data.iloc[i]["Event ID"])  # Get Event ID as string
            anomalies[event_id] = "ML-detected anomaly"

    return anomalies  # Return event_id-based dictionary

# Log categorization and threat detection
def categorize_logs(df):
    blockchain_logs = []
    mongodb_logs = []
    event_counts = {}

    for _, row in df.iterrows():
        log_entry = {
            "level": str(row.get("Level", "Unknown")),
            "timestamp": str(row.get("Date and Time", "Unknown")),
            "source": str(row.get("Source", "Unknown")),
            "event_id": str(row.get("Event ID", "Unknown")),
            "task_category": str(row.get("Task Category", "Unknown")),
            "message": str(row.get("message", "unknown"))
        }

        # Detect threats
        log_entry["threats"] = detect_threats(log_entry)

        # Track event ID occurrences for statistical anomaly detection
        event_id = log_entry["event_id"]
        event_counts[event_id] = event_counts.get(event_id, 0) + 1

        # Categorize logs based on severity
        if log_entry["level"] in high_severity_levels or log_entry["threats"]:
            blockchain_logs.append(log_entry)
        else:
            mongodb_logs.append(log_entry)

    # Detect statistical anomalies
    anomalies = detect_anomalies(event_counts)
    for log in mongodb_logs:
        if log["event_id"] in anomalies:
            log["anomaly"] = anomalies[log["event_id"]]

    # Detect ML anomalies
    ml_anomalies = ml_anomaly_detection(df)
    for log in mongodb_logs[:]:  # Iterate over a copy to modify safely
        if log["event_id"] in ml_anomalies:
            log["anomaly"] = ml_anomalies[log["event_id"]]
            blockchain_logs.append(log)  # Move to blockchain logs
            mongodb_logs.remove(log)  # Remove from MongoDB logs

    return blockchain_logs, mongodb_logs

# Categorize logs and detect threats
blockchain_logs, mongodb_logs = categorize_logs(df)

# Save categorized logs
with open("blockchain_logs.json", "w") as bc_file:
    json.dump(blockchain_logs, bc_file, indent=4)

with open("mongodb_logs.json", "w") as mongo_file:
    json.dump(mongodb_logs, mongo_file, indent=4)

print("Logs categorized, threats detected, and saved successfully.")
