import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest

high_severity_levels = {9, 11, 37, 41, 50, 55, 6008, 7023, 7034, 1008, 41, 55, 1000, 1002, 1026, 1030, 11707, 11724, 1500, 5000, 8193, 1001, 1014, 2004,1000, 1026, 11724, 4624, 4625, 4634, 4648, 4670, 4697, 4740, 4776, 4798, 5140, 1102, 4688, 4720, 4726, 4740, 4768, 20, 6005, 1116}

def detect_threats(log_entry):
    threats = []
    if "failed login" in log_entry["Message"].lower():
        threats.append("Brute-force attack detected")
    if "access denied" in log_entry["Message"].lower():
        threats.append("Unauthorized access attempt")
    if "malware" in log_entry["Message"].lower():
        threats.append("Possible malware infection")
    return threats if threats else None

def detect_anomalies(event_counts):
    event_frequencies = np.array(list(event_counts.values()))
    if len(event_frequencies) == 0:
        return {}
    threshold = np.mean(event_frequencies) + 2 * np.std(event_frequencies)
    return {event_id: "High event occurrence anomaly" for event_id, count in event_counts.items() if count > threshold}

def ml_anomaly_detection(log_data):
    if not log_data:
        return {}
    model = IsolationForest(contamination=0.01)
    log_features = pd.get_dummies(pd.DataFrame(log_data))
    model.fit(log_features)
    predictions = model.predict(log_features)
    return {str(log_data[i]["EventID"]): "ML-detected anomaly" for i, pred in enumerate(predictions) if pred == -1}

def process_logs_in_batches(logs, batch_size=5):
    blockchain_logs, mongodb_logs, event_counts = [], [], {}
    for i in range(0, len(logs), batch_size):
        batch = logs[i:i + batch_size]
        for log_entry in batch:
            log_entry["threats"] = detect_threats(log_entry)
            event_counts[log_entry["EventID"]] = event_counts.get(log_entry["EventID"], 0) + 1
            if log_entry["Level"] in high_severity_levels or log_entry["threats"]:
                blockchain_logs.append(log_entry)
            else:
                mongodb_logs.append(log_entry)
        anomalies = detect_anomalies(event_counts)
        ml_anomalies = ml_anomaly_detection(batch)
        for log in mongodb_logs[:]:
            if log["EventID"] in anomalies or log["EventID"] in ml_anomalies:
                log["anomaly"] = anomalies.get(log["EventID"], ml_anomalies.get(log["EventID"]))
                blockchain_logs.append(log)
                mongodb_logs.remove(log)
    return blockchain_logs, mongodb_logs