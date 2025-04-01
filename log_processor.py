import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import json

high_severity_levels = {
    # System logs
    41: "Unexpected shutdown/restart",
    55: "File system corruption",
    1014: "DNS resolution issues",
    1001: "System crash (blue screen)",
    2004: "Low system resources",
    9: "Disk controller error",
    11: "Disk I/O errors",
    37: "CPU power issues",
    50: "Disk warning",
    7034: "Service terminated unexpectedly",
    6008: "Unexpected shutdown",
    7023: "Service terminated with error",
    1008: "Performance counter issues",

    # Application logs
    1000: "Application crash",
    1026: ".NET unhandled exception",
    11724: "Installation issues",
    1002: "Application unresponsive",
    1500: "User profile load error",
    8193: "Shadow copy failed",
    1030: "Group Policy error",
    11707: "Installation critical error",
    5000: "Unhandled app exception",
    3005: "Web app (IIS) error",

    # Security logs
    4625: "Failed login attempt",
    4688: "Suspicious process execution",
    4720: "Unauthorized user creation",
    4726: "User deletion",
    4740: "Account lockout",
    4768: "Authentication issue",
    4624: "Suspicious successful login",
    4634: "Account logoff",
    4648: "Credential misuse",
    4670: "Sensitive permissions change",
    4697: "Potential malicious service",
    4798: "Sensitive group enumeration",
    5140: "Unauthorized file share access",
    1102: "Audit log cleared",
    4776: "Failed NTLM authentication",
}

critical_levels = [1,2,3]

def detect_threats(log_entry, high_severity_levels):
    threats = []
    event_id = log_entry.get("EventID")

    if event_id in high_severity_levels:
        threats.append(high_severity_levels[event_id])
        
    return threats if threats else False

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
            log_entry["threats"] = detect_threats(log_entry, high_severity_levels)
            event_counts[log_entry["EventID"]] = event_counts.get(log_entry["EventID"], 0) + 1

            if log_entry["Level"] in critical_levels or log_entry["threats"]:
                blockchain_logs.append(log_entry)
            else:
                mongodb_logs.append(log_entry)
        anomalies = detect_anomalies(event_counts)
        ml_anomalies = ml_anomaly_detection(batch)

        for log in mongodb_logs[:]:
            if log["EventID"] in anomalies or log["EventID"] in ml_anomalies:
                log["anomaly"] = anomalies.get(log["EventID"], ml_anomalies.get(log["EventID"]))
                
                if log["Level"] in critical_levels or log["threats"]:
                    mongodb_logs.remove(log)
                    blockchain_logs.append(log)
    return blockchain_logs, mongodb_logs
