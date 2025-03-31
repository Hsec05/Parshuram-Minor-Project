import os
import time
import win32evtlog
from datetime import datetime
from loguru import logger
from log_processor import process_logs_in_batches
from storage.blockchain import store_critical_logs_bulk
from storage.otherStore import store_other_logs
from collections import Counter

# Set up directories and logging
output_directory = r"C:\Users\HET\OneDrive\Desktop\GSFC_U\Minor Project\Project - Integrate\Project - Integrate\testing"
os.makedirs(output_directory, exist_ok=True)
logger.add(f"{output_directory}/event_logs.log", rotation="10 MB", level="DEBUG")

def fetch_event_logs(log_types, poll_interval=5, start_date=None):
    last_record_numbers = {log_type: 0 for log_type in log_types}
    while True:
        all_logs = {"System": [], "Application": [], "Security": []}
        for log_type in log_types:
            try:
                log_handle = win32evtlog.OpenEventLog(None, log_type)
                total_records = win32evtlog.GetNumberOfEventLogRecords(log_handle)
                if total_records <= last_record_numbers[log_type]:
                    continue
                flags = win32evtlog.EVENTLOG_SEQUENTIAL_READ | win32evtlog.EVENTLOG_FORWARDS_READ
                events = win32evtlog.ReadEventLog(log_handle, flags, last_record_numbers[log_type])
                logs = []
                for event in events:
                    event_time = event.TimeGenerated.Format()
                    try:
                        event_time_dt = datetime.strptime(event_time, "%a %b %d %H:%M:%S %Y")
                    except ValueError:
                        continue
                    if start_date and event_time_dt < start_date:
                        continue
                    log_entry = {
                        "EventID": event.EventID,
                        "Level": event.EventType,
                        "TimeCreated": event_time,
                        "Source": event.SourceName,
                        "Task": event.EventCategory,
                        "Computer": event.ComputerName,
                        "Message": " ".join(event.StringInserts) if event.StringInserts else "N/A",
                    }
                    logs.append(log_entry)
                win32evtlog.CloseEventLog(log_handle)
                if logs:
                    last_record_numbers[log_type] = total_records
                    all_logs[log_type].extend(logs)
            except Exception as e:
                logger.error(f"Error fetching logs for '{log_type}': {e}")

        if any(all_logs.values()):
            for log_type in all_logs:
                blockchain_logs, mongodb_logs = process_logs_in_batches(all_logs[log_type])
                
                if blockchain_logs:
                    store_critical_logs_bulk(blockchain_logs, log_type.lower())
                if mongodb_logs:
                    store_other_logs(mongodb_logs, log_type.lower())

        time.sleep(poll_interval)


start_date = datetime(2024, 12, 1)
fetch_event_logs(log_types=["System", "Application", "Security"], poll_interval=5, start_date=start_date)
