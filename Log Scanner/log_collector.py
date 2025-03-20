import os
import json
import time
import win32evtlog
from datetime import datetime
from loguru import logger
from log_processor import process_logs_in_batches

output_directory = r"C:\Users\HET\OneDrive\Desktop\GSFC_U\Minor Project\Test_new\test_logs"
os.makedirs(output_directory, exist_ok=True)
logger.add(f"{output_directory}/event_logs.log", rotation="10 MB", level="DEBUG")

def fetch_event_logs(log_types, poll_interval=5, start_date=None):
    last_record_numbers = {log_type: 0 for log_type in log_types}
    while True:
        all_logs = []
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
                    all_logs.extend(logs)
            except Exception as e:
                logger.error(f"Error fetching logs for '{log_type}': {e}")
        if all_logs:
            blockchain_logs, mongodb_logs = process_logs_in_batches(all_logs)
            save_logs(f"{output_directory}/blockchain_logs.json", blockchain_logs)
            save_logs(f"{output_directory}/mongodb_logs.json", mongodb_logs)
        time.sleep(poll_interval)

def save_logs(output_file, logs):
    if not logs:
        return
    if os.path.exists(output_file):
        with open(output_file, "r+") as json_file:
            try:
                existing_logs = json.load(json_file)
            except json.JSONDecodeError:
                existing_logs = []
            existing_logs.extend(logs)
            json_file.seek(0)
            json.dump(existing_logs, json_file, indent=4)
    else:
        with open(output_file, "w") as json_file:
            json.dump(logs, json_file, indent=4)

start_date = datetime(2025, 1, 1)
fetch_event_logs(log_types=["System", "Application", "Security"], poll_interval=5, start_date=start_date)
