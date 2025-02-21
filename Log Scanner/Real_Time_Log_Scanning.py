import win32evtlog
import json
import time

def capture_logs_to_json_continuously(server="localhost", log_type="System", poll_interval=10, output_file="event_logs.json"):
    """
    Continuously captures Windows Event Viewer logs and appends them to a JSON file.

    :param server: Server name (use "localhost" for local machine).
    :param log_type: Log type (e.g., "System", "Application", "Security").
    :param poll_interval: Time interval (in seconds) to check for new logs.
    :param output_file: Path to the output JSON file.
    """
    logs = []
    last_record_number = 0  # To track the last read log record

    try:
        # Open the log
        log_handle = win32evtlog.OpenEventLog(server, log_type)
        print(f"Monitoring '{log_type}' logs on {server}...\n")

        while True:
            # Read the total number of records in the log
            total_records = win32evtlog.GetNumberOfEventLogRecords(log_handle)
            
            # Read new logs if there are any
            if total_records > last_record_number:
                print(f"New logs detected! Capturing logs from record {last_record_number + 1} to {total_records}...\n")
                
                # Read records sequentially
                flags = win32evtlog.EVENTLOG_SEQUENTIAL_READ | win32evtlog.EVENTLOG_FORWARDS_READ
                events = win32evtlog.ReadEventLog(log_handle, flags, last_record_number)

                for event in events:
                    log_entry = {
                        "EventID": event.EventID,
                        "Source": event.SourceName,
                        "TimeGenerated": str(event.TimeGenerated),
                        "EventType": event.EventType,
                        "Category": event.EventCategory,
                        "Description": event.StringInserts,
                    }
                    logs.append(log_entry)

                # Update the last record number
                last_record_number = total_records

                # Append logs to the JSON file
                with open(output_file, 'r+') as json_file:
                    try:
                        existing_logs = json.load(json_file)  # Load existing logs
                    except json.JSONDecodeError:
                        existing_logs = []  # If file is empty, start fresh

                    existing_logs.extend(logs)
                    json_file.seek(0)  # Move to the start of the file
                    json.dump(existing_logs, json_file, indent=4)
                    logs.clear()  # Clear logs buffer

                print(f"Logs successfully appended to {output_file}")

            else:
                print("No new logs detected. Waiting for the next poll...\n")

            time.sleep(poll_interval)

    except Exception as e:
        print(f"Error capturing logs: {e}")

    finally:
        win32evtlog.CloseEventLog(log_handle)

# Example usage
capture_logs_to_json_continuously(log_type="System", poll_interval=10)
