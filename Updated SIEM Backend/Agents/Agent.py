import requests
import win32evtlog
import time
import os
import subprocess
# import socketio # pip install "python-socketio[client]"

SERVER_HOST = "http://localhost:3000/"
REGISTER_URL = f"{SERVER_HOST}/api/auth/register"
LOGIN_URL = f"{SERVER_HOST}/api/auth/login"
API_BASE = f"{SERVER_HOST}/api/windows"
# SOCKET_URL = SERVER_HOST

CHANNELS = {
    "system": "System",
    "security": "Security",
    "application": "Application"
}

last_record_ids = {ch: None for ch in CHANNELS}  # Track last sent ID
agent_id = None
session = None
hardware_info = {}
# socket = socketio.Client()

def get_hardware_info():
    try:
        cpu_id = subprocess.check_output("wmic cpu get ProcessorId", shell=True).decode().split("\n")[1].strip()
        mb_id = subprocess.check_output("wmic baseboard get SerialNumber", shell=True).decode().split("\n")[1].strip()
        disk_id = subprocess.check_output("wmic diskdrive get SerialNumber", shell=True).decode().split("\n")[1].strip()
        return {
            "cpuId": cpu_id,
            "motherboardId": mb_id,
            "diskId": disk_id
        }
    except Exception as e:
        print(f"⚠ Could not retrieve hardware info: {e}")
        return {}

def save_agent_id(agent_id_val):
    with open("agent_id.txt", "w") as f:
        f.write(agent_id_val)

def load_agent_id():
    if os.path.exists("agent_id.txt"):
        with open("agent_id.txt", "r") as f:
            return f.read().strip()
    return None

def register_agent():
    global agent_id
    
    print("📡 Sending registration request...")
    try:
        res = requests.post(REGISTER_URL, json=hardware_info, timeout=10)
        if res.status_code == 200:
            if res.json().get("agentId"):
                agent_id = res.json().get("agentId")
                save_agent_id(agent_id)
            print(res.json().get("message"))
        else:
            print(f"❌ Registration failed: {res.status_code} {res.text}")
    except Exception as e:
        print(f"⚠ Registration error: {e}")

def login_agent():
    global session
    print("🔐 Attempting login...")
    try:
        payload = {
            "agentId": agent_id,
            **hardware_info
        }
        res = requests.post(LOGIN_URL, json=payload, timeout=10)
        if res.status_code == 200:
            session = res.json().get("session")
            print(f"✅ Login successful. Session received.")
            return True
        else:
            print(f"❌ Login failed: {res.status_code} {res.text}")
            return False
    except Exception as e:
        print(f"⚠ Login error: {e}")
        return False

# def on_approved(data):
#     global agent_id, session
#     agent_id = data.get("agentId")
#     session = data.get("session")
#     print(f"✅ Agent approved via socket! ID: {agent_id}")
#     save_agent_id(agent_id)

# def connect_socket():
#     @socket.event
#     def connect():
#         print("🔌 Socket connected to server.")

#     @socket.event
#     def disconnect():
#         print("🔌 Socket disconnected.")

#     @socket.on("approved")
#     def handle_approved(data):
#         on_approved(data)

#     try:
#         socket.connect(SOCKET_URL)
#     except Exception as e:
#         print(f"⚠ Could not connect to socket: {e}")

# AGENT_ID = get_agent_id()


def fetch_logs(channel_name, channel_display, count=11):
    """Fetch latest events from a Windows Event Log channel."""
    logs = []
    hand = win32evtlog.OpenEventLog(None, channel_display)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    events = win32evtlog.ReadEventLog(hand, flags, 0)

    if events:
        sent_count = 0
        for event in events:
            if last_record_ids[channel_name] and event.RecordNumber <= last_record_ids[channel_name]:
                break

            log_entry = {
                "EventID": event.EventID & 0xFFFF,
                "Level": event.EventType,
                "TimeCreated": event.TimeGenerated.Format(),
                "Source": event.SourceName,
                "Task": event.EventCategory,
                "Computer": event.ComputerName,
                "Description": event.StringInserts[0] if event.StringInserts else ""
            }
            logs.append(log_entry)
            sent_count += 1

            if sent_count >= count:
                break

        if logs:
            last_record_ids[channel_name] = events[0].RecordNumber
    win32evtlog.CloseEventLog(hand)
    return logs


def send_logs(channel_name, logs):
    if not logs:
        return
    
    logs = list(reversed(logs))
    data = {
        "logs": logs
    }

    headers = {
        "x-agent-id": agent_id,
        "x-session": session
    }

    # print('data:\n',data, '\nheaders:\n',headers)

    url = f"{API_BASE}/{channel_name}"
    try:
        res = requests.post(url, json=data, headers=headers, timeout=10)
        if res.status_code != 200:
            print(f"❌ Failed to send logs to {channel_name}: {res.status_code} {res.text}")
        else:
            print(f"✅ Sent {len(logs)} logs to {channel_name}")
    except Exception as e:
        print(f"⚠ Error sending logs: {e}")


def run_agent():
    print("🚀 Windows Log Agent started. Waiting for session...")
    while not session:
        print("⏳ Awaiting approval or login session...")
        time.sleep(5)

    while True:
        for channel_name, channel_display in CHANNELS.items():
            logs = fetch_logs(channel_name, channel_display)
            send_logs(channel_name, logs)
            # print("Logs:\n", logs)
        time.sleep(10)


if __name__ == "__main__":
    hardware_info = get_hardware_info()
    if not hardware_info:
        print("❌ Could not collect hardware info. Exiting.")
        exit(1)
    
    agent_id = load_agent_id()
    # connect_socket()

    if not agent_id:
        register_agent()

    while True:
        if not login_agent():
            print("\nLogin failed!\nRetrying in 5 seconds....")
            time.sleep(5)
        else:
            break
                
    print(session)
    run_agent()