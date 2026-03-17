import json
import os

LOG_DIR="traffic_logs"

def save_log(data, filename):
    filepath = os.path.join(LOG_DIR, filename)
    logs = []

    if os.path.exists(filepath):
        try:
            with open(filepath, "r") as f:
                logs = json.load(f)
        except:
            logs = []

    logs.append(data)
    with open(filepath, "w") as f:
        json.dump(logs, f, indent=4)