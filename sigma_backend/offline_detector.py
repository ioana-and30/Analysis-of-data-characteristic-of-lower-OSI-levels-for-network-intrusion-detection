import json

from sigma_backend.sigmaDetector import SigmaDetector
from traffic_capture.logs import save_log

RULE_DIR="sigma_rules"

detector=SigmaDetector(RULE_DIR)

def analyze(file_path):
    with open(file_path, 'r') as f:
        logs=json.load(f)

    for entry in logs:
        if detector.analyze(entry):
            save_log(entry, "offline_alerts.json")

if __name__ == "__main__":
    analyze("offline_logs.json")