# modules/sqli/utils.py
import os

def load_payloads():
    base_path = os.path.dirname(__file__)
    payload_file = os.path.join(base_path, "payloads.txt")
    try:
        with open(payload_file, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[ERROR] Failed to load SQLi payloads: {e}")
        return []
