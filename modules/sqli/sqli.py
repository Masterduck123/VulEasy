import time
import requests
import os
import urllib.parse
import re

def banner():
    print(r"""   _____  ____  _      
  / ____|/ __ \| |     
 | (___ | |  | | |     
  \___ \| |  | | |     
  ____) | |__| | |____ 
 |_____/ \___\_\______|
                       
                       """)

def is_valid_url(url):
    regex = re.compile(
        r'^(https?:\/\/)'                  # http:// o https://
        r'(([A-Za-z0-9-]+\.)+[A-Za-z]{2,})'  # domain, example example.com
        r'(:\d+)?'                         # optional port, example :8080
        r'(\/[A-Za-z0-9\-._~:/?#[\]@!$&\'()*+,;=%]*)?$',  # optional rute
        re.IGNORECASE
    )
    return re.match(regex, url) is not None

def run():
    banner()
    base_url = input("Target URL (e.g. https://example.com): ").strip()
    if not is_valid_url(base_url):
        print("[ERROR] Invalid URL format.")
        return

    method = input("HTTP Method (GET/POST): ").strip().upper()
    endpoint = input("Endpoint (e.g. /login): ").strip()
    if not endpoint.startswith("/"):
        endpoint = "/" + endpoint

    params_raw = input("Parameters (e.g. user=admin&pass=): ").strip()
    param_vuln = input("Parameter to inject payload (e.g. pass): ").strip() or None

    if param_vuln is None or param_vuln not in params_raw:
        print("[ERROR] You must specify a valid parameter to inject the payload.")
        return

    payloads = load_payloads()
    if not payloads:
        print("[ERROR] No payloads found.")
        return

    print(f"\n[INFO] Starting {method} scan with {len(payloads)} payloads...\n")

    params = dict(urllib.parse.parse_qsl(params_raw))

    for payload in payloads:
        params_injected = params.copy()
        params_injected[param_vuln] = payload

        try:
            if method == "GET":
                url = base_url.strip("/") + endpoint
                r = requests.get(url, params=params_injected, timeout=10)
            elif method == "POST":
                url = base_url.strip("/") + endpoint
                r = requests.post(url, data=params_injected, timeout=10)

            show_result(payload, r)
        except Exception as e:
            print(f"[ERROR] {e}")

        time.sleep(2)

    input("\n[INFO] Scan finished... Press [ENTER] to return to main menu...")

def show_result(payload, response):
    print(f"[PAYLOAD] {payload}")
    print(f"[STATUS] {response.status_code}")
    print(f"[RESPONSE]\n{response.text[:500]}\n{'-'*40}")

def load_payloads():
    filepath = os.path.join(os.path.dirname(__file__), "payloads.txt")
    if not os.path.exists(filepath):
        return []
    with open(filepath, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]