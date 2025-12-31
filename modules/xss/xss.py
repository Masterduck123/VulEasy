import time
import requests
import re
import urllib.parse
from modules.xss.utils import load_payloads

def banner():
    print(r"""__  ______ ____  
\ \/ / ___/ ___| 
 \  /\___ \___ \ 
 /  \ ___) |__) |
/_/\_\____/____/ 
                 
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
    if method not in ["GET", "POST"]:
        print("[ERROR] Invalid Method! Only GET or POST allowed.")
        return

    endpoint = input("Endpoint (e.g. /search): ").strip()
    endpoint = endpoint if endpoint.startswith("/") else "/" + endpoint

    params_raw = input("Parameters (e.g. q=): ").strip()
    param_vuln = input("Parameter to inject payload (e.g. q): ").strip()

    if not param_vuln or param_vuln not in params_raw:
        print("[ERROR] You must specify a valid parameter to inject the payload.")
        return

    payloads = load_payloads()
    if not payloads:
        print("[ERROR] No payloads found.")
        return

    print(f"\n[INFO] Starting {method} XSS scan with {len(payloads)} payloads...\n")

    params = dict(urllib.parse.parse_qsl(params_raw))

    for payload in payloads:
        params_injected = params.copy()
        params_injected[param_vuln] = payload

        try:
            url = base_url.rstrip("/") + endpoint
            if method == "GET":
                r = requests.get(url, params=params_injected, timeout=10)
            elif method == "POST":
                r = requests.post(url, data=params_injected, timeout=10)

            show_result(payload, r)
        except Exception as e:
            print(f"[ERROR] {e}")

        time.sleep(1)

    input("\n[INFO] Scan finished... Press [ENTER] to exit...")
    
def show_result(payload, response):
    reflected = "[XSS DETECTED]" if payload in response.text else ""
    print(f"[PAYLOAD] {payload}")
    print(f"[STATUS] {response.status_code}")
    print(f"[RESPONSE]\n{response.text[:500]}\n{'-'*40}")
    if reflected:
        print(reflected)

if __name__ == "__main__":
    run()