import re
from bs4 import BeautifulSoup
from .utils import send_request, extract_domain, resolve_ip

# ---------------- ENTRY POINT ----------------

def run():
    banner()
    
    url = input("Target URL: ").strip()

    if not url.startswith("http"):
        url = "http://" + url

    headers = {"User-Agent": "VulEasy Fingerprint"}
    response = send_request(url, headers)

    domain = extract_domain(url)

    result = {
        "domain": domain,
        "ip": resolve_ip(domain) if domain else None,
        "server": detect_server(response),
        "cloudflare": detect_cloudflare(response),
        "wordpress": detect_wordpress(response)
    }

    output = (
        f"[Fingerprint Result]\n"
        f"Domain: {result['domain']}\n"
        f"IP: {result['ip']}\n"
        f"Server: {result['server']}\n"
        f"Cloudflare: {result['cloudflare']}\n"
        f"WordPress: {result['wordpress']}\n"
    )

    print(output)
    return output
    
def banner():
    print(r""" _____ ___ _   _  ____ _____ ____  ____  ____  ___ _   _ _____ 
|  ___|_ _| \ | |/ ___| ____|  _ \|  _ \|  _ \|_ _| \ | |_   _|
| |_   | ||  \| | |  _|  _| | |_) | |_) | |_) || ||  \| | | |  
|  _|  | || |\  | |_| | |___|  _ <|  __/|  _ < | || |\  | | |  
|_|   |___|_| \_|\____|_____|_| \_\_|   |_| \_\___|_| \_| |_|  
                       """)
                       
def is_valid_url(url):
    regex = re.compile(
        r'^(https?:\/\/)'
        r'(([A-Za-z0-9-]+\.)+[A-Za-z]{2,})'
        r'(:\d+)?'
        r'(\/[A-Za-z0-9\-._~:/?#[\]@!$&\'()*+,;=%]*)?$',
        re.IGNORECASE
    )
    return re.match(regex, url) is not None

# ---------------- SERVER ----------------

def detect_server(response):
    if not response:
        return "unknown"

    server = response.headers.get("Server", "").lower()

    if "nginx" in server:
        return "nginx"
    if "apache" in server:
        return "apache"
    if "cloudflare" in server:
        return "cloudflare"

    return server or "unknown"


# ---------------- CLOUDFLARE ----------------

def detect_cloudflare(response):
    if not response:
        return False

    headers = response.headers
    cf_headers = (
        "cf-ray",
        "cf-cache-status",
        "cf-request-id",
        "cf-connecting-ip"
    )

    return any(h in headers for h in cf_headers) or \
           headers.get("Server", "").lower() == "cloudflare"


# ---------------- WORDPRESS ----------------

def detect_wordpress(response):
    result = {"detected": False}

    if not response:
        return result

    html = response.text.lower()

    if not any(x in html for x in ("wp-content", "wp-includes", "/wp-json")):
        return result

    result["detected"] = True

    soup = BeautifulSoup(response.text, "html.parser")
    meta = soup.find("meta", {"name": "generator"})

    if meta and "wordpress" in meta.get("content", "").lower():
        result["version"] = meta.get("content")

    for c in response.cookies.get_dict():
        if "wordpress" in c.lower():
            result["cookie_hint"] = c

    return result
