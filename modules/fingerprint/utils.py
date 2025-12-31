# modules/fingerprint/utils.py
import requests
import socket


def extract_domain(url: str) -> str | None:
    try:
        return url.split("//")[-1].split("/")[0]
    except Exception:
        return None


def resolve_ip(domain: str) -> str | None:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


def send_request(
    url: str,
    headers: dict,
    method: str = "GET",
    params: dict | None = None,
    data: dict | None = None,
    timeout: int = 10
):
    try:
        if method.upper() == "POST":
            return requests.post(
                url,
                headers=headers,
                data=data,
                timeout=timeout,
                allow_redirects=True
            )
        else:
            return requests.get(
                url,
                headers=headers,
                params=params,
                timeout=timeout,
                allow_redirects=True
            )
    except requests.RequestException:
        return None
