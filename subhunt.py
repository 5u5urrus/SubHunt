#!/usr/bin/env python3
"""
SubHunt - fast subdomain enumeration from massive passive DNS datasets
Author: Vahe Demirkhanyan
"""

import sys
import json
import time
from typing import Any, Iterable, Optional, Set
import requests

API_URL = "https://ip.thc.org/api/v1/lookup/subdomains"
CANDIDATE_KEYS = ("domain", "subdomain", "fqdn", "name", "host")

def die(msg: str, code: int = 1) -> None:
    print(msg, file=sys.stderr)
    sys.exit(code)

def extract_domains(obj: Any) -> Iterable[str]:
    if isinstance(obj, str):
        yield obj
        return
    if isinstance(obj, list):
        for item in obj:
            yield from extract_domains(item)
        return
    if isinstance(obj, dict):
        for k in CANDIDATE_KEYS:
            v = obj.get(k)
            if isinstance(v, str) and v.strip():
                yield v.strip()
        for k in ("subdomains", "results", "data", "items"):
            v = obj.get(k)
            if isinstance(v, (list, dict, str)):
                yield from extract_domains(v)
        for v in obj.values():
            if isinstance(v, (list, dict)):
                yield from extract_domains(v)

def find_next_page_state(obj: Any) -> Optional[str]:
    if isinstance(obj, dict):
        for k in ("page_state", "next_page_state", "next", "cursor"):
            v = obj.get(k)
            if isinstance(v, str) and v:
                return v
        for v in obj.values():
            ps = find_next_page_state(v)
            if ps:
                return ps
    elif isinstance(obj, list):
        for v in obj:
            ps = find_next_page_state(v)
            if ps:
                return ps
    return None

def post_lookup(session: requests.Session, domain: str, limit: int, page_state: str) -> Any:
    body = json.dumps({"domain": domain, "limit": limit, "page_state": page_state})
    r = session.post(
        API_URL,
        data=body,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json, */*",
            "User-Agent": "thc-subd-cli/1.0",
        },
        timeout=30,
    )
    r.raise_for_status()
    try:
        return r.json()
    except Exception:
        snippet = r.text[:200].replace("\n", "\\n")
        die(f"Unexpected response (not JSON). First 200 chars: {snippet}", 2)

def main() -> None:
    if len(sys.argv) != 2:
        die(f"Usage: {sys.argv[0]} <domain>")
    domain = sys.argv[1].strip().lower()
    if not domain or "/" in domain or " " in domain:
        die("Invalid domain")
    session = requests.Session()
    page_state = ""
    seen: Set[str] = set()
    limit = 500
    while True:
        obj = post_lookup(session, domain, limit, page_state)
        out = []
        for s in extract_domains(obj):
            s = s.strip().lower()
            if s == domain or s.endswith("." + domain):
                if s not in seen:
                    seen.add(s)
                    out.append(s)
        for s in out:
            print(s)
        next_state = find_next_page_state(obj)
        if not next_state or next_state == page_state:
            break
        page_state = next_state
        time.sleep(0.15)

if __name__ == "__main__":
    main()
