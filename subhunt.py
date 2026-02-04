#!/usr/bin/env python3
"""
SubHunt - fast subdomain enumeration from massive passive DNS datasets
Author: Vahe Demirkhanyan
"""

import sys
import time
import random
from typing import Any, Iterable, Optional, Set

import requests

API_URL = "https://ip.thc.org/api/v1/lookup/subdomains"
CANDIDATE_KEYS = ("domain", "subdomain", "fqdn", "name", "host")

MAX_RETRIES = 6
BASE_BACKOFF_SEC = 0.6
MAX_BACKOFF_SEC = 12.0
TIMEOUT_SEC = 30

TRANSIENT_STATUSES = {408, 425, 429, 500, 502, 503, 504}


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


def _retry_after_seconds(resp: requests.Response) -> Optional[float]:
    ra = resp.headers.get("Retry-After")
    if not ra:
        return None
    try:
        return float(int(ra.strip()))
    except Exception:
        return None


def _sleep_backoff(attempt: int, forced_min: Optional[float] = None) -> None:
    delay = min(MAX_BACKOFF_SEC, BASE_BACKOFF_SEC * (2 ** attempt))
    delay *= random.uniform(0.85, 1.15)
    if forced_min is not None:
        delay = max(delay, forced_min)
    time.sleep(delay)


def post_lookup(session: requests.Session, domain: str, limit: int, page_state: str) -> Any:
    payload = {"domain": domain, "limit": limit, "page_state": page_state}
    headers = {"Accept": "application/json", "User-Agent": "subhunt/1.1"}

    last_err: Optional[str] = None

    for attempt in range(MAX_RETRIES):
        try:
            r = session.post(API_URL, json=payload, headers=headers, timeout=TIMEOUT_SEC)
        except requests.RequestException as e:
            last_err = f"Request error: {e}"
            _sleep_backoff(attempt)
            continue

        if 200 <= r.status_code < 300:
            try:
                return r.json()
            except Exception:
                snippet = r.text[:200].replace("\n", "\\n")
                die(f"Unexpected response (not JSON). First 200 chars: {snippet}", 2)

        if r.status_code in TRANSIENT_STATUSES or (500 <= r.status_code <= 599):
            ra = _retry_after_seconds(r) if r.status_code == 429 else None
            last_err = f"HTTP {r.status_code}"
            _sleep_backoff(attempt, forced_min=ra)
            continue

        snippet = (r.text or "")[:200].replace("\n", "\\n")
        die(f"HTTP {r.status_code}. First 200 chars: {snippet}", 2)

    die(f"Failed after {MAX_RETRIES} retries. Last error: {last_err or 'unknown'}", 2)


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
