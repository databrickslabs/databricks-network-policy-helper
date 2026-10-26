"""Dependency-free HTTP GET with a short exponential-backoff retry (ported from the notebooks)."""

from __future__ import annotations

import json
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

FEED_TIMEOUT_SECONDS = 30
FEED_USER_AGENT = "Databricks-Network-Policy-Helper"


def http_get(url: str, as_json: bool = False, headers: dict[str, str] | None = None) -> Any | None:
    """GET a URL with a short retry, returning text or parsed JSON. Returns None on failure.
    `headers` adds/overrides request headers (e.g. an abuse.ch `Auth-Key`)."""
    hdrs = {"User-Agent": FEED_USER_AGENT, "Accept": "*/*"}
    if headers:
        hdrs.update(headers)
    delay, last_error = 1.0, None
    for attempt in range(1, 4):
        try:
            request = Request(url, headers=hdrs)
            with urlopen(request, timeout=FEED_TIMEOUT_SECONDS) as response:
                raw = response.read().decode("utf-8", errors="replace")
            return json.loads(raw) if as_json else raw
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as error:
            last_error = error
            if attempt < 3:
                time.sleep(delay)
                delay *= 2
    from ..console import banner

    banner("warn", f"feed fetch failed for {url}: {last_error}")
    return None


def http_post_json(url: str, body: dict, headers: dict[str, str] | None = None) -> Any | None:
    """POST a JSON body and return the parsed JSON response (None on failure). Used for the abuse.ch
    APIs, which take a JSON query and an `Auth-Key` header."""
    hdrs = {"User-Agent": FEED_USER_AGENT, "Accept": "*/*", "Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    data = json.dumps(body).encode()
    delay, last_error = 1.0, None
    for attempt in range(1, 4):
        try:
            request = Request(url, data=data, headers=hdrs, method="POST")
            with urlopen(request, timeout=FEED_TIMEOUT_SECONDS) as response:
                return json.loads(response.read().decode("utf-8", errors="replace"))
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as error:
            last_error = error
            if attempt < 3:
                time.sleep(delay)
                delay *= 2
    from ..console import banner

    banner("warn", f"feed fetch failed for {url}: {last_error}")
    return None


def http_get_zip_member(url: str, member_suffix: str = ".csv") -> str | None:
    """Download a ZIP and return the decoded text of its first member whose name ends with
    `member_suffix` (used for Tranco's `top-1m.csv.zip`). Follows redirects; returns None on failure.
    Kept separate from `http_get` because the payload is binary, not UTF-8 text."""
    import io
    import zipfile

    delay, last_error = 1.0, None
    for attempt in range(1, 4):
        try:
            request = Request(url, headers={"User-Agent": FEED_USER_AGENT, "Accept": "*/*"})
            with urlopen(request, timeout=FEED_TIMEOUT_SECONDS) as response:
                blob = response.read()
            with zipfile.ZipFile(io.BytesIO(blob)) as zf:
                name = next((n for n in zf.namelist() if n.endswith(member_suffix)), None)
                if name is None:
                    return None
                return zf.read(name).decode("utf-8", errors="replace")
        except (HTTPError, URLError, TimeoutError, zipfile.BadZipFile, OSError) as error:
            last_error = error
            if attempt < 3:
                time.sleep(delay)
                delay *= 2
    from ..console import banner

    banner("warn", f"feed fetch failed for {url}: {last_error}")
    return None
