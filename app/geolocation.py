from __future__ import annotations

from typing import Dict, Optional

import json
import urllib.error
import urllib.request

_cache: Dict[str, Dict[str, str]] = {}


def lookup_ip_location(ip: str, timeout: float = 3.0) -> Optional[Dict[str, str]]:
    """Look up IP geolocation using ip-api.com (free tier, no key required).

    Returns a dict with city/region/country/lat/lon/isp when available.
    Results are cached in-memory per process.
    """
    if not ip or ip in {"127.0.0.1", "::1"}:
        return None
    if ip in _cache:
        return _cache[ip]
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,isp"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NetMapper/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
        if data.get("status") != "success":
            return None
        result = {
            "country": data.get("country", ""),
            "region": data.get("regionName", ""),
            "city": data.get("city", ""),
            "lat": str(data.get("lat", "")),
            "lon": str(data.get("lon", "")),
            "isp": data.get("isp", ""),
        }
        _cache[ip] = result
        return result
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError):
        return None

