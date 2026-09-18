#!/usr/bin/env python3
"""
Standalone keep-alive pinger for Render free-tier services.

Usage:
    # Ping every 5 minutes (default)
    python keep_awake.py https://netwatch-sih26153-api.onrender.com

    # Custom interval (in seconds)
    python keep_awake.py https://netwatch-sih26153-api.onrender.com --interval 180

    # One-shot ping (for cron jobs)
    python keep_awake.py https://netwatch-sih26153-api.onrender.com --once
"""

import argparse
import sys
import time
import urllib.request
import json
from datetime import datetime, timezone

UTC = timezone.utc


def ping(url: str, timeout: int = 30) -> tuple[bool, dict]:
    """Ping the keepalive endpoint and return status."""
    try:
        start = time.time()
        resp = urllib.request.urlopen(f"{url}/api/keepalive", timeout=timeout)
        elapsed = time.time() - start
        data = json.loads(resp.read().decode())
        return True, {"status": resp.status, "elapsed_ms": round(elapsed * 1000), **data}
    except Exception as e:
        return False, {"error": str(e)}


def main():
    parser = argparse.ArgumentParser(description="Keep Render free-tier service awake")
    parser.add_argument("url", help="Base URL (e.g. https://your-app.onrender.com)")
    parser.add_argument("--interval", type=int, default=300, help="Ping interval in seconds (default: 300)")
    parser.add_argument("--once", action="store_true", help="Ping once and exit")
    args = parser.parse_args()

    url = args.url.rstrip("/")
    print(f"🔄 Keep-alive pinger for {url}")
    print(f"   Interval: {args.interval}s | Mode: {'once' if args.once else 'continuous'}")
    print()

    while True:
        ts = datetime.now(UTC).strftime("%H:%M:%S")
        ok, info = ping(url)

        if ok:
            print(f"[{ts}] ✅ HTTP {info['status']} | {info['elapsed_ms']}ms | uptime: {info.get('uptime', '?')}")
        else:
            print(f"[{ts}] ❌ FAILED: {info['error']}")

        if args.once:
            sys.exit(0 if ok else 1)

        time.sleep(args.interval)


if __name__ == "__main__":
    main()
