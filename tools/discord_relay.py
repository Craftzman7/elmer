#!/usr/bin/env python3
"""Relay elmer webhook alerts to Discord across an air gap.

Monitored competition boxes have no internet, but they can reach the blue
team LAN. Run this on the one box that has an uplink (e.g. a laptop on
wifi + ethernet): elmer's webhook channel POSTs to it over plain HTTP,
the relay verifies the HMAC signature, records every alert to a local
JSONL log (the channel of record if Discord drops anything), and
forwards to a Discord webhook URL.

Stdlib only, no dependencies, no build step. Python 3.9+.

    python3 tools/discord_relay.py \
        --discord https://discord.com/api/webhooks/... \
        --secret <shared secret> \
        --listen 0.0.0.0:8080

Each monitored box gets in elmer.yaml:

    alerts:
      webhook:
        url: http://<relay-lan-ip>:8080/alert
        secret: <shared secret>
"""

import argparse
import hashlib
import hmac
import json
import queue
import signal
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

QUEUE_SIZE = 4096
FORWARD_ATTEMPTS = 5

SEVERITY_COLORS = {
    "CRITICAL": 0xC0392B,
    "HIGH": 0xE74C3C,
    "MEDIUM": 0xF1C40F,
    "LOW": 0x3498DB,
    "INFO": 0x95A5A6,
}

# Keys of events.Flat() that are rendered into the embed itself rather
# than as extra fields; anything else in the payload was an event Field.
RESERVED_KEYS = {"time", "severity", "category", "title", "message", "technique", "host"}


def to_discord_payload(ev):
    sev = str(ev.get("severity", "INFO")).upper()
    host = ev.get("host") or ""
    title = str(ev.get("title") or "untitled")
    head = f"[{sev}] {host}: {title}" if host else f"[{sev}] {title}"

    fields = []
    for key in ("category", "technique"):
        val = ev.get(key)
        if val:
            fields.append({"name": key, "value": str(val)[:1024], "inline": True})
    for key in sorted(ev):
        if key in RESERVED_KEYS or key.startswith("_"):
            continue
        val = ev.get(key)
        if val in (None, ""):
            continue
        fields.append({"name": str(key)[:256], "value": str(val)[:1024], "inline": True})
    fields = fields[:25]  # Discord hard cap

    embed = {
        "title": head[:256],
        "color": SEVERITY_COLORS.get(sev, SEVERITY_COLORS["INFO"]),
        "fields": fields,
    }
    if ev.get("message"):
        embed["description"] = str(ev["message"])[:4096]
    if ev.get("time"):
        try:
            ts = str(ev["time"]).replace("Z", "+00:00")
            embed["timestamp"] = datetime.fromisoformat(ts).isoformat()
        except ValueError:
            pass
    return {"username": "elmer", "embeds": [embed]}


def post_discord(url, body):
    """Returns (http_status, retry_after_seconds); status 0 = transport error."""
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json", "User-Agent": "elmer-relay"}
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, 0.0
    except urllib.error.HTTPError as e:
        retry_after = 0.0
        if e.code == 429:
            try:
                retry_after = float(e.headers.get("Retry-After", 0))
            except (TypeError, ValueError):
                retry_after = 0.0
        return e.code, retry_after
    except (urllib.error.URLError, OSError):
        return 0, 0.0


class Relay:
    def __init__(self, discord_url, log_path):
        self.discord_url = discord_url
        self.q = queue.Queue(maxsize=QUEUE_SIZE)
        self.log_lock = threading.Lock()
        self.log_file = open(log_path, "a", encoding="utf-8", buffering=1)

    def record(self, ev, peer):
        """Log on receipt, before forwarding, so the JSONL file is the
        channel of record even if Discord drops the event."""
        line = json.dumps(
            {"recv_time": datetime.now(timezone.utc).isoformat(), "peer": peer, "event": ev},
            separators=(",", ":"),
        )
        with self.log_lock:
            self.log_file.write(line + "\n")

    def enqueue(self, ev):
        try:
            self.q.put_nowait(ev)
        except queue.Full:
            # Drop-oldest, mirroring elmer's own dispatch policy.
            try:
                self.q.get_nowait()
                self.q.put_nowait(ev)
                print("[relay] queue full; dropped oldest event", file=sys.stderr, flush=True)
            except queue.Empty:
                pass

    def forward_loop(self):
        while True:
            ev = self.q.get()
            body = json.dumps(to_discord_payload(ev)).encode()
            last_err = "unknown"
            for attempt in range(FORWARD_ATTEMPTS):
                status, retry_after = post_discord(self.discord_url, body)
                if 200 <= status < 300:
                    last_err = ""
                    break
                last_err = f"HTTP {status}" if status else "network error"
                # 4xx other than 429 means the URL/payload is wrong;
                # retrying cannot fix it.
                if status in (400, 401, 403, 404):
                    break
                time.sleep(max(retry_after, min(2**attempt, 8)))
            if last_err:
                print(
                    f"[discord] drop ({last_err}); event remains in local log",
                    file=sys.stderr,
                    flush=True,
                )
            self.q.task_done()


class Handler(BaseHTTPRequestHandler):
    server_version = "elmer-relay/1.0"

    def do_POST(self):
        relay = self.server.relay
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length > 0 else b""

        if relay.secret:
            want = "sha256=" + hmac.new(relay.secret.encode(), body, hashlib.sha256).hexdigest()
            got = self.headers.get("X-Elmer-Signature", "")
            if not hmac.compare_digest(want, got):
                print(
                    f"[relay] rejected bad signature from {self.client_address[0]}",
                    file=sys.stderr,
                    flush=True,
                )
                self.send_error(401)
                return

        try:
            ev = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.send_error(400)
            return

        relay.record(ev, self.client_address[0])
        relay.enqueue(ev)

        sev = str(ev.get("severity", "?")).upper()
        host = ev.get("host") or "?"
        title = str(ev.get("title") or "untitled")
        print(f"{datetime.now().strftime('%H:%M:%S')} {sev:<8} {host:<12} {title}", flush=True)

        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        if self.path == "/healthz":
            body = b"ok\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404)

    def log_message(self, fmt, *args):
        pass  # request noise would drown out the per-alert lines


def lan_ip():
    # connect() on a UDP socket only picks a route; no packet is sent.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def main():
    ap = argparse.ArgumentParser(description="Relay elmer webhook alerts to Discord.")
    ap.add_argument("--listen", default="0.0.0.0:8080", help="bind as host:port (default 0.0.0.0:8080)")
    ap.add_argument(
        "--discord",
        default=None,
        help="Discord webhook URL (or env ELMER_DISCORD_WEBHOOK)",
    )
    ap.add_argument(
        "--secret",
        default=None,
        help="shared HMAC secret; required to match elmer's webhook secret (or env ELMER_RELAY_SECRET)",
    )
    ap.add_argument("--log", default="elmer-relay.jsonl", help="local alert log (default elmer-relay.jsonl)")
    args = ap.parse_args()

    discord_url = args.discord or ""
    secret = args.secret or ""
    if not discord_url:
        sys.exit("error: --discord (or ELMER_DISCORD_WEBHOOK) is required")
    if not secret:
        print("[relay] warning: no --secret set; anyone on the LAN can inject alerts", file=sys.stderr)

    host, _, port = args.listen.rpartition(":")
    if not host:
        sys.exit(f"error: --listen must be host:port, got {args.listen!r}")

    relay = Relay(discord_url, args.log)
    relay.secret = secret

    httpd = ThreadingHTTPServer((host, int(port)), Handler)
    httpd.daemon_threads = True
    httpd.relay = relay

    threading.Thread(target=relay.forward_loop, daemon=True).start()

    ip = lan_ip()
    print(f"elmer discord relay listening on {args.listen} (LAN ip looks like {ip})", flush=True)
    print(f"alert log: {args.log}", flush=True)
    print("paste into each box's elmer.yaml:", flush=True)
    print(f"  alerts:\n    webhook:\n      url: http://{ip}:{port}/alert", flush=True)
    if secret:
        print(f"      secret: {secret}", flush=True)
    print("ctrl-c to stop", flush=True)

    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
