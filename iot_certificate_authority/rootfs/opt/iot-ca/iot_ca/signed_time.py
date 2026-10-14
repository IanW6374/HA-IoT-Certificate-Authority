"""Device-bound signed time; independent signer and bounded, read-only clocks.

Never sets the host clock, issues certificates, or uses the CA signing key.
Network activity/listener creation occur only in explicitly enabled main().
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
import socket
import signal
import stat
import struct
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
DEFAULTS = dict(signed_time_enabled=False, time_source="host", time_ntp_servers=[],
                time_require_nts=True, time_device_macs=[], time_hostname="", time_port=9011)


def hostname(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 253:
        raise ValueError("A bounded server hostname is required")
    try:
        ipaddress.IPv4Address(value)
        return value
    except ValueError:
        pass
    if not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", p)
               for p in value.split(".")):
        raise ValueError("Invalid server hostname")
    return value.lower()


def configuration(options):
    if not isinstance(options, dict):
        raise ValueError("Invalid add-on options")
    c = {k: options.get(k, v) for k, v in DEFAULTS.items()}
    if any(type(c[k]) is not bool for k in ("signed_time_enabled", "time_require_nts")):
        raise ValueError("Time switches must be booleans")
    if c["time_source"] not in ("host", "ntp"):
        raise ValueError("Clock source must be host or ntp")
    if not isinstance(c["time_ntp_servers"], list) or len(c["time_ntp_servers"]) > 4:
        raise ValueError("Configure at most four named NTP servers")
    c["time_ntp_servers"] = [hostname(v) for v in c["time_ntp_servers"]]
    if len(set(c["time_ntp_servers"])) != len(c["time_ntp_servers"]):
        raise ValueError("Duplicate time server")
    if c["time_source"] == "ntp" and not c["time_ntp_servers"]:
        raise ValueError("Custom NTP requires at least one server")
    if not isinstance(c["time_device_macs"], list) or len(c["time_device_macs"]) > 4096:
        raise ValueError("A bounded device allowlist is required")
    devices = []
    for v in c["time_device_macs"]:
        if not isinstance(v, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{12}|(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})", v):
            raise ValueError("Invalid factory device MAC")
        value = v.replace(":", "").lower()
        if value == "0" * 12 or value in devices:
            raise ValueError("Zero or duplicate factory device MAC")
        devices.append(value)
    c["time_device_macs"] = devices
    if c["signed_time_enabled"] and not devices:
        raise ValueError("Enabling signed time requires allowed device MACs")
    if c["time_hostname"]:
        c["time_hostname"] = hostname(c["time_hostname"])
    if type(c["time_port"]) is not int or not 1 <= c["time_port"] <= 65535:
        raise ValueError("Invalid external signed-time port")
    return c


def load_options(path="/data/options.json"):
    p = Path(path)
    return configuration(json.loads(p.read_text()) if p.exists() else {})


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".new")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(value, stream, sort_keys=True)
        stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary, path)


def load_signer(root):
    path = Path(root) / "secrets" / "time-signing-key.pem"
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # No implicit replacement/rotation after corrupt or incomplete key creation.
    if not path.exists() and not path.is_symlink():
        key = ec.generate_private_key(ec.SECP256R1())
        raw = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > 8192:
            raise ValueError("Private dedicated signing key required")
        key = serialization.load_pem_private_key(stream.read(8193), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("Dedicated P-256 time key required")
    return key


def host_sample(wall=time.time, run=subprocess.run):
    # Compiled against target libc headers: no guessed 32/64-bit timex ABI.
    result = run(["iot-ca-clock-status"], check=True, timeout=1, capture_output=True, text=True)
    if len(result.stdout) > 1024:
        raise ValueError("Oversized host clock status")
    state = json.loads(result.stdout)
    if any(type(state[k]) is not int for k in ("result", "status", "maxerror")) or state["result"] != 0 or state["status"] & 0x40 or not 0 <= state["maxerror"] <= 1000000:
        raise ValueError("Host clock is not demonstrably synchronized")
    return wall()


def chrony_config(c, directory):
    directory = Path(directory)
    if not re.fullmatch(r"/[A-Za-z0-9_./-]+", str(directory)):
        raise ValueError("Unsafe private chrony path")
    lines = ["port 0", "cmdport 0", "bindcmdaddress " + str(directory / "chronyd.sock"),
             "pidfile " + str(directory / "chronyd.pid"), "maxdistance 1.0", "maxupdateskew 100.0",
             "authselectmode " + ("require" if c["time_require_nts"] else "ignore")]
    lines += ["server " + name + " iburst minpoll 4 maxpoll 5" +
              (" nts" if c["time_require_nts"] else "") for name in c["time_ntp_servers"]]
    return "\n".join(lines) + "\n"


def chrony_sample(output, wall):
    fields = {}
    for line in output.splitlines():
        if ":" in line:
            k, v = line.split(":", 1); fields[k.strip()] = v.strip()
    if fields.get("Leap status") != "Normal" or not 1 <= int(fields["Stratum"]) <= 15:
        raise ValueError("Custom clock is not synchronized")
    ref = fields["Reference ID"].split()[0]
    if ref in ("00000000", "7F7F0101"):
        raise ValueError("External clock source required")
    updated = datetime.strptime(fields["Ref time (UTC)"], "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc).timestamp()
    match = re.fullmatch(r"([0-9.]+) seconds (fast|slow) of NTP time", fields["System time"])
    if not match:
        raise ValueError("Invalid tracking offset")
    offset = float(match[1]); offset *= -1 if match[2] == "fast" else 1
    utc = wall + offset
    delay = float(fields["Root delay"].split()[0]); dispersion = float(fields["Root dispersion"].split()[0])
    skew = float(fields["Skew"].split()[0])
    if not all(math.isfinite(v) for v in (utc, delay, dispersion, skew)) or not 0 <= utc - updated <= 120:
        raise ValueError("Stale or malformed custom clock")
    if delay < 0 or dispersion < 0 or delay / 2 + dispersion > 1 or not 0 <= skew <= 100:
        raise ValueError("Custom clock uncertainty exceeds policy")
    return utc


class Clock:
    def __init__(self, sample, monotonic=time.monotonic):
        self.sample = sample; self.monotonic = monotonic
        self.lock = threading.Lock(); self.anchor = None; self.healthy = False; self.fault = False

    def refresh(self):
        try:
            before = self.monotonic(); utc = self.sample(); now = self.monotonic()
            if not math.isfinite(utc) or not 1704067200 <= utc <= 4102444800 or not 0 <= now - before <= 2:
                raise ValueError("Unbounded clock sample")
            with self.lock:
                if self.anchor and (now < self.anchor[0] or abs(utc - self.anchor[1] - (now - self.anchor[0])) > 2):
                    self.fault = True
                self.healthy = not self.fault
                if self.healthy:
                    self.anchor = (now, utc)
        except Exception:
            with self.lock:
                self.healthy = False

    def now(self):
        with self.lock:
            now = self.monotonic()
            if not self.healthy or self.fault or self.anchor is None or not 0 <= now - self.anchor[0] <= 15:
                raise ValueError("Clock unavailable or expired")
            return self.anchor[1] + now - self.anchor[0]


class Authority:
    def __init__(self, signer, devices, clock, monotonic=time.monotonic):
        self.signer = signer; self.devices = frozenset(devices); self.clock = clock
        self.monotonic = monotonic; self.rate = {}; self.lock = threading.Lock()

    def response(self, method, path):
        if method != "GET":
            return 405, b""
        if not isinstance(path, str) or len(path) > 256:
            return 400, b""
        try:
            uri = urlsplit(path)
            if uri.scheme or uri.netloc or uri.fragment or uri.path != "/iotmd/v1/time":
                return 404, b""
            args = parse_qs(uri.query, strict_parsing=True, max_num_fields=2)
            if set(args) != {"device", "nonce"} or any(len(v) != 1 for v in args.values()):
                return 400, b""
            device, nonce = args["device"][0], args["nonce"][0]
            if not re.fullmatch(r"[0-9a-fA-F]{12}", device) or not re.fullmatch(r"[0-9a-fA-F]{64}", nonce):
                return 400, b""
        except ValueError:
            return 400, b""
        device = device.lower()
        if device not in self.devices:
            return 403, b""
        with self.lock:
            now = self.monotonic()
            if now - self.rate.get(device, -float("inf")) < 1:
                return 429, b""
            self.rate[device] = now
            try:
                utc = self.clock.now()
            except ValueError:
                return 503, b""
            message = b"IMDT01\0\0" + bytes.fromhex(device) + bytes.fromhex(nonce) + struct.pack("<Q", int(utc))
            r, s = utils.decode_dss_signature(self.signer.sign(message, ec.ECDSA(hashes.SHA256())))
            return 200, message + r.to_bytes(32, "big") + min(s, ORDER - s).to_bytes(32, "big")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def setup(self):
        self.request.settimeout(2)
        self.deadline = threading.Timer(3, self.expire); self.deadline.daemon = True; self.deadline.start()
        try:
            super().setup()
        except Exception:
            self.deadline.cancel(); raise
    def expire(self):
        try:
            self.request.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
    def finish(self):
        try:
            super().finish()
        finally:
            self.deadline.cancel()
    def do_GET(self):
        if self.headers.get("Transfer-Encoding") or self.headers.get("Content-Length", "0") != "0":
            code, body = 400, b""
        else:
            code, body = self.server.authority.response("GET", self.path)
        self.send_response_only(code)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store"); self.send_header("Connection", "close")
        self.end_headers(); self.wfile.write(body); self.close_connection = True
    def do_POST(self):
        self.send_response_only(405); self.send_header("Content-Length", "0")
        self.send_header("Connection", "close"); self.end_headers(); self.close_connection = True
    do_PUT = do_DELETE = do_PATCH = do_POST
    def log_message(self, *args):
        pass  # No nonce/query dumps or signing-material logs.


class Server(HTTPServer):
    request_queue_size = 8
    def __init__(self, address, authority):
        self.authority = authority; self.slots = threading.BoundedSemaphore(4)
        self.pool = ThreadPoolExecutor(max_workers=4)
        super().__init__(address, Handler)
    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request); return
        try:
            self.pool.submit(self.process, request, address)
        except RuntimeError:
            self.slots.release(); self.shutdown_request(request)
    def process(self, request, address):
        try:
            self.finish_request(request, address)
        except Exception:
            pass
        finally:
            self.shutdown_request(request); self.slots.release()
    def server_close(self):
        super().server_close(); self.pool.shutdown(wait=True, cancel_futures=True)


def public_state(path):
    try:
        if path.stat().st_size > 8192:
            return {}
        value = json.loads(path.read_text())
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def public_configuration(root, options=None):
    try:
        c = options if options is not None else load_options()
    except (ValueError, OSError):
        c = configuration({})
    path = Path(root) / "signed-time-status.json"
    status = public_state(path)
    # A persisted healthy bit is never a post-reboot health assertion.
    current = status.get("configuration_hash") == configuration_hash(c)
    stamp = status.get("monotonic", -100)
    fresh = type(stamp) in (int, float) and status.get("boot_id") == boot_id() and 0 <= time.monotonic() - stamp <= 15
    healthy = bool(c["signed_time_enabled"] and current and fresh and status.get("healthy") is True)
    reason = ("disabled" if not c["signed_time_enabled"] else
              "restart-required" if status.get("configuration_hash") and not current else
              "status-stale-or-not-running" if not fresh else
              status.get("reason", status.get("error", "not-running")))
    settings = Path(root) / "settings.json"
    ca = public_state(settings)
    return dict(c, healthy=healthy, key_ready=bool(status.get("public_key_xy")),
                reason=reason if not healthy else "synchronized",
                public_key_xy=status.get("public_key_xy", ""),
                hostname=c["time_hostname"] or ca.get("ca_dns", ""), port=c["time_port"],
                fingerprint=status.get("fingerprint", ""))


def configuration_hash(c):
    return hashlib.sha256(json.dumps(c, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def boot_id():
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        return "unsupported-host"


def main():
    root = Path(os.environ.get("IOT_CA_DATA_ROOT", "/config/iot-ca"))
    status = root / "signed-time-status.json"
    try:
        c = load_options()
        signer = load_signer(root) if c["signed_time_enabled"] else None
    except (ValueError, TypeError, OSError):
        atomic_json(status, {"healthy": False, "error": "configuration-or-key-invalid"})
        # A time configuration fault must not take certificate services down.
        while True:
            time.sleep(60)
    if not c["signed_time_enabled"]:
        atomic_json(status, {"healthy": False})
        while True:
            time.sleep(60)
    point = signer.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)[1:]
    process = None
    stop = threading.Event()
    if c["time_source"] == "ntp":
        directory = Path("/run/iot-ca-time"); directory.mkdir(mode=0o700, exist_ok=True)
        conf = directory / "chrony.conf"; conf.write_text(chrony_config(c, directory)); conf.chmod(0o600)
        # -x forbids host-clock adjustment; no privilege escalation/CAP_SYS_TIME.
        try:
            process = subprocess.Popen(["chronyd", "-d", "-x", "-U", "-u", "root", "-f", str(conf)],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            process = None
        def sample():
            if process is None or process.poll() is not None:
                raise ValueError("Custom clock unavailable")
            result = subprocess.run(["chronyc", "-n", "-h", str(directory / "chronyd.sock"), "tracking"],
                                    check=True, timeout=1, capture_output=True, text=True, env={**os.environ, "LC_ALL": "C"})
            if len(result.stdout) > 4096:
                raise ValueError("Oversized tracking status")
            return chrony_sample(result.stdout, time.time())
    else:
        sample = host_sample
    clock = Clock(sample)
    def monitor():
        while not stop.is_set():
            clock.refresh()
            try:
                clock.now(); healthy = True
            except ValueError:
                healthy = False
            atomic_json(status, dict(healthy=healthy, reason="synchronized" if healthy else
                                     "clock-step-latched" if clock.fault else "clock-not-synchronized",
                                     configuration_hash=configuration_hash(c),
                                     public_key_xy=point.hex(),
                                     fingerprint=hashlib.sha256(point).hexdigest(),
                                     boot_id=boot_id(), monotonic=time.monotonic()))
            stop.wait(5)
    worker = threading.Thread(target=monitor, daemon=True); worker.start()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    try:
        with Server(("0.0.0.0", 9011), Authority(signer, c["time_device_macs"], clock)) as server:
            server.timeout = .5
            while not stop.is_set():
                server.handle_request()
    finally:
        stop.set(); worker.join(timeout=3)
        if process:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait()


if __name__ == "__main__":
    main()
