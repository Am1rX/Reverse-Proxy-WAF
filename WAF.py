#!/usr/bin/env python3
"""
A lightweight reverse-proxy Web Application Firewall (WAF).

Hardened, production-leaning rewrite of a learning-grade WAF. It sits in front
of a backend HTTP server, inspects incoming requests for common web attacks
(SQLi / XSS / path traversal / command injection / common scanners), blocks or
challenges them, and transparently proxies clean traffic to the backend.

Design goals
------------
* No third-party dependencies for the core (stdlib only). `requests` is used for
  the upstream client if available, otherwise it falls back to urllib.
* Pluggable detection engine: swap `RegexDetectionEngine` for ModSecurity/Coraza
  later without touching the proxy.
* Safe-by-default: bounded body sizes, TLS 1.2+, per-IP rate limiting, structured
  JSON logging, correct handling of compressed/binary responses.
* Configuration via environment variables / CLI / YAML-free file, NOT interactive
  prompts (so it can run under systemd / Docker). Interactive mode is opt-in.

IMPORTANT — read this before trusting it in production
------------------------------------------------------
A regex-based WAF is a *speed bump*, not a wall. Determined attackers can bypass
signature matching. For real production protection, put this behind (or replace
with) a mature engine such as **ModSecurity + OWASP CRS** or **Coraza**, and
treat this as a first filtering layer + learning tool. The detection engine here
is intentionally pluggable so you can wire in a stronger one.
"""

from __future__ import annotations

import argparse
import base64
import gzip
import html
import json
import logging
import os
import re
import signal
import socket
import socketserver
import ssl
import sys
import threading
import time
import zlib
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from typing import Iterable, Optional
from urllib.parse import unquote, unquote_plus, urlsplit, urlunsplit

# ---------------------------------------------------------------------------
# Optional upstream HTTP client. Prefer `requests` (connection pooling), but
# degrade gracefully to urllib so the file runs with zero dependencies.
# ---------------------------------------------------------------------------
try:
    import requests  # type: ignore
    from requests.adapters import HTTPAdapter  # type: ignore

    try:
        from urllib3.util.retry import Retry  # type: ignore
    except Exception:  # pragma: no cover
        Retry = None  # type: ignore
    _HAVE_REQUESTS = True
except Exception:  # pragma: no cover
    _HAVE_REQUESTS = False


# ===========================================================================
# Configuration
# ===========================================================================
@dataclass
class Config:
    # Listener
    listen_host: str = "0.0.0.0"
    listen_port: int = 8080

    # Upstream (the app being protected)
    target_scheme: str = "http"
    target_host: str = "127.0.0.1"
    target_port: int = 80

    # TLS termination at the WAF
    ssl_enabled: bool = False
    cert_file: str = "cert.pem"
    key_file: str = "key.pem"

    # Reverse-proxy URL rewriting. The public host clients use to reach the WAF.
    # Used to rewrite Location / Set-Cookie / (optionally) HTML bodies so the
    # backend's own hostname doesn't leak through.
    public_host: str = ""           # e.g. "waf.example.com" (empty = no rewrite)
    rewrite_html_bodies: bool = False  # rewrite backend host inside text/html

    # Limits / hardening
    max_request_body: int = 10 * 1024 * 1024   # 10 MiB
    max_response_body: int = 25 * 1024 * 1024   # 25 MiB (buffered for rewrite)
    upstream_timeout: float = 15.0
    socket_timeout: float = 20.0                # Slowloris mitigation
    verify_upstream_tls: bool = True            # verify backend cert if https

    # Detection
    blocking_enabled: bool = True               # False = detect-only (log, allow)
    block_status: int = 403
    block_page_file: str = "error.html"

    # Rate limiting (token bucket per client IP)
    rate_limit_enabled: bool = True
    rate_limit_rps: float = 20.0                # sustained requests/sec/IP
    rate_limit_burst: int = 40                  # bucket capacity

    # Trust X-Forwarded-For from these proxy IPs (CIDR not supported; exact IPs).
    trusted_proxies: tuple[str, ...] = ()

    # Logging
    log_level: str = "INFO"
    log_json: bool = True

    @property
    def target_base(self) -> str:
        return f"{self.target_scheme}://{self.target_host}:{self.target_port}"

    @classmethod
    def from_env_and_args(cls) -> "Config":
        c = cls()

        # --- environment overrides ---
        def env(name: str, default: Optional[str] = None) -> Optional[str]:
            return os.environ.get(name, default)

        def env_bool(name: str, default: bool) -> bool:
            v = os.environ.get(name)
            if v is None:
                return default
            return v.strip().lower() in ("1", "true", "yes", "on")

        c.listen_host = env("WAF_LISTEN_HOST", c.listen_host)
        c.listen_port = int(env("WAF_LISTEN_PORT", str(c.listen_port)))
        c.target_scheme = env("WAF_TARGET_SCHEME", c.target_scheme)
        c.target_host = env("WAF_TARGET_HOST", c.target_host)
        c.target_port = int(env("WAF_TARGET_PORT", str(c.target_port)))
        c.ssl_enabled = env_bool("WAF_SSL", c.ssl_enabled)
        c.cert_file = env("WAF_CERT_FILE", c.cert_file)
        c.key_file = env("WAF_KEY_FILE", c.key_file)
        c.public_host = env("WAF_PUBLIC_HOST", c.public_host)
        c.rewrite_html_bodies = env_bool("WAF_REWRITE_HTML", c.rewrite_html_bodies)
        c.blocking_enabled = env_bool("WAF_BLOCKING", c.blocking_enabled)
        c.verify_upstream_tls = env_bool("WAF_VERIFY_UPSTREAM", c.verify_upstream_tls)
        c.rate_limit_enabled = env_bool("WAF_RATE_LIMIT", c.rate_limit_enabled)
        c.log_level = env("WAF_LOG_LEVEL", c.log_level)
        c.log_json = env_bool("WAF_LOG_JSON", c.log_json)
        tp = env("WAF_TRUSTED_PROXIES", "")
        if tp:
            c.trusted_proxies = tuple(x.strip() for x in tp.split(",") if x.strip())

        # --- CLI overrides (highest priority) ---
        p = argparse.ArgumentParser(description="Reverse-proxy WAF")
        p.add_argument("--listen-host")
        p.add_argument("--listen-port", type=int)
        p.add_argument("--target-host")
        p.add_argument("--target-port", type=int)
        p.add_argument("--target-scheme", choices=["http", "https"])
        p.add_argument("--ssl", dest="ssl_enabled", action="store_true")
        p.add_argument("--no-ssl", dest="ssl_enabled", action="store_false")
        p.add_argument("--cert-file")
        p.add_argument("--key-file")
        p.add_argument("--public-host")
        p.add_argument("--detect-only", dest="blocking_enabled",
                       action="store_false", help="log attacks but do not block")
        p.add_argument("--interactive", action="store_true",
                       help="prompt for config interactively")
        p.set_defaults(ssl_enabled=None, blocking_enabled=None)
        args, _ = p.parse_known_args()

        if args.interactive:
            return cls._interactive(c)

        for name in ("listen_host", "listen_port", "target_host", "target_port",
                     "target_scheme", "cert_file", "key_file", "public_host"):
            val = getattr(args, name)
            if val is not None:
                setattr(c, name, val)
        if args.ssl_enabled is not None:
            c.ssl_enabled = args.ssl_enabled
        if args.blocking_enabled is not None:
            c.blocking_enabled = args.blocking_enabled
        return c

    @staticmethod
    def _interactive(c: "Config") -> "Config":
        print("--- WAF interactive configuration ---")
        mode = input("Protocol  1) HTTP  2) HTTPS  [1]: ").strip() or "1"
        c.ssl_enabled = (mode == "2")
        c.listen_port = int(input(f"WAF listen port [{443 if c.ssl_enabled else 8080}]: ").strip()
                            or (443 if c.ssl_enabled else 8080))
        c.target_host = input(f"Backend host [{c.target_host}]: ").strip() or c.target_host
        c.target_port = int(input(f"Backend port [{c.target_port}]: ").strip() or c.target_port)
        c.public_host = input("Public host for URL rewriting (optional): ").strip()
        if c.ssl_enabled:
            c.cert_file = input(f"TLS cert path [{c.cert_file}]: ").strip() or c.cert_file
            c.key_file = input(f"TLS key path [{c.key_file}]: ").strip() or c.key_file
        return c


# ===========================================================================
# Structured logging
# ===========================================================================
class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)),
            "level": record.levelname,
            "msg": record.getMessage(),
        }
        extra = getattr(record, "extra_fields", None)
        if extra:
            payload.update(extra)
        return json.dumps(payload, ensure_ascii=False)


def build_logger(cfg: Config) -> logging.Logger:
    logger = logging.getLogger("waf")
    logger.setLevel(getattr(logging, cfg.log_level.upper(), logging.INFO))
    logger.handlers.clear()
    h = logging.StreamHandler(sys.stdout)
    if cfg.log_json:
        h.setFormatter(JsonFormatter())
    else:
        h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(h)
    logger.propagate = False
    return logger


def log_event(logger: logging.Logger, level: int, msg: str, **fields) -> None:
    logger.log(level, msg, extra={"extra_fields": fields})


# ===========================================================================
# Detection engine
# ===========================================================================
@dataclass
class Finding:
    rule_id: str
    category: str
    location: str            # where it matched: path / query / body / header:x
    score: int
    snippet: str


@dataclass
class Verdict:
    blocked: bool
    score: int
    findings: list[Finding] = field(default_factory=list)


class DetectionEngine:
    """Interface. Implement `inspect()` to plug in any engine."""

    def inspect(self, *, method: str, path: str, query: str,
                headers: dict[str, str], body: bytes) -> Verdict:
        raise NotImplementedError


def _normalize(value: str) -> str:
    """
    Defeat common evasion: multi-pass percent decoding, HTML entity decoding,
    strip SQL inline comments, collapse whitespace, lowercase.
    Bounded to avoid decode loops.
    """
    if not value:
        return ""
    prev = value
    for _ in range(3):                       # bounded multi-pass URL decode
        cur = unquote_plus(prev)
        cur = unquote(cur)
        if cur == prev:
            break
        prev = cur
    text = html.unescape(prev)
    text = text.replace("\x00", "")          # null-byte evasion
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)  # SQL inline comments
    text = re.sub(r"\s+", " ", text)
    return text.lower()


class RegexDetectionEngine(DetectionEngine):
    """
    Scored signature engine. Each request part is normalized then matched
    against weighted rules. A request is blocked when total score >= threshold.
    Scoring (instead of single-hit) reduces false positives from any one weak rule.
    """

    THRESHOLD = 5

    # (rule_id, category, weight, compiled_regex)
    def __init__(self) -> None:
        raw: list[tuple[str, str, int, str]] = [
            # --- SQL injection ---
            ("SQLI-UNION", "sqli", 5, r"\bunion\b[\s\S]{0,40}\bselect\b"),
            ("SQLI-BOOL", "sqli", 5,
             r"(['\"]?\s*\b(or|and)\b\s*['\"]?\s*\d+\s*['\"]?\s*=\s*['\"]?\s*\d+)"),
            ("SQLI-COMMENT", "sqli", 3, r"(--\s|#\s*$|;\s*--)"),
            ("SQLI-FUNC", "sqli", 5,
             r"\b(sleep|benchmark|pg_sleep|waitfor\s+delay|load_file|extractvalue|updatexml)\s*\("),
            ("SQLI-STACK", "sqli", 4,
             r";\s*\b(drop|insert|update|delete|create|alter|truncate|grant)\b"),
            ("SQLI-INFO", "sqli", 3,
             r"\b(information_schema|sysobjects|pg_catalog|mysql\.user)\b"),
            # --- XSS ---
            ("XSS-SCRIPT", "xss", 5, r"<\s*script[\s\S]{0,200}?>"),
            ("XSS-EVENT", "xss", 4, r"\bon[a-z]{3,15}\s*=\s*['\"]?[^'\">]*\("),
            ("XSS-JSURI", "xss", 4, r"javascript\s*:"),
            ("XSS-SVG", "xss", 3, r"<\s*(svg|img|iframe|body|video)[\s\S]{0,80}?on[a-z]+\s*="),
            ("XSS-EVAL", "xss", 3, r"\b(eval|document\.cookie|window\.location)\b"),
            # --- Path traversal / LFI ---
            ("LFI-TRAVERSE", "lfi", 5, r"(\.\.[\\/]){2,}"),
            ("LFI-ETC", "lfi", 5, r"(/etc/passwd|/etc/shadow|boot\.ini|win\.ini)"),
            ("LFI-WRAP", "lfi", 4, r"\b(php|file|data|expect|phar)://"),
            # --- Command injection ---
            ("CMDI-CHAIN", "cmdi", 4,
             r"[;&|`]\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh|python|powershell)\b"),
            ("CMDI-SUBST", "cmdi", 4, r"\$\([^)]+\)|`[^`]+`"),
            # --- Scanners / tooling ---
            ("SCAN-UA", "scanner", 5,
             r"\b(sqlmap|nikto|nmap|acunetix|nessus|masscan|dirbuster|gobuster|wpscan)\b"),
        ]
        self.rules = [
            (rid, cat, w, re.compile(rx, re.IGNORECASE))
            for (rid, cat, w, rx) in raw
        ]

    def _scan(self, location: str, value: str, out: list[Finding]) -> None:
        norm = _normalize(value)
        if not norm:
            return
        for rid, cat, weight, rx in self.rules:
            m = rx.search(norm)
            if m:
                out.append(Finding(
                    rule_id=rid, category=cat, location=location,
                    score=weight, snippet=m.group(0)[:80],
                ))

    def inspect(self, *, method, path, query, headers, body) -> Verdict:
        findings: list[Finding] = []
        self._scan("path", path, findings)
        self._scan("query", query, findings)

        # Inspect security-relevant headers (UA for scanners, cookie/referer values)
        for hname in ("user-agent", "referer", "cookie", "x-forwarded-for"):
            hval = headers.get(hname)
            if hval:
                self._scan(f"header:{hname}", hval, findings)

        # Inspect body for textual content types only.
        ctype = (headers.get("content-type") or "").lower()
        if body and ("json" in ctype or "form" in ctype or "text" in ctype
                     or "xml" in ctype or ctype == ""):
            try:
                self._scan("body", body.decode("utf-8", errors="ignore"), findings)
            except Exception:
                pass

        total = sum(f.score for f in findings)
        return Verdict(blocked=total >= self.THRESHOLD, score=total, findings=findings)


# ===========================================================================
# Rate limiting (token bucket per client IP)
# ===========================================================================
class RateLimiter:
    def __init__(self, rps: float, burst: int) -> None:
        self.rps = rps
        self.burst = burst
        self._buckets: dict[str, tuple[float, float]] = {}  # ip -> (tokens, ts)
        self._lock = threading.Lock()

    def allow(self, ip: str) -> bool:
        now = time.monotonic()
        with self._lock:
            tokens, ts = self._buckets.get(ip, (float(self.burst), now))
            tokens = min(self.burst, tokens + (now - ts) * self.rps)
            if tokens >= 1.0:
                self._buckets[ip] = (tokens - 1.0, now)
                return True
            self._buckets[ip] = (tokens, now)
            return False

    def sweep(self, max_entries: int = 100_000) -> None:
        # crude memory guard
        with self._lock:
            if len(self._buckets) > max_entries:
                self._buckets.clear()


# ===========================================================================
# Upstream client abstraction
# ===========================================================================
class UpstreamResponse:
    def __init__(self, status: int, headers: list[tuple[str, str]], body: bytes):
        self.status = status
        self.headers = headers
        self.body = body


class UpstreamClient:
    HOP_BY_HOP = {
        "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
        "te", "trailers", "transfer-encoding", "upgrade", "content-encoding",
        "content-length",
    }

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._session = None
        if _HAVE_REQUESTS:
            s = requests.Session()
            adapter_kwargs = {"pool_connections": 20, "pool_maxsize": 50}
            if Retry is not None:
                adapter_kwargs["max_retries"] = Retry(
                    total=2, backoff_factor=0.2,
                    status_forcelist=(502, 503, 504),
                    allowed_methods=frozenset(["GET", "HEAD", "OPTIONS"]),
                )
            s.mount("http://", HTTPAdapter(**adapter_kwargs))
            s.mount("https://", HTTPAdapter(**adapter_kwargs))
            self._session = s

    def fetch(self, method: str, path: str, headers: dict[str, str],
              body: bytes) -> UpstreamResponse:
        url = f"{self.cfg.target_base}{path}"
        fwd = {k: v for k, v in headers.items()
               if k.lower() not in self.HOP_BY_HOP}
        fwd["Host"] = f"{self.cfg.target_host}:{self.cfg.target_port}" \
            if self.cfg.target_port not in (80, 443) else self.cfg.target_host

        if self._session is not None:
            resp = self._session.request(
                method, url, headers=fwd, data=body or None,
                allow_redirects=False, timeout=self.cfg.upstream_timeout,
                verify=self.cfg.verify_upstream_tls, stream=False,
            )
            # requests transparently decompresses .content; encoding header dropped.
            out_headers = [(k, v) for k, v in resp.headers.items()
                           if k.lower() not in self.HOP_BY_HOP]
            return UpstreamResponse(resp.status_code, out_headers, resp.content)

        # urllib fallback ----------------------------------------------------
        import urllib.request
        import urllib.error
        req = urllib.request.Request(url, data=body or None, method=method)
        for k, v in fwd.items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=self.cfg.upstream_timeout) as r:
                raw = r.read()
                enc = (r.headers.get("Content-Encoding") or "").lower()
                raw = _maybe_decompress(raw, enc)
                hdrs = [(k, v) for k, v in r.headers.items()
                        if k.lower() not in self.HOP_BY_HOP]
                return UpstreamResponse(r.status, hdrs, raw)
        except urllib.error.HTTPError as e:
            raw = e.read()
            enc = (e.headers.get("Content-Encoding") or "").lower()
            raw = _maybe_decompress(raw, enc)
            hdrs = [(k, v) for k, v in e.headers.items()
                    if k.lower() not in self.HOP_BY_HOP]
            return UpstreamResponse(e.code, hdrs, raw)


def _maybe_decompress(data: bytes, encoding: str) -> bytes:
    try:
        if encoding == "gzip":
            return gzip.decompress(data)
        if encoding == "deflate":
            try:
                return zlib.decompress(data)
            except zlib.error:
                return zlib.decompress(data, -zlib.MAX_WBITS)
    except Exception:
        return data
    return data


# ===========================================================================
# Request handler
# ===========================================================================
class WAFHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "waf"
    sys_version = ""  # don't leak Python version

    # injected by the server factory
    cfg: Config = None          # type: ignore
    engine: DetectionEngine = None  # type: ignore
    limiter: Optional[RateLimiter] = None
    upstream: UpstreamClient = None  # type: ignore
    logger: logging.Logger = None    # type: ignore

    # --- helpers ---------------------------------------------------------
    def _client_ip(self) -> str:
        peer = self.client_address[0]
        if peer in self.cfg.trusted_proxies:
            xff = self.headers.get("X-Forwarded-For")
            if xff:
                return xff.split(",")[0].strip()
        return peer

    def _send_simple(self, status: int, body: bytes,
                     content_type: str = "text/html; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _block(self, verdict: Verdict, client_ip: str) -> None:
        log_event(self.logger, logging.WARNING, "request blocked",
                  ip=client_ip, method=self.command, path=self.path,
                  score=verdict.score,
                  rules=[f.rule_id for f in verdict.findings],
                  categories=sorted({f.category for f in verdict.findings}))
        body = b"<h1>403 Forbidden</h1><p>Request blocked by WAF.</p>"
        try:
            if os.path.isfile(self.cfg.block_page_file):
                with open(self.cfg.block_page_file, "rb") as f:
                    body = f.read()
        except OSError:
            pass
        self._send_simple(self.cfg.block_status, body)

    def _rewrite_location(self, value: str) -> str:
        if not self.cfg.public_host:
            return value
        parts = urlsplit(value)
        if parts.netloc and self.cfg.target_host in parts.netloc:
            netloc = self.cfg.public_host
            scheme = "https" if self.cfg.ssl_enabled else "http"
            return urlunsplit((scheme, netloc, parts.path, parts.query, parts.fragment))
        return value

    def _rewrite_setcookie(self, value: str) -> str:
        # strip Domain attribute so cookies bind to the WAF host
        parts = [p.strip() for p in value.split(";")]
        kept = [p for p in parts if not p.lower().startswith("domain=")]
        return "; ".join(kept)

    # --- core ------------------------------------------------------------
    def _handle(self, method: str) -> None:
        client_ip = self._client_ip()

        # health check endpoint (never proxied)
        if self.path in ("/healthz", "/waf/health"):
            self._send_simple(200, b'{"status":"ok"}',
                              "application/json")
            return

        # rate limit
        if self.limiter is not None and not self.limiter.allow(client_ip):
            log_event(self.logger, logging.WARNING, "rate limited", ip=client_ip)
            self._send_simple(429, b"<h1>429 Too Many Requests</h1>")
            return

        # read body with hard cap
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = 0
        if length > self.cfg.max_request_body:
            self._send_simple(413, b"<h1>413 Payload Too Large</h1>")
            return
        body = b""
        if length > 0:
            try:
                body = self.rfile.read(length)
            except (ConnectionResetError, TimeoutError, socket.timeout):
                return

        # split path/query
        split = urlsplit(self.path)
        headers = {k.lower(): v for k, v in self.headers.items()}

        # inspect
        verdict = self.engine.inspect(
            method=method, path=split.path, query=split.query,
            headers=headers, body=body,
        )
        if verdict.blocked:
            if self.cfg.blocking_enabled:
                self._block(verdict, client_ip)
                return
            log_event(self.logger, logging.WARNING, "attack detected (detect-only)",
                      ip=client_ip, path=self.path, score=verdict.score,
                      rules=[f.rule_id for f in verdict.findings])

        # proxy to upstream
        try:
            resp = self.upstream.fetch(method, self.path, dict(self.headers), body)
        except Exception as e:  # noqa: BLE001
            log_event(self.logger, logging.ERROR, "upstream error",
                      ip=client_ip, path=self.path, error=str(e))
            self._send_simple(502, b"<h1>502 Bad Gateway</h1>")
            return

        content = resp.body
        if len(content) > self.cfg.max_response_body:
            content = content[: self.cfg.max_response_body]

        # optional HTML host rewrite (text only)
        ctype = next((v for k, v in resp.headers if k.lower() == "content-type"), "")
        if (self.cfg.rewrite_html_bodies and self.cfg.public_host
                and "text/html" in ctype.lower()):
            content = content.replace(self.cfg.target_host.encode(),
                                      self.cfg.public_host.encode())

        # write response
        self.send_response(resp.status)
        for k, v in resp.headers:
            lk = k.lower()
            if lk == "location":
                v = self._rewrite_location(v)
            elif lk == "set-cookie":
                v = self._rewrite_setcookie(v)
            self.send_header(k, v)
        # security headers (don't override if backend already set them)
        present = {k.lower() for k, _ in resp.headers}
        if "x-content-type-options" not in present:
            self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        try:
            if method != "HEAD":
                self.wfile.write(content)
        except (BrokenPipeError, ConnectionResetError):
            pass

    # method dispatch
    def do_GET(self):      self._handle("GET")
    def do_POST(self):     self._handle("POST")
    def do_PUT(self):      self._handle("PUT")
    def do_DELETE(self):   self._handle("DELETE")
    def do_PATCH(self):    self._handle("PATCH")
    def do_HEAD(self):     self._handle("HEAD")
    def do_OPTIONS(self):  self._handle("OPTIONS")

    # quiet default logging (we log ourselves)
    def log_message(self, fmt, *args):  # noqa: A003
        return


# ===========================================================================
# Server
# ===========================================================================
class ThreadedHTTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128

    def __init__(self, cfg: Config, handler_cls):
        self.cfg = cfg
        super().__init__((cfg.listen_host, cfg.listen_port), handler_cls)

    def get_request(self):
        sock, addr = super().get_request()
        sock.settimeout(self.cfg.socket_timeout)  # Slowloris mitigation
        return sock, addr


def build_ssl_context(cfg: Config) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=cfg.cert_file, keyfile=cfg.key_file)
    try:
        ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM")
    except ssl.SSLError:
        pass
    return ctx


def run(cfg: Config) -> None:
    logger = build_logger(cfg)

    engine = RegexDetectionEngine()
    limiter = RateLimiter(cfg.rate_limit_rps, cfg.rate_limit_burst) \
        if cfg.rate_limit_enabled else None
    upstream = UpstreamClient(cfg)

    handler_cls = type("BoundWAFHandler", (WAFHandler,), {
        "cfg": cfg, "engine": engine, "limiter": limiter,
        "upstream": upstream, "logger": logger,
    })

    server = ThreadedHTTPServer(cfg, handler_cls)

    if cfg.ssl_enabled:
        try:
            ctx = build_ssl_context(cfg)
        except FileNotFoundError:
            logger.error("TLS cert/key not found: %s / %s",
                         cfg.cert_file, cfg.key_file)
            return
        except ssl.SSLError as e:
            logger.error("TLS error: %s", e)
            return
        server.socket = ctx.wrap_socket(server.socket, server_side=True)

    log_event(logger, logging.INFO, "WAF started",
              listen=f"{cfg.listen_host}:{cfg.listen_port}",
              tls=cfg.ssl_enabled, target=cfg.target_base,
              blocking=cfg.blocking_enabled,
              upstream_client="requests" if _HAVE_REQUESTS else "urllib")

    stop = threading.Event()

    def shutdown(signum, frame):  # noqa: ARG001
        log_event(logger, logging.INFO, "shutting down", signal=signum)
        stop.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    # Signal handlers only work in the main thread; skip when embedded.
    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGINT, shutdown)
        signal.signal(signal.SIGTERM, shutdown)

    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
        log_event(logger, logging.INFO, "stopped")


if __name__ == "__main__":
    run(Config.from_env_and_args())
