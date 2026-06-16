# Reverse-Proxy WAF

A lightweight, dependency-optional **Web Application Firewall** that sits in front
of your backend HTTP server, inspects incoming traffic for common web attacks,
blocks or logs them, and transparently proxies clean requests upstream.

This is a hardened rewrite of a learning-grade WAF. It is suitable as a **first
filtering layer** and a **teaching/portfolio project**. For high-stakes
production it should sit alongside (or behind) a mature engine — see *Limitations*.

## Features

- **Attack detection** — scored signature engine covering SQL injection, XSS,
  path traversal / LFI, command injection, and known scanner tooling. Scoring
  (not single-hit) reduces false positives.
- **Evasion resistance** — multi-pass URL decoding, HTML-entity decoding, SQL
  comment stripping, null-byte and case normalization before matching.
- **Inspects everything** — path, query string, request body (JSON/form/text),
  and security-relevant headers (User-Agent, Referer, Cookie, X-Forwarded-For).
- **Correct proxying** — handles gzip/deflate responses, leaves binary bodies
  untouched, strips hop-by-hop headers, rewrites `Location` and `Set-Cookie`.
- **Hardening** — TLS 1.2+ termination, bounded request/response sizes,
  per-IP token-bucket rate limiting, Slowloris socket timeouts, no version leak.
- **Operability** — structured JSON logging, `/healthz` endpoint, graceful
  shutdown, env/CLI/interactive config, detect-only mode, Docker-ready.
- **Zero required dependencies** — runs on the stdlib; uses `requests` for
  connection pooling if installed, otherwise falls back to `urllib`.
- **Pluggable engine** — swap `RegexDetectionEngine` for ModSecurity/Coraza by
  implementing the `DetectionEngine` interface.

## Quick start

```bash
# Plain HTTP, protecting a backend on 10.0.0.5:8000
python3 waf.py --listen-port 8080 --target-host 10.0.0.5 --target-port 8000
```

```bash
# HTTPS termination at the WAF
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
python3 waf.py --ssl --listen-port 8443 \
  --cert-file cert.pem --key-file key.pem \
  --target-host 127.0.0.1 --target-port 8000
```

```bash
# Interactive prompts (like the original script)
python3 waf.py --interactive
```

```bash
# Detect-only: log attacks but never block (great for tuning before enforcing)
python3 waf.py --detect-only --target-host 127.0.0.1 --target-port 8000
```

## Configuration

Precedence: **CLI flags > environment variables > defaults**.

| Env var | CLI | Default | Description |
|---|---|---|---|
| `WAF_LISTEN_HOST` | `--listen-host` | `0.0.0.0` | Bind address |
| `WAF_LISTEN_PORT` | `--listen-port` | `8080` | Listen port |
| `WAF_TARGET_HOST` | `--target-host` | `127.0.0.1` | Backend host |
| `WAF_TARGET_PORT` | `--target-port` | `80` | Backend port |
| `WAF_TARGET_SCHEME` | `--target-scheme` | `http` | `http` or `https` backend |
| `WAF_SSL` | `--ssl` / `--no-ssl` | `false` | Terminate TLS at the WAF |
| `WAF_CERT_FILE` | `--cert-file` | `cert.pem` | TLS certificate |
| `WAF_KEY_FILE` | `--key-file` | `key.pem` | TLS private key |
| `WAF_PUBLIC_HOST` | `--public-host` | _(empty)_ | Host used to rewrite `Location`/cookies/HTML |
| `WAF_REWRITE_HTML` | — | `false` | Rewrite backend host inside `text/html` bodies |
| `WAF_BLOCKING` | `--detect-only` | `true` | Enforce blocks (`false` = log only) |
| `WAF_VERIFY_UPSTREAM` | — | `true` | Verify backend TLS cert (if https) |
| `WAF_RATE_LIMIT` | — | `true` | Enable per-IP rate limiting |
| `WAF_TRUSTED_PROXIES` | — | _(empty)_ | Comma-separated IPs whose `X-Forwarded-For` is trusted |
| `WAF_LOG_LEVEL` | — | `INFO` | Log level |
| `WAF_LOG_JSON` | — | `true` | JSON vs plain logs |

Tunable in code (`Config`): `max_request_body`, `max_response_body`,
`upstream_timeout`, `socket_timeout`, `rate_limit_rps`, `rate_limit_burst`,
`block_status`, `block_page_file`.

## Docker

```bash
docker build -t waf .
docker run -p 8080:8080 \
  -e WAF_TARGET_HOST=backend -e WAF_TARGET_PORT=8000 \
  --name waf waf
```

## systemd

```ini
# /etc/systemd/system/waf.service
[Unit]
Description=Reverse-proxy WAF
After=network.target

[Service]
Environment=WAF_LISTEN_PORT=8080
Environment=WAF_TARGET_HOST=127.0.0.1
Environment=WAF_TARGET_PORT=8000
ExecStart=/usr/bin/python3 /opt/waf/waf.py
Restart=always
DynamicUser=yes
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
```

## How detection works

Each request part is **normalized** (decode → de-entity → strip comments →
lowercase) and matched against weighted rules. A request is blocked only when the
**combined score** reaches the threshold (default 5), so a single weak signal
won't cause a false positive but a clear attack will. Tune weights/threshold in
`RegexDetectionEngine`.

Use `--detect-only` in production first, watch the logs for false positives on
your real traffic, adjust, then switch to enforcing.

## Plugging in a stronger engine

```python
class MyEngine(waf.DetectionEngine):
    def inspect(self, *, method, path, query, headers, body):
        ...
        return waf.Verdict(blocked=..., score=..., findings=[...])
```

Then pass it where `RegexDetectionEngine()` is constructed in `run()`.

## Limitations (read before production)

- A signature/regex WAF is a **speed bump, not a wall**. Skilled attackers can
  craft bypasses. For serious production protection, run **ModSecurity + OWASP
  CRS**, **Coraza**, or a cloud WAF — and treat this as a complementary first
  layer.
- Bodies are buffered up to `max_response_body` for rewriting; this is not a
  streaming proxy for very large downloads (raise the cap or disable rewrite).
- The threaded stdlib server is fine for low/medium traffic. For high
  concurrency, front it with nginx/HAProxy or move to an async runtime.
- This does not replace input validation, parameterized queries, output
  encoding, CSP, and authentication in your application. Defense in depth.

## License

Provided as-is. Add your preferred license.
