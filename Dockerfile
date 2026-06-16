FROM python:3.12-slim

# Optional dependency for upstream connection pooling.
RUN pip install --no-cache-dir requests

WORKDIR /app
COPY waf.py error.html ./

# Run as non-root.
RUN useradd -r -u 10001 wafuser
USER wafuser

# Defaults (override at runtime with -e WAF_*).
ENV WAF_LISTEN_HOST=0.0.0.0 \
    WAF_LISTEN_PORT=8080 \
    WAF_TARGET_HOST=backend \
    WAF_TARGET_PORT=80 \
    WAF_LOG_JSON=true

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s \
  CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=2).status==200 else 1)"

ENTRYPOINT ["python3", "waf.py"]
