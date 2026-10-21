FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir . \
    && useradd --create-home --uid 10001 rdis \
    && chown -R rdis:rdis /app
USER rdis

# Cloud hosts inject the listening port via $PORT (HF Spaces: set app_port to match).
ENV PORT=8000
EXPOSE 8000

# 0.0.0.0 bind auto-enables per-visitor sessions (each visitor's uploads/edits stay private).
# --no-open: headless, don't try to launch a browser. --max-mb caps upload size on shared hosts.
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import os,urllib.request as u; u.urlopen('http://127.0.0.1:%s/' % os.environ.get('PORT', '8000'), timeout=4)"
CMD ["sh", "-c", "rdis-gui --host 0.0.0.0 --port ${PORT:-8000} --no-open --max-mb 64"]
