FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir .

# Cloud hosts inject the listening port via $PORT (HF Spaces: set app_port to match).
ENV PORT=8000
EXPOSE 8000

# 0.0.0.0 bind auto-enables per-visitor sessions (each visitor's uploads/edits stay private).
# --no-open: headless, don't try to launch a browser. --max-mb caps upload size on shared hosts.
CMD ["sh", "-c", "rdis-gui --host 0.0.0.0 --port ${PORT:-8000} --no-open --max-mb 64"]
