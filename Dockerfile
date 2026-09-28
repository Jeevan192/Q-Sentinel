# ── Stage 1: Build React Frontend ──
FROM node:20-slim AS frontend-builder
WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install
COPY frontend/ ./
RUN npm run build

# ── Stage 2: Python Backend Runtime ──
FROM python:3.11-slim AS base

LABEL maintainer="Q-SENTINEL Team"
LABEL version="9.1.0"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# Create non-root user
RUN groupadd -r qsentinel && useradd -r -g qsentinel -u 1000 qsentinel

WORKDIR /app

# Install dependencies first (for layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir uvicorn[standard]

# Copy application code — use full directories to preserve __init__.py hierarchy
COPY src/ ./src/
COPY apps/ ./apps/
COPY data/ ./data/
COPY attacker/ ./attacker/
COPY experiments/ ./experiments/
COPY --from=frontend-builder /frontend/dist ./frontend/dist

# Ensure data + credentials directories are writable by qsentinel
RUN mkdir -p /app/data /app/attacker/credentials && \
    chown -R qsentinel:qsentinel /app/data /app/attacker/credentials

# Auto-provision ML-DSA-65 credentials if private keys don't exist
# (they are .gitignore'd and must be regenerated in each container)
RUN python attacker/provision.py

USER qsentinel

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=60s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:${PORT:-8000}/v1/health')"

# Run with uvicorn — PORT is injected by Render/Railway at runtime
CMD ["sh", "-c", "python -m uvicorn apps.api.main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1"]
