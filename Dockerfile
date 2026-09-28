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

# Security: don't buffer output, don't write .pyc
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

# Copy application code
COPY src/ ./src/
COPY apps/api/ ./apps/api/
COPY data/ ./data/
COPY attacker/ ./attacker/
COPY experiments/ ./experiments/
COPY --from=frontend-builder /frontend/dist ./frontend/dist

# Ensure data directory exists and is writable by qsentinel
RUN mkdir -p /app/data && chown -R qsentinel:qsentinel /app/data

# Switch to non-root user
USER qsentinel

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=5s --retries=5 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/v1/health')"

# Run with uvicorn (respects dynamic cloud $PORT, falls back to 8000)
CMD ["sh", "-c", "python -m uvicorn apps.api.main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1"]
