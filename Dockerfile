# =============================================================================
# Entropy LLM Firewall — Multi-stage Docker Build
# =============================================================================
FROM python:3.11-slim AS base

# Env
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ---- Dependencies stage ----
FROM base AS deps

COPY pyproject.toml ./
RUN pip install --upgrade pip && \
    pip install -e ".[dev]" 2>/dev/null || pip install -e .

# ---- Production stage ----
FROM base AS production

COPY --from=deps /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=deps /usr/local/bin /usr/local/bin

COPY . /app

# Create non-root user
RUN groupadd -r entropy && useradd --no-log-init -r -g entropy entropy
RUN chown -R entropy:entropy /app
USER entropy

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import httpx; r=httpx.get('http://localhost:8000/health'); r.raise_for_status()"

CMD ["uvicorn", "entropy.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
