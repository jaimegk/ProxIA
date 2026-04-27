FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY tests/ ./tests/
COPY scripts/ ./scripts/

# Vault data is stored in a volume — survives container restarts
VOLUME ["/app/data"]

ENV DATA_DIR=/app/data
ENV DATABASE_PATH=/app/data/pii_vault.db
ENV OLLAMA_HOST=http://ollama:11434
ENV ANTHROPIC_API_URL=https://api.anthropic.com
ENV PORT=5555
ENV HOST=0.0.0.0

EXPOSE 5555

HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
    CMD curl -sf http://localhost:${PORT}/health || exit 1

CMD ["sh", "-c", "uvicorn src.main:app --host 0.0.0.0 --port ${PORT} --log-level info"]
