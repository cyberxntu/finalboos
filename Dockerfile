FROM python:3.11-slim-bookworm@sha256:1d849ea9a5d...

RUN useradd -m appuser && \
    mkdir -p /app && \
    chown appuser:appuser /app

WORKDIR /app

RUN apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY --chown=appuser:appuser requirements-secure.txt .

RUN pip install --no-cache-dir \
    --require-hashes \
    -r requirements-secure.txt && \
    pip check

COPY --chown=appuser:appuser . .

USER appuser

ENV PYTHONUNBUFFERED=1 \
    PORT=8080 \
    GUNICORN_CMD_ARGS="--worker-tmp-dir /dev/shm --workers 4 --threads 2 --timeout 120"

EXPOSE 8080

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--access-logfile", "-", "app:app"]
