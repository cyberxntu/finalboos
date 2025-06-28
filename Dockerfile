FROM python:3.11-slim-bookworm as builder

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    libpq-dev && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install -r requirements.txt  # حذف --user هنا

FROM python:3.11-slim-bookworm

WORKDIR /app

COPY --from=builder /usr/local /usr/local  # انسخ مجلد التثبيت system-wide
COPY . .

ENV FLASK_APP=app.py
ENV FLASK_ENV=production
ENV PORT=8080
ENV PYTHONUNBUFFERED=1
ENV PATH=/usr/local/bin:$PATH  # ضبط PATH

EXPOSE 8080

CMD ["gunicorn", \
    "--bind", "0.0.0.0:8080", \
    "--workers", "4", \
    "--threads", "2", \
    "--timeout", "120", \
    "--access-logfile", "-", \
    "--error-logfile", "-", \
    "app:app"]
