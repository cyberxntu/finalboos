# Use official Python slim image
FROM python:3.11-slim-bookworm

# Set working directory
WORKDIR /app

# 1. Install dependencies first (for better layer caching)
COPY requirements.txt .

# Install system packages and clean up
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc python3-dev && \
    pip install --no-cache-dir -r requirements.txt && \
    apt-get remove -y gcc python3-dev && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# 2. Copy application files
COPY . .

# 3. Set environment variables
ENV FLASK_APP=app.py
ENV FLASK_ENV=production
ENV PORT=8080  # Changed to 8080 for Fly.io compatibility

# 4. Expose the correct port (must match PORT)
EXPOSE 8080

# 5. Run Gunicorn with secure settings
CMD ["gunicorn", \
     "--bind", "0.0.0.0:8080", \
     "--workers", "4", \
     "--threads", "2", \
     "--timeout", "120", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "app:app"]
