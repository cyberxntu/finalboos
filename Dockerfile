# استخدام slim مع تحديثات الأمان
FROM python:3.11-slim-bookworm

# تهيئة بيئة نظيفة
WORKDIR /app

# 1. تثبيت التبعيات أولاً (لتحسين layer caching)
COPY requirements.txt .

# تثبيت حزم النظام المطلوبة (إن وجدت)
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc python3-dev && \
    pip install --no-cache-dir -r requirements.txt && \
    apt-get remove -y gcc python3-dev && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# 2. نسخ باقي الملفات
COPY . .

# 3. تهيئة متغيرات البيئة
ENV FLASK_APP=app.py
ENV FLASK_ENV=production
ENV PORT=8080  # تغيير إلى 8080 ليتوافق مع Fly.io

# 4. المنفذ المكشوف (يجب أن يكون مطابقًا لـ PORT)
EXPOSE 8080

# 5. تشغيل Gunicorn مع إعدادات آمنة
CMD ["gunicorn", 
     "--bind", "0.0.0.0:8080",
     "--workers", "4",
     "--threads", "2",
     "--timeout", "120",
     "--access-logfile", "-",
     "--error-logfile", "-",
     "app:app"]
