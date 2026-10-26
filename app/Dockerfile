FROM python:3.14-slim@sha256:35caba83af2fe6da9a5d922f9b0156f21d1246a48278c58a08bd253303ba42e8

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SHERLOCK_DB_PATH=/data/sherlock.db \
    SHERLOCK_APPS_FILE=/config/apps.yaml

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

COPY sherlock ./sherlock

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin sherlock \
    && mkdir -p /data /config \
    && chown 10001:10001 /data
USER 10001

EXPOSE 8000
CMD ["uvicorn", "sherlock.main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips", "10.42.0.0/16", "--no-server-header"]
