FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    FLASK_ENV=production \
    USER_CONFIG_FILE=/app/data/user_config.json \
    FRAUD_LOG_FILE=/app/logs/fraud_decisions.jsonl

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install -r requirements.txt

COPY . .

RUN mkdir -p /app/data /app/logs \
    && adduser --disabled-password --gecos "" appuser \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 2000

CMD ["gunicorn", "--bind", "0.0.0.0:2000", "--workers", "1", "--threads", "4", "--timeout", "120", "app:app"]
