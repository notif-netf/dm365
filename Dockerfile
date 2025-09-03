# === Build Stage ===
FROM python:3.10-slim as builder

# Install system dependencies
RUN apt-get update && \
    apt-get install -y tesseract-ocr chromium-driver chromium fonts-liberation && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --user -r requirements.txt

# === Runtime Stage ===
FROM python:3.10-slim

RUN apt-get update && \
    apt-get install -y tesseract-ocr chromium-driver chromium fonts-liberation && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /root/.local /root/.local

ENV PATH=/root/.local/bin:$PATH \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY . .

EXPOSE 5000

CMD ["gunicorn", "main:app", "--bind", "0.0.0.0:5000"]
