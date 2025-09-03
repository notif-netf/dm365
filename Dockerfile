# === Build Stage ===
FROM python:3.10-slim as builder

# Install system dependencies
RUN apt-get update && \
    apt-get install -y tesseract-ocr chromium-driver chromium-browser fonts-liberation && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python packages
COPY requirements.txt .
RUN pip install --user -r requirements.txt

# === Runtime Stage ===
FROM python:3.10-slim

# Install only runtime system deps
RUN apt-get update && \
    apt-get install -y tesseract-ocr chromium-driver chromium-browser fonts-liberation && \
    rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder stage
COPY --from=builder /root/.local /root/.local

# Set environment so Python and Gunicorn can find packages
ENV PATH=/root/.local/bin:$PATH \
    PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Copy app code
COPY . .

# Expose port
EXPOSE 5000

# Run app with Gunicorn
CMD ["gunicorn", "main:app", "--bind", "0.0.0.0:5000"]
