# Minimal image that runs tests (pytest) by default
FROM python:3.11-slim

WORKDIR /app

# Copy and install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Environment: disable ZK, ensure UTF-8 logs
ENV NOPE_ZK_CHECK=0 \
    NOPE_ZK_ENFORCE=0 \
    PYTHONIOENCODING=utf-8

# Default command: run tests quietly (you can override in docker run/compose)
CMD ["pytest", "-q"]
