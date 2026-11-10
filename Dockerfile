# ========================================================
# SENTINEL CORE // Docker Production Image
# Multi-stage secure non-root container
# ========================================================

FROM python:3.11-slim as runtime

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000 \
    HOST=0.0.0.0

WORKDIR /app

# Install system utilities needed for production
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged application user
RUN groupadd -g 10001 sentinel && \
    useradd -u 10001 -g sentinel -s /bin/bash -m sentinel

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source code and web templates
COPY app/ ./app/
COPY templates/ ./templates/

# Enforce secure ownership
RUN chown -R sentinel:sentinel /app

# Switch to unprivileged runtime user
USER sentinel

# Expose default application port
EXPOSE 8000

# Container healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT}/api/health || exit 1

# Start production server
CMD ["sh", "-c", "uvicorn app.main:app --host ${HOST} --port ${PORT} --workers 2"]

