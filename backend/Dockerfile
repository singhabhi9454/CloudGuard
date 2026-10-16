# CloudGuard Backend Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Prevent python from writing pyc files and buffer stdout
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    sqlite3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source modules
COPY backend/ ./backend/
COPY scanner/ ./scanner/
COPY rules/ ./rules/
COPY database/ ./database/
COPY reports/ ./reports/

EXPOSE 8000

# Run FastAPI backend
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
