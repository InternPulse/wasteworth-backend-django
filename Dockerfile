# Use official Python slim image
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    gcc \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Set work directory
WORKDIR /app

# Copy dependencies first for caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Copy wait-for-db script and make it executable
COPY wait-for-db.sh .
RUN chmod +x wait-for-db.sh

# Default command
CMD ["./wait-for-db.sh", "db", "python", "manage.py", "runserver", "0.0.0.0:8000"]