# Use Python 3.14 slim image as base
FROM python:3.14-slim

# Set working directory
WORKDIR /app

# Install system dependencies that may be needed by pwntools
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    git \
    build-essential \
    cmake \
    binutils \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies
RUN python -m pip install --no-cache-dir -r requirements.txt --break-system-packages

# Copy the application code
COPY . .

# Create /tmp directory for competition.json (if not already present)
RUN mkdir -p /tmp

# Set Python to run in unbuffered mode for better logging
ENV PYTHONUNBUFFERED=1

# Default command - can be overridden at runtime
# Usage: docker run <image> <competition_name> [--options]
ENTRYPOINT ["python3", "main.py"]

# Example usage:
# docker build -t ctf-flag-submitter .
# docker run ctf-flag-submitter mock --dry-run
# docker run ctf-flag-submitter saarctf --concurrent-teams-per-script 20
