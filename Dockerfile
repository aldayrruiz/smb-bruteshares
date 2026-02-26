FROM python:3.12-slim

LABEL maintainer="Aldayr Ruiz (xSmaky)"
LABEL description="SMB Share Brute-Forcer"

# Install smbclient (system dependency)
RUN apt-get update \
    && apt-get install -y --no-install-recommends smbclient \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the script
COPY smb_bruteshares.py .

# Default: show help
ENTRYPOINT ["python3", "smb_bruteshares.py"]
CMD ["--help"]
