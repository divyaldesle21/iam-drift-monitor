FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    curl unzip git \
    && rm -rf /var/lib/apt/lists/*

# Install TFLint
RUN curl -s https://raw.githubusercontent.com/terraform-linters/tflint/master/install_linux.sh | bash

# Install OPA binary
RUN curl -L -o /usr/local/bin/opa \
    https://openpolicyagent.org/downloads/v0.63.0/opa_linux_amd64_static \
    && chmod +x /usr/local/bin/opa

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy scripts and policies
COPY scripts/ ./scripts/
COPY policies/ ./policies/

ENTRYPOINT ["python", "scripts/check_drift.py"]