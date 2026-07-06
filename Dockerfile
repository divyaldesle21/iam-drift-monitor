FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    curl unzip git \
    && rm -rf /var/lib/apt/lists/*

RUN curl -s https://raw.githubusercontent.com/terraform-linters/tflint/master/install_linux.sh | bash

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY scripts/ ./scripts/

ENTRYPOINT ["python", "scripts/check_drift.py"]
