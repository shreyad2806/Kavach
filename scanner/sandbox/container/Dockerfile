# Fargate sandbox container
# Runs untrusted artifact code in isolation.
# Security:
# - Non-root user
# - No network (enforced at VPC level)
# - strace for syscall-level monitoring

FROM python:3.11-slim

# Install required system packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    strace \
    nodejs \
    && rm -rf /var/lib/apt/lists/*

# Install AWS SDK
RUN pip install --no-cache-dir boto3==1.34.0

# Create sandbox working directory
WORKDIR /sandbox

# Copy application entrypoint
COPY entrypoint.py /sandbox/entrypoint.py

# Run container as non-root user
USER 65534

# Start sandbox
ENTRYPOINT ["python", "/sandbox/entrypoint.py"]
