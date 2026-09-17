# Fargate sandbox container
# Runs untrusted artifact code in isolation.
# Security: non-root user, no network (enforced at VPC level), strace for syscall monitoring.

FROM python:3.11-slim

# Install strace for syscall-level monitoring and boto3 for S3/DynamoDB access
RUN apt-get update && apt-get install -y --no-install-recommends \
    strace \
    nodejs \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir boto3==1.34.0

# Create a non-root user (nobody = UID 65534)
RUN useradd -u 65534 -s /sbin/nologin nobody 2>/dev/null || true

WORKDIR /sandbox

COPY entrypoint.py /sandbox/entrypoint.py

# Run as nobody — no root privileges inside the container
USER 65534

ENTRYPOINT ["python", "/sandbox/entrypoint.py"]
