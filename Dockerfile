# Lambda container image for the scanner pipeline.
# Packages bandit, semgrep, pip-audit, and gitleaks into the image
# so they are available as subprocess calls inside Lambda.

FROM public.ecr.aws/lambda/python:3.11

# Install system dependencies
RUN dnf install -y git tar gzip && dnf clean all

# Install Python scanner tools
RUN pip install --no-cache-dir \
    bandit==1.7.9 \
    semgrep==1.72.0 \
    pip-audit==2.7.3 \
    boto3==1.34.0 \
    pydantic==2.7.0 \
    strands-agents==0.1.0 \
    strands-agents-tools==0.1.0

# Install gitleaks (Go binary — download prebuilt release)
RUN curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz \
    | tar -xz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks

# Copy scanner source code
COPY . /var/task/

CMD ["scanner.gateway.handler.handler"]
