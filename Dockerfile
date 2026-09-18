# Lambda container image for the scanner pipeline.
# Packages bandit, semgrep, pip-audit, and gitleaks into the image
# so they are available as subprocess calls inside Lambda.

FROM public.ecr.aws/lambda/python:3.11

# ------------------------------------------------------------
# System dependencies
# ------------------------------------------------------------
# Python 3.11 Lambda base image uses Amazon Linux 2, so use yum.
RUN yum install -y \
    git \
    tar \
    gzip \
    curl \
    && yum clean all \
    && rm -rf /var/cache/yum


# ------------------------------------------------------------
# Python dependencies
# ------------------------------------------------------------
# Pydantic is used directly by the application.
# Version 2.11.7 satisfies the newer MCP dependency pulled
# by strands-agents while remaining in the Pydantic 2.x series.
RUN pip install --no-cache-dir \
    bandit==1.7.9 \
    semgrep==1.72.0 \
    pip-audit==2.7.3 \
    boto3==1.34.0 \
    pydantic==2.11.7 \
    strands-agents==0.1.0


# ------------------------------------------------------------
# Bundle Semgrep rules at build time
# ------------------------------------------------------------
# This allows Lambda to use local rules instead of downloading
# them at runtime.
RUN mkdir -p /opt/semgrep-rules && \
    semgrep --config p/python \
        --dump-config /opt/semgrep-rules/python.yaml \
        2>/dev/null || true && \
    semgrep --config p/secrets \
        --dump-config /opt/semgrep-rules/secrets.yaml \
        2>/dev/null || true && \
    semgrep --config p/supply-chain \
        --dump-config /opt/semgrep-rules/supply-chain.yaml \
        2>/dev/null || true && \
    semgrep --config p/javascript \
        --dump-config /opt/semgrep-rules/javascript.yaml \
        2>/dev/null || true && \
    semgrep --config p/typescript \
        --dump-config /opt/semgrep-rules/typescript.yaml \
        2>/dev/null || true && \
    semgrep --config p/golang \
        --dump-config /opt/semgrep-rules/golang.yaml \
        2>/dev/null || true && \
    semgrep --config p/java \
        --dump-config /opt/semgrep-rules/java.yaml \
        2>/dev/null || true && \
    semgrep --config p/ruby \
        --dump-config /opt/semgrep-rules/ruby.yaml \
        2>/dev/null || true && \
    semgrep --config p/bash \
        --dump-config /opt/semgrep-rules/bash.yaml \
        2>/dev/null || true

ENV SEMGREP_RULES_DIR=/opt/semgrep-rules


# ------------------------------------------------------------
# Install Gitleaks
# ------------------------------------------------------------
# This binary is for Linux x86_64/amd64.
RUN curl -sSfL \
    https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz \
    | tar -xz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks


# ------------------------------------------------------------
# Copy scanner source code
# ------------------------------------------------------------
COPY . /var/task/


# ------------------------------------------------------------
# Lambda handler
# ------------------------------------------------------------
CMD ["scanner.gateway.handler.handler"]
