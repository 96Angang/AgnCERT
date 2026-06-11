FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    openssl \
    socat \
    git \
    iputils-ping \
    gettext \
    ssh \
    openssh-client \
    cron \
    sshpass \
    && rm -rf /var/lib/apt/lists/*

# Set HOME and install acme.sh to a fixed location
# ACME_EMAIL: acme.sh 계정 등록 이메일 (빌드 시 --build-arg ACME_EMAIL=you@example.com 으로 지정)
ENV HOME=/root
ARG ACME_EMAIL=admin@example.com
RUN curl https://get.acme.sh | sh -s email=$ACME_EMAIL && \
    cp /root/.acme.sh/acme.sh /usr/local/bin/acme.sh && \
    chmod +x /usr/local/bin/acme.sh

WORKDIR /app

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

COPY data/requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Create necessary directories
RUN mkdir -p /app/logs /app/acme.sh /app/staticfiles

ENTRYPOINT ["/bin/bash", "/app/entrypoint.sh"]
