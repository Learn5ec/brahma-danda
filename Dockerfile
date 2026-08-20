# Pinned base image — never 'latest'
FROM debian:bookworm-20250721-slim

# ── Install scan tools + Python for the Claude/Slack remediation step ──
RUN apt-get update && apt-get install -y --no-install-recommends \
        debsecan \
        nmap \
        python3 \
        python3-pip \
        python3-venv \
        curl \
        ca-certificates \
        jq \
        cron \
        iproute2 \
        iptables \
        nftables \
        ufw \
        lynis \
        git \
        bsdmainutils \
        dnsutils \
        sudo \
    && rm -rf /var/lib/apt/lists/*

# ── Install testssl.sh ──
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /usr/local/testssl \
    && ln -s /usr/local/testssl/testssl.sh /usr/local/bin/testssl.sh

# ── Trivy (direct download from GitHub releases) ──
ARG TRIVY_VERSION=0.73.0
RUN curl -sfL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
      | tar xz -C /usr/local/bin

# ── supercronic (lightweight, container-friendly cron — avoids full cron/PID1 issues) ──
ARG SUPERCRONIC_VERSION=v0.2.33
ARG SUPERCRONIC=supercronic-linux-amd64
RUN curl -fsSLO "https://github.com/aptible/supercronic/releases/download/${SUPERCRONIC_VERSION}/${SUPERCRONIC}" \
    && chmod +x "${SUPERCRONIC}" \
    && mv "${SUPERCRONIC}" /usr/local/bin/supercronic

# ── Non-root user — the container only ever needs READ access to the host mount ──
RUN groupadd -r brahmadanda && useradd -r -g brahmadanda -m -d /home/brahmadanda brahmadanda \
    && echo "brahmadanda ALL=(root) NOPASSWD: /usr/sbin/iptables-save, /usr/sbin/nft, /usr/sbin/ufw, /usr/bin/ss" > /etc/sudoers.d/brahmadanda \
    && chmod 0440 /etc/sudoers.d/brahmadanda

WORKDIR /app

COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

COPY scripts/ ./scripts/
COPY crontab /app/crontab

RUN chmod +x scripts/*.sh scripts/checks/*.sh \
    && mkdir -p /app/reports \
    && chown -R brahmadanda:brahmadanda /app

USER brahmadanda

ENTRYPOINT ["/app/scripts/entrypoint.sh"]
