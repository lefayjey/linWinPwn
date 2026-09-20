FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/root/.local/bin:/opt/lwp-scripts/.venv/bin:${PATH}"

# 1. Install system prerequisites including gcc/build-essential
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential sudo wget unzip git curl nmap john libsasl2-dev libldap2-dev \
    libkrb5-dev ntpsec-ntpdate pipx swig jq openssl rlwrap smbmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/linWinPwn

# 2. Copy and run install.sh ONLY (caches all 30+ tool installations)
COPY install.sh /opt/linWinPwn/
RUN chmod +x /opt/linWinPwn/install.sh \
    && /opt/linWinPwn/install.sh \
    && rm -rf /root/.cache /tmp/* /var/tmp/*

# 3. Copy main script and configs (fast rebuilds when scripts change)
COPY linWinPwn.sh MENUS.md README.md /opt/linWinPwn/
RUN chmod +x /opt/linWinPwn/linWinPwn.sh \
    && mkdir -p /opt/lwp-output /opt/lwp-wordlists

ENTRYPOINT ["/bin/bash", "-c", "if [ -t 0 ]; then exec rlwrap -Nn /opt/linWinPwn/linWinPwn.sh -o /opt/lwp-output \"$@\"; else exec /opt/linWinPwn/linWinPwn.sh -o /opt/lwp-output \"$@\"; fi", "--"]