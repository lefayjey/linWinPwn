FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    sudo wget unzip git curl nmap john libsasl2-dev libldap2-dev \
    libkrb5-dev ntpsec-ntpdate pipx swig jq openssl rlwrap smbmap \
    && rm -rf /var/lib/apt/lists/*

COPY linWinPwn.sh install.sh /opt/linWinPwn/

RUN chmod +x /opt/linWinPwn/install.sh /opt/linWinPwn/linWinPwn.sh \
    && /opt/linWinPwn/install.sh \
    && rm -rf /root/.cache /tmp/* /var/tmp/*

RUN mkdir -p /opt/lwp-output

ENV PATH="/root/.local/bin:${PATH}"
WORKDIR /opt/linWinPwn
ENTRYPOINT ["linWinPwn", "-o", "/opt/lwp-output"]