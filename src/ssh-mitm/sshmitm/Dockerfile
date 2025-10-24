FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libffi-dev libssl-dev openssh-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/ssh-mitm
COPY . .
RUN pip install --upgrade pip \
    && pip install --no-cache-dir .

# 필요 시 openssh-server 추가 설치:
# RUN apt-get update && apt-get install -y --no-install-recommends openssh-server

EXPOSE 12223
ENTRYPOINT ["ssh-mitm", "server", "--listen-port", "12223" "--remote-host", "127.0.0.1", "--remote-port", "2223", "--host-key", "server.key", "--host-key-algorithm", "rsa"]