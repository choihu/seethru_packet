FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libffi-dev libssl-dev openssh-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/ssh-mitm
COPY . .

#RUN pip install --upgrade pip && pip install --no-cache-dir .
RUN pip install --no-cache-dir .