FROM jacketser/artex:local
USER root
RUN apt-get update -o Acquire::Retries=2 -o Acquire::http::Timeout=30 && apt-get install -y --no-install-recommends gcc libc6-dev python3-dev nginx-light && rm -rf /var/lib/apt/lists/*
COPY opencanary /sources/opencanary
COPY honeypots /sources/honeypots
ARG PIP_INDEX_URL=https://mirrors.aliyun.com/pypi/simple
ENV PIP_DEFAULT_TIMEOUT=30
RUN python3 -m venv /opt/opencanary && /opt/opencanary/bin/pip install --no-cache-dir /sources/opencanary
RUN python3 -m venv /opt/qeeqbox && /opt/qeeqbox/bin/pip install --no-cache-dir /sources/honeypots pyOpenSSL==24.3.0 cryptography==44.0.3
ENTRYPOINT []
