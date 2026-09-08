# The vantage point: the collector and the tools, with the binaries they shell out to.
FROM python:3.10-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends iputils-ping traceroute iproute2 net-tools \
      dnsutils curl ca-certificates procps \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir dnspython certifi
WORKDIR /app
CMD ["sleep", "infinity"]
