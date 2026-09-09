# The vantage point: the collector and the tools, with the binaries they shell out to.
FROM python:3.10-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends iputils-ping traceroute iproute2 net-tools \
      dnsutils curl ca-certificates procps tcpdump \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir dnspython certifi scapy pymodbus
# tcpdump + scapy: the passive path. The poller (lab/poller.py, pymodbus) talks Modbus/TCP to
# the two devices; tcpdump on eth1 records it; net_ingest reads the capture back. That is the
# industrial deployment in miniature - the monitor never sends a Modbus packet of its own.
WORKDIR /app
CMD ["sleep", "infinity"]
