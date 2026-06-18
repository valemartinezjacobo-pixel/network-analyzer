# netaudit · imagen mínima (sin dependencias, solo stdlib)
FROM python:3.12-slim

# Herramientas de red que el script usa por debajo (ping, ip, arp, traceroute)
RUN apt-get update && apt-get install -y --no-install-recommends \
        iputils-ping iproute2 net-tools traceroute \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY network_analyzer.py .

# Para escaneo completo de la LAN usa --network host:
#   docker run --rm --network host -v "$PWD:/out" netaudit -o /out/report.html
ENTRYPOINT ["python3", "network_analyzer.py"]
CMD ["--help"]
