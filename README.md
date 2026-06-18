# network-analyzer · `netaudit` v2.0

Auditor de red **multiplataforma** (Linux · macOS · Windows) escrito en Python puro
(sin dependencias). Recolecta el máximo de parámetros de la red local y de Internet,
descubre y **escanea** los hosts de la LAN (puertos, banners, fingerprint de SO),
inspecciona **certificados TLS**, descubre dispositivos **UPnP/SSDP**, lee el **Wi-Fi**,
hace **benchmark de DNS** y un **test de velocidad**, calcula un **score de seguridad**
con recomendaciones, y genera un **dashboard HTML interactivo con gráficas**.

![python](https://img.shields.io/badge/python-3.8%2B-blue) ![deps](https://img.shields.io/badge/deps-stdlib%20only-green) ![platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey)

---

## Descargar el binario (sin instalar Python)

Pestaña **[Releases](../../releases)** y descarga el ejecutable de tu sistema:

| Sistema  | Archivo                       |
|----------|-------------------------------|
| Windows  | `netaudit-windows-x64.exe`    |
| macOS    | `netaudit-macos-arm64`        |
| Linux    | `netaudit-linux-x64`          |

En macOS/Linux: `chmod +x netaudit-*` y ejecútalo. Los binarios se compilan
automáticamente con **GitHub Actions** (tests → build en runners nativos).

## Ejecutar desde el código

```bash
python3 network_analyzer.py
```

Genera `network_report.html`. Ábrelo en el navegador.

### Opciones

```
-o salida.html        nombre del HTML de salida
--json datos.json      vuelca el JSON crudo
--csv hosts.csv        exporta los hosts de la LAN a CSV
--target HOST          analiza/escanea un host o red concretos
--subnet 10.0.0.0/24   red a escanear (por defecto autodetecta /24)
--ports 1-1024         puertos del escaneo remoto (rango o lista)
--timeout 0.6          timeout por conexión (segundos)
--no-lan               omite el escaneo de la LAN
--no-portscan          descubre hosts pero no escanea sus puertos
--no-public            sin consultas a Internet
--no-speedtest         sin test de velocidad
--online-oui           resuelve fabricantes desconocidos por Internet
--compare a.json b.json  compara dos reportes (diff) y sale
--fast                 modo rápido · --no-color · --version
```

## Qué analiza

1. **Host / sistema** — hostname, FQDN, SO, arquitectura, uptime.
2. **Interfaces** — IPv4/IPv6, MAC, MTU, flags, estado.
3. **Gateway · DNS · Rutas · ARP** — incluye **detección de ARP spoofing** (MAC en varias IPs).
4. **Puertos en escucha** locales con servicio.
5. **Wi-Fi** — SSID, señal, canal (según plataforma).
6. **IP pública** — geolocalización, ASN, ISP, rDNS, listas negras (DNSBL); opcional Shodan/AbuseIPDB con API key.
7. **UPnP / SSDP** — descubre routers, TVs, impresoras e IoT.
8. **Escaneo de la LAN** — ping sweep concurrente + **escaneo de puertos remoto**, **banner grabbing**, **fingerprint de SO por TTL**, fabricante (OUI) y **certificados TLS** (emisor, caducidad, cifrado).
9. **Benchmark de DNS** — compara Cloudflare / Google / Quad9 / OpenDNS y tu resolver.
10. **Conectividad** — latencia ICMP, MTU, traceroute, resolución DNS.
11. **Test de velocidad** — throughput de descarga real.
12. **Score de seguridad** — puntuación 0–100 con grado A–F y **recomendaciones** (puertos peligrosos, certificados caducados, ARP spoofing, reputación de IP…).

El **dashboard HTML** incluye gráficas (Chart.js), tablas filtrables/ordenables,
mapa de geolocalización, gauge de seguridad y exportación a CSV desde el navegador.

## Docker

```bash
docker build -t netaudit .
docker run --rm --network host -v "$PWD:/out" netaudit -o /out/report.html
```

## Tests

```bash
python3 -m unittest -v test_netaudit.py
```

## Compilar localmente

```bash
pip install pyinstaller
pyinstaller --onefile --name netaudit network_analyzer.py   # binario en dist/
```

## Aviso legal

Úsalo **solo en redes propias o con autorización explícita**. El escaneo de redes
de terceros sin permiso puede infringir la ley en tu jurisdicción.

## Licencia

MIT — ver [LICENSE](LICENSE).
