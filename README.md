# network-analyzer · `netaudit`

Auditor de red **multiplataforma** (Linux · macOS · Windows) escrito en Python puro
(sin dependencias). Recolecta el máximo de parámetros posibles de la red local y de
la conexión a Internet, audita la IP pública, descubre hosts en la LAN, mide la
conectividad y genera un **dashboard HTML interactivo**.

![status](https://img.shields.io/badge/python-3.8%2B-blue) ![status](https://img.shields.io/badge/deps-stdlib%20only-green) ![status](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey)

---

## Descargar el binario (sin instalar Python)

Ve a la pestaña **[Releases](../../releases)** y descarga el ejecutable de tu sistema:

| Sistema  | Archivo                       |
|----------|-------------------------------|
| Windows  | `netaudit-windows-x64.exe`    |
| macOS    | `netaudit-macos-arm64`        |
| Linux    | `netaudit-linux-x64`          |

En macOS/Linux dale permisos: `chmod +x netaudit-*` y ejecútalo.

> Los binarios se compilan automáticamente con **GitHub Actions** en runners
> nativos de cada sistema (ver `.github/workflows/build.yml`).

## Ejecutar desde el código

```bash
python3 network_analyzer.py
```

Genera `network_report.html`. Ábrelo en el navegador.

### Opciones

```
-o, --output ARCHIVO   nombre del HTML de salida (def. network_report.html)
    --json ARCHIVO      vuelca también los datos crudos en JSON
    --no-lan            omite el escaneo de la LAN
    --no-public         omite consultas a Internet
    --fast              modo rápido (menos pruebas)
```

## Qué analiza

1. **Host / sistema** — hostname, FQDN, SO, arquitectura, uptime, usuario.
2. **Interfaces** — IPv4/IPv6, MAC, MTU, flags, estado.
3. **Gateway · DNS · Rutas · ARP** — gateway por defecto, servidores DNS, tabla de rutas, ARP con fabricante (OUI).
4. **Auditoría IP pública** — IP pública, geolocalización, ASN, ISP, reverse DNS, flags proxy/hosting, reputación en 5 listas negras (DNSBL).
5. **Puertos en escucha** locales con identificación de servicio.
6. **Escaneo LAN** — ping sweep concurrente del /24, cruzado con ARP, hostnames y fabricante.
7. **ARP / vecinos**.
8. **Conectividad** — latencia ICMP (loss/min/avg/max/jitter), timing DNS, handshake TCP/443, Path MTU, traceroute.

## Compilar localmente

```bash
pip install pyinstaller
pyinstaller --onefile --name netaudit network_analyzer.py
# binario en dist/
```

## Aviso legal

Úsalo **solo en redes propias o con autorización explícita**. El escaneo de
redes de terceros sin permiso puede infringir la ley en tu jurisdicción.

## Licencia

MIT — ver [LICENSE](LICENSE).
