#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SPIDER-EYE v1.0
Professional Security Recon Tool

Author: xMike-hub, fabio22-git
GitHub: xMike-hub, fabio-22-git

USO CONSENTITO SOLO SU:
- reti proprie
- lab personali
- target con autorizzazione esplicita

Note:
- SPIDER-EYE usa Nmap come motore di scansione.
- Nmap deve essere installato nel sistema.
"""

import argparse
import csv
import html
import ipaddress
import json
import logging
import os
import platform
import re
import shutil
import socket
import ssl
import sys
from datetime import datetime
from urllib.parse import urlparse

try:
    import requests
    import urllib3
    from nmap import PortScanner
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    from rich.prompt import Confirm, Prompt
    from rich.table import Table
except ImportError as exc:
    print(f"[!] Missing Python dependency: {exc}")
    print("[*] Install requirements with:")
    print("    pip install -r requirements.txt")
    print("[*] Or run the project installer:")
    print("    ./install.sh")
    sys.exit(1)


# Evita warning brutti a schermo quando si fa fingerprint HTTPS su certificati self-signed.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

APP_NAME = "SPIDER-EYE"
VERSION = "1.0"
OUTPUT_DIR = "spider_reports"
LOG_DIR = "logs"
WEB_COMMON_PORTS = "80,443,8080,8000,8009,8180,8443"

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    filename=os.path.join(LOG_DIR, "spider_eye.log"),
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)


BANNER = r"""
[bold red]
   ███████╗██████╗ ██╗██████╗ ███████╗██████╗       ███████╗██╗   ██╗███████╗
   ██╔════╝██╔══██╗██║██╔══██╗██╔════╝██╔══██╗      ██╔════╝╚██╗ ██╔╝██╔════╝
   ███████╗██████╔╝██║██║  ██║█████╗  ██████╔╝█████╗█████╗   ╚████╔╝ █████╗
   ╚════██║██╔═══╝ ██║██║  ██║██╔══╝  ██╔══██╗╚════╝██╔══╝    ╚██╔╝  ██╔══╝
   ███████║██║     ██║██████╔╝███████╗██║  ██║      ███████╗   ██║   ███████╗
   ╚══════╝╚═╝     ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝      ╚══════╝   ╚═╝   ╚══════╝
[/bold red]
[bold white]             Professional Security Recon Tool v1.0[/bold white]
"""


RISKY_PORTS = {
    20: ("LOW", "FTP data channel rilevato"),
    21: ("MEDIUM", "FTP può esporre credenziali o dati in chiaro"),
    22: ("LOW", "SSH esposto: verificare policy, versioni e autenticazione"),
    23: ("HIGH", "Telnet trasmette credenziali in chiaro"),
    25: ("MEDIUM", "SMTP esposto: verificare relay e configurazione"),
    53: ("MEDIUM", "DNS esposto: verificare zone transfer e configurazione"),
    80: ("LOW", "HTTP esposto: verificare contenuti, header e versioni"),
    111: ("MEDIUM", "RPCBind esposto: spesso utile per enumerazione servizi RPC/NFS"),
    139: ("MEDIUM", "NetBIOS esposto: verificare enumerazione e condivisioni"),
    443: ("LOW", "HTTPS esposto: verificare TLS, certificato e tecnologie"),
    445: ("HIGH", "SMB esposto: verificare patching e configurazione"),
    512: ("HIGH", "rexec esposto: servizio legacy ad alto rischio"),
    513: ("HIGH", "rlogin esposto: servizio legacy ad alto rischio"),
    514: ("HIGH", "rsh/syslog esposto: verificare servizio e configurazione"),
    1524: ("HIGH", "Ingreslock/backdoor-like service nei lab vulnerabili"),
    2049: ("MEDIUM", "NFS esposto: verificare export e permessi"),
    2121: ("MEDIUM", "FTP alternativo esposto"),
    3306: ("MEDIUM", "MySQL esposto: verificare accesso remoto e credenziali"),
    5432: ("MEDIUM", "PostgreSQL esposto: verificare accesso remoto e credenziali"),
    5900: ("HIGH", "VNC esposto: verificare autenticazione e cifratura"),
    6000: ("MEDIUM", "X11 esposto: verificare access control"),
    6667: ("HIGH", "IRC esposto: nei lab può indicare servizi vulnerabili"),
    8009: ("MEDIUM", "AJP/Tomcat esposto: verificare configurazione"),
    8080: ("LOW", "HTTP alternativo esposto"),
    8180: ("LOW", "HTTP alternativo esposto"),
    8443: ("LOW", "HTTPS alternativo esposto"),
}

RISK_WEIGHT = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

MODE_NAMES = {
    "1": "Service Scan",
    "2": "OS Fingerprint",
    "3": "Full Audit",
    "4": "UDP Fast",
    "5": "Vulnerability NSE",
    "6": "Discovery",
    "7": "Web Recon",
    "8": "Safe Scan",
}

MODE_ALIASES = {
    "service": "1",
    "services": "1",
    "os": "2",
    "os-detection": "2",
    "os-fingerprint": "2",
    "aggressive": "3",
    "audit": "3",
    "full-audit": "3",
    "udp": "4",
    "udp-fast": "4",
    "vuln": "5",
    "vulnerability": "5",
    "discovery": "6",
    "discover": "6",
    "web": "7",
    "web-recon": "7",
    "safe": "8",
    "safe-scan": "8",
}


class SpiderEye:
    def __init__(self, assume_yes=False):
        self.assume_yes = assume_yes
        self.last_scan_context = {}
        self.scanner = self.create_scanner_or_exit()

    def create_scanner_or_exit(self):
        try:
            return PortScanner()
        except Exception:
            console.print("[bold red]Errore: Nmap non trovato.[/bold red]")
            console.print("Installa Nmap e assicurati che sia nel PATH di sistema.")
            console.print("Kali/Debian: sudo apt install nmap -y")
            sys.exit(1)

    def print_banner(self):
        console.print(BANNER, highlight=False)

    def disclaimer(self):
        if self.assume_yes:
            return

        text = """
[bold red]AVVISO LEGALE[/bold red]

Questo tool deve essere usato solo su sistemi di tua proprietà
o per i quali hai autorizzazione esplicita.

Scansioni non autorizzate possono essere illegali.
"""
        console.print(Panel(text, border_style="red", title="LEGAL DISCLAIMER"))

        accepted = Confirm.ask(
            "[yellow]Confermi di avere autorizzazione sul target?[/yellow]",
            default=False
        )

        if not accepted:
            console.print("[red]Operazione annullata.[/red]")
            sys.exit(0)

    def environment_check(self):
        table = Table(title="Pre-flight Check", border_style="green")
        table.add_column("Check", style="cyan")
        table.add_column("Stato")
        table.add_column("Dettaglio")

        python_version = platform.python_version()
        table.add_row("Python", "[green]OK[/green]", python_version)

        nmap_path = shutil.which("nmap")
        if nmap_path:
            table.add_row("Nmap", "[green]OK[/green]", nmap_path)
        else:
            table.add_row("Nmap", "[red]MISSING[/red]", "Installa con: sudo apt install nmap -y")

        system_name = platform.system()
        table.add_row("Sistema", "[green]OK[/green]", system_name)

        if hasattr(os, "geteuid"):
            if os.geteuid() == 0:
                table.add_row("Permessi", "[green]ROOT[/green]", "SYN/UDP/OS scan supportati meglio")
            else:
                table.add_row(
                    "Permessi",
                    "[yellow]USER[/yellow]",
                    "Alcune scan (-sS, -O, -sU) possono richiedere sudo"
                )
        else:
            table.add_row("Permessi", "[yellow]N/A[/yellow]", "Controllo root non disponibile")

        console.print(table)

    def is_root(self):
        """Restituisce True se il programma gira con privilegi root/amministratore su Linux."""
        return hasattr(os, "geteuid") and os.geteuid() == 0

    def relaunch_with_sudo_if_needed(self):
        """
        Permette di rilanciare SPIDER-EYE con sudo direttamente dal programma.

        Serve soprattutto per modalità che usano pacchetti raw o fingerprinting avanzato:
        - SYN Scan (-sS)
        - OS Fingerprint (-O)
        - UDP Scan (-sU)
        - Full Audit (-A)
        - Vulnerability NSE
        """
        if not hasattr(os, "geteuid"):
            return

        if self.is_root():
            return

        console.print(Panel(
            "[yellow]SPIDER-EYE è avviato come utente normale.[/yellow]\n\n"
            "Puoi continuare così, ma alcune modalità potrebbero essere meno affidabili "
            "o non funzionare correttamente senza privilegi root.\n\n"
            "Modalità consigliate con sudo:\n"
            "- Service Scan / Safe Scan: usa SYN scan (-sS)\n"
            "- OS Fingerprint: usa OS detection (-O)\n"
            "- Full Audit: usa -A, script e traceroute\n"
            "- UDP Fast: usa UDP scan (-sU)\n"
            "- Vulnerability NSE: usa SYN scan + script vuln\n\n"
            "Se accetti, il programma verrà riavviato automaticamente con sudo "
            "mantenendo lo stesso interprete Python del venv.",
            border_style="yellow",
            title="PRIVILEGI SUDO"
        ))

        should_relaunch = self.assume_yes or Confirm.ask(
            "[bold yellow]Vuoi rilanciare SPIDER-EYE con sudo?[/bold yellow]",
            default=False
        )

        if not should_relaunch:
            console.print("[yellow]Continuo senza sudo. Alcune scansioni potrebbero essere limitate.[/yellow]")
            return

        python_path = sys.executable
        script_path = os.path.abspath(sys.argv[0])
        args = sys.argv[1:]

        console.print("[cyan]Rilancio con sudo...[/cyan]")
        console.print(f"[dim]sudo {python_path} {script_path} {' '.join(args)}[/dim]")

        try:
            os.execvp("sudo", ["sudo", python_path, script_path] + args)
        except Exception as e:
            console.print(f"[red]Errore nel rilancio con sudo:[/red] {e}")
            console.print("Puoi lanciarlo manualmente con:")
            console.print(f"[cyan]sudo {python_path} {script_path}[/cyan]")

    def restore_sudo_user_ownership(self, paths):
        """
        Se il programma è stato rilanciato con sudo, i report verrebbero creati da root.
        Questa funzione prova a restituire la proprietà dei file all'utente originale,
        così puoi aprirli/modificarli normalmente da VS Code o file manager.
        """
        if not hasattr(os, "chown"):
            return

        sudo_uid = os.environ.get("SUDO_UID")
        sudo_gid = os.environ.get("SUDO_GID")

        if not sudo_uid or not sudo_gid:
            return

        try:
            uid = int(sudo_uid)
            gid = int(sudo_gid)
        except ValueError:
            return

        for path in paths:
            try:
                if path and os.path.exists(path):
                    os.chown(path, uid, gid)
            except Exception:
                pass

    def validate_target(self, target):
        try:
            if "/" in target:
                ipaddress.ip_network(target, strict=False)
            else:
                ipaddress.ip_address(target)
            return True
        except ValueError:
            console.print(f"[red]Target non valido:[/red] {target}")
            return False

    def normalize_mode(self, mode):
        mode = str(mode).strip().lower()
        if mode in MODE_NAMES:
            return mode
        return MODE_ALIASES.get(mode, "")

    def reverse_dns(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ""

    def extract_title(self, html_text):
        try:
            match = re.search(
                r"<\s*title\s*>(.*?)<\s*/\s*title\s*>",
                html_text,
                re.IGNORECASE | re.DOTALL
            )
            if match:
                title = re.sub(r"\s+", " ", match.group(1)).strip()
                return title[:120]
        except Exception:
            pass
        return ""

    def get_ssl_info(self, host, port):
        ssl_data = {
            "ssl_subject": "",
            "ssl_issuer": "",
            "ssl_not_before": "",
            "ssl_not_after": ""
        }

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, int(port)), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()

            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))

            ssl_data["ssl_subject"] = subject.get("commonName", "")
            ssl_data["ssl_issuer"] = issuer.get("commonName", "")
            ssl_data["ssl_not_before"] = cert.get("notBefore", "")
            ssl_data["ssl_not_after"] = cert.get("notAfter", "")
        except Exception:
            pass

        return ssl_data

    def http_fingerprint(self, ip, port):
        result = {
            "url": "",
            "status_code": "",
            "title": "",
            "server": "",
            "powered_by": "",
            "redirected": "",
            "technologies": "",
            "ssl_subject": "",
            "ssl_issuer": "",
            "ssl_not_before": "",
            "ssl_not_after": ""
        }

        port = int(port)
        schemes = ["https", "http"] if port in [443, 8443] else ["http", "https"]

        for scheme in schemes:
            url = f"{scheme}://{ip}:{port}"

            try:
                response = requests.get(
                    url,
                    timeout=5,
                    verify=False,
                    allow_redirects=True,
                    headers={"User-Agent": "Spider-Eye Recon Tool"}
                )

                result["url"] = response.url
                result["status_code"] = response.status_code
                result["server"] = response.headers.get("Server", "")
                result["powered_by"] = response.headers.get("X-Powered-By", "")
                result["title"] = self.extract_title(response.text)
                result["redirected"] = "yes" if response.url != url else "no"

                tech = []
                headers_joined = " ".join([f"{k}: {v}" for k, v in response.headers.items()]).lower()
                body_lower = response.text[:5000].lower()

                checks = {
                    "Apache": "apache",
                    "Nginx": "nginx",
                    "PHP": "php",
                    "WordPress": "wp-content",
                    "Drupal": "drupal",
                    "Joomla": "joomla",
                    "OpenSSL": "openssl",
                    "Tomcat": "tomcat",
                    "Node.js": "node",
                    "Express": "express",
                    "IIS": "microsoft-iis"
                }

                for name, needle in checks.items():
                    if needle in headers_joined or needle in body_lower:
                        tech.append(name)

                result["technologies"] = ", ".join(sorted(set(tech)))

                if scheme == "https" or urlparse(response.url).scheme == "https":
                    ssl_info = self.get_ssl_info(ip, port)
                    result.update(ssl_info)

                return result

            except Exception:
                continue

        return result

    def build_arguments(self, mode, timing, ports=None):
        """
        Costruisce gli argomenti Nmap.
        Nota importante:
        - UDP Fast usa -F solo se non vengono specificate porte custom.
        - Safe Scan forza sempre T3 e top 1000 per restare prudente.
        """
        if mode == "8":
            return "-sS -sV --top-ports 1000 -T3 -Pn"

        timing_flag = f"-T{timing}"

        if mode == "4":
            # Se l'utente sceglie porte custom o full, non usiamo -F perché sarebbe ridondante.
            if ports:
                return f"-sU -sV {timing_flag} -Pn"
            return f"-sU -sV -F {timing_flag} -Pn"

        modes = {
            "1": f"-sS -sV {timing_flag} -Pn",
            "2": f"-sS -sV -O {timing_flag} -Pn",
            "3": f"-A {timing_flag} -Pn",
            "5": f"-sS -sV --script vuln {timing_flag} -Pn",
            "6": f"-sn {timing_flag}",
            "7": f"-sS -sV {timing_flag} -Pn",
        }

        return modes.get(mode, f"-sS -sV {timing_flag} -Pn")

    def normalize_ports(self, mode, ports):
        if mode == "6":
            return ""

        if ports is None:
            return None

        ports = str(ports).strip().lower()

        if ports in ["", "none", "top", "top1000", "top-1000", "default"]:
            if mode == "7":
                return WEB_COMMON_PORTS
            return None

        if ports in ["all", "full", "alltcp", "1-65535"]:
            return "1-65535"

        if ports in ["web", "common-web"]:
            return WEB_COMMON_PORTS

        return ports

    def build_nmap_command(self, target, ports, arguments):
        if ports:
            return f"nmap {arguments} -p {ports} {target}"
        return f"nmap {arguments} {target}"

    def count_hosts(self, target):
        try:
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                if network.version == 4 and network.num_addresses > 2:
                    return max(network.num_addresses - 2, 1)
                return network.num_addresses
            return 1
        except Exception:
            return 1

    def count_ports(self, ports, mode):
        if mode == "6":
            return 0
        if not ports:
            # Nmap -F in UDP Fast usa un set ridotto di porte comuni.
            if mode == "4":
                return 100
            return 1000

        total = 0
        parts = str(ports).split(",")
        for part in parts:
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                try:
                    start, end = part.split("-", 1)
                    total += abs(int(end) - int(start)) + 1
                except Exception:
                    total += 1
            else:
                total += 1

        return total or 1000

    def estimate_and_confirm(self, target, ports, mode, timing, arguments):
        host_count = self.count_hosts(target)
        port_count = self.count_ports(ports, mode)
        combinations = host_count * max(port_count, 1)
        mode_name = MODE_NAMES.get(mode, mode)

        risk_label = "[green]Leggera[/green]"
        border = "green"

        if mode in ["3", "4", "5"] or combinations >= 100000:
            risk_label = "[yellow]Media[/yellow]"
            border = "yellow"

        if combinations >= 1000000 or mode == "5" or (mode == "4" and port_count > 100):
            risk_label = "[red]Pesante/Rumorosa[/red]"
            border = "red"

        table = Table(title="Riepilogo scansione", border_style=border)
        table.add_column("Campo", style="cyan")
        table.add_column("Valore")

        table.add_row("Target", target)
        table.add_row("Modalità", f"{mode} - {mode_name}")
        table.add_row("Timing", "3 (Safe Scan forza T3)" if mode == "8" else str(timing))
        table.add_row("Porte stimate", str(port_count) if port_count else "0 - Discovery")
        table.add_row("Host stimati", str(host_count))
        table.add_row("Combinazioni", str(combinations if port_count else host_count))
        table.add_row("Impatto stimato", risk_label)
        table.add_row("Comando Nmap", self.build_nmap_command(target, ports, arguments))

        console.print(table)

        if self.assume_yes:
            return True

        if combinations >= 100000 or mode in ["3", "4", "5"]:
            return Confirm.ask("[yellow]Vuoi continuare con questa scansione?[/yellow]", default=False)

        return True

    def run_scan(self, target, ports, mode, timing):
        arguments = self.build_arguments(mode, timing, ports)
        nmap_command = self.build_nmap_command(target, ports, arguments)

        self.last_scan_context = {
            "app": APP_NAME,
            "version": VERSION,
            "target": target,
            "mode": mode,
            "mode_name": MODE_NAMES.get(mode, mode),
            "timing": "3 (forced safe profile)" if mode == "8" else timing,
            "ports": ports if ports else ("UDP Fast common set (-F)" if mode == "4" else "Top 1000 Nmap/default"),
            "nmap_arguments": arguments,
            "nmap_command": nmap_command,
            "started_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        if not self.estimate_and_confirm(target, ports, mode, timing, arguments):
            console.print("[yellow]Scansione annullata dall'utente.[/yellow]")
            return None

        logging.info(f"Scan avviata | {nmap_command}")

        # Reset scanner per evitare risultati residui tra scansioni consecutive.
        self.scanner = self.create_scanner_or_exit()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            transient=True
        ) as progress:
            progress.add_task(description=f"[cyan]Scansione di {target} in corso...[/cyan]", total=None)

            try:
                if ports:
                    self.scanner.scan(hosts=target, ports=ports, arguments=arguments)
                else:
                    self.scanner.scan(hosts=target, arguments=arguments)

                self.last_scan_context["finished_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                logging.info(f"Scan completata | Target: {target}")
                return self.scanner

            except Exception as e:
                logging.error(f"Errore scan | Target: {target} | Errore: {e}")
                console.print(f"[red]Errore durante la scansione:[/red] {e}")
                return None

    def parse_script_output(self, info):
        scripts = info.get("script", {})
        if not scripts:
            return ""

        output_lines = []
        for script_name, script_output in scripts.items():
            cleaned = str(script_output).replace("\n", " ").strip()
            output_lines.append(f"{script_name}: {cleaned}")

        return " | ".join(output_lines)

    def parse_os_guess(self, scanner, host):
        """
        Estrae il miglior match OS prodotto da Nmap (-O o -A).
        Serve a rendere visibile la differenza tra Service Scan e OS Fingerprint.
        """
        try:
            os_matches = scanner[host].get("osmatch", [])
            if os_matches:
                best = os_matches[0]
                return best.get("name", ""), best.get("accuracy", "")
        except Exception:
            pass

        return "", ""

    def parse_traceroute(self, scanner, host):
        """
        Estrae una traccia sintetica del traceroute quando presente (-A).
        python-nmap può salvarla in strutture diverse in base alla versione.
        """
        try:
            trace = scanner[host].get("trace", {})
            hops = trace.get("hops", [])
            if hops:
                compact_hops = []
                for hop in hops[:8]:
                    ipaddr = hop.get("ipaddr", "")
                    ttl = hop.get("ttl", "")
                    if ipaddr:
                        compact_hops.append(f"{ttl}:{ipaddr}" if ttl else ipaddr)
                return " -> ".join(compact_hops)
        except Exception:
            pass

        return ""

    def risk_rating(self, port, service, state, nse_scripts):
        if str(state).lower() not in ["open", "open|filtered", "up"]:
            return "INFO", "Stato non aperto o solo informativo"

        nse_lower = str(nse_scripts).lower()
        if any(word in nse_lower for word in ["vulnerable", "cve", "exploit", "backdoor"]):
            return "CRITICAL", "Output NSE contiene possibile vulnerabilità o CVE"

        try:
            port_int = int(port)
        except Exception:
            port_int = None

        if port_int in RISKY_PORTS:
            return RISKY_PORTS[port_int]

        service_lower = str(service).lower()
        if service_lower in ["telnet", "rlogin", "rexec", "rsh"]:
            return "HIGH", "Servizio legacy o non cifrato"
        if service_lower in ["ftp", "mysql", "postgresql", "smb", "microsoft-ds", "netbios-ssn"]:
            return "MEDIUM", "Servizio da verificare per esposizione e configurazione"
        if service_lower in ["http", "https", "ssl/http", "http-proxy"]:
            return "LOW", "Servizio web esposto, verificare configurazione"

        return "INFO", "Nessun rischio automatico classificato"

    def empty_web_data(self):
        return {
            "url": "",
            "status_code": "",
            "title": "",
            "server": "",
            "powered_by": "",
            "redirected": "",
            "technologies": "",
            "ssl_subject": "",
            "ssl_issuer": "",
            "ssl_not_before": "",
            "ssl_not_after": ""
        }

    def parse_results(self, scanner):
        results = []

        for host in scanner.all_hosts():
            hostname = self.reverse_dns(host)
            host_state = scanner[host].state()
            os_guess, os_accuracy = self.parse_os_guess(scanner, host)
            traceroute = self.parse_traceroute(scanner, host)
            protocols = scanner[host].all_protocols()

            if not protocols:
                risk_level, risk_note = self.risk_rating("", "host-discovery", host_state, "")
                results.append({
                    "host": host,
                    "hostname": hostname,
                    "host_state": host_state,
                    "protocol": "",
                    "port": "",
                    "state": host_state,
                    "service": "host-discovery",
                    "product": "",
                    "version": "",
                    "extra_info": "",
                    "os_guess": os_guess,
                    "os_accuracy": os_accuracy,
                    "traceroute": traceroute,
                    "risk_level": risk_level,
                    "risk_note": risk_note,
                    "nse_scripts": "",
                    "url": "",
                    "http_status": "",
                    "page_title": "",
                    "server": "",
                    "powered_by": "",
                    "redirected": "",
                    "technologies": "",
                    "ssl_subject": "",
                    "ssl_issuer": "",
                    "ssl_not_before": "",
                    "ssl_not_after": ""
                })
                continue

            for proto in protocols:
                ports = sorted(scanner[host][proto].keys())

                for port in ports:
                    info = scanner[host][proto][port]

                    service = info.get("name", "")
                    product = info.get("product", "")
                    version = info.get("version", "")
                    extrainfo = info.get("extrainfo", "")
                    state = info.get("state", "")
                    script_output = self.parse_script_output(info)
                    web_data = self.empty_web_data()

                    if service in ["http", "https", "http-proxy", "ssl/http"] or int(port) in [80, 443, 8080, 8000, 8009, 8180, 8443]:
                        web_data = self.http_fingerprint(host, port)

                    risk_level, risk_note = self.risk_rating(port, service, state, script_output)

                    results.append({
                        "host": host,
                        "hostname": hostname,
                        "host_state": host_state,
                        "protocol": proto,
                        "port": port,
                        "state": state,
                        "service": service,
                        "product": product,
                        "version": version,
                        "extra_info": extrainfo,
                        "os_guess": os_guess,
                        "os_accuracy": os_accuracy,
                        "traceroute": traceroute,
                        "risk_level": risk_level,
                        "risk_note": risk_note,
                        "nse_scripts": script_output,
                        "url": web_data.get("url", ""),
                        "http_status": web_data.get("status_code", ""),
                        "page_title": web_data.get("title", ""),
                        "server": web_data.get("server", ""),
                        "powered_by": web_data.get("powered_by", ""),
                        "redirected": web_data.get("redirected", ""),
                        "technologies": web_data.get("technologies", ""),
                        "ssl_subject": web_data.get("ssl_subject", ""),
                        "ssl_issuer": web_data.get("ssl_issuer", ""),
                        "ssl_not_before": web_data.get("ssl_not_before", ""),
                        "ssl_not_after": web_data.get("ssl_not_after", "")
                    })

        return results

    def show_results(self, results):
        if not results:
            console.print("[yellow]Nessun risultato rilevante trovato.[/yellow]")
            return

        table = Table(title="Risultati SPIDER-EYE", border_style="red", show_lines=False)
        table.add_column("Host", style="cyan", no_wrap=True)
        table.add_column("Hostname", style="blue")
        table.add_column("Porta", justify="center", no_wrap=True)
        table.add_column("Stato", style="green", no_wrap=True)
        table.add_column("Servizio", no_wrap=True)
        table.add_column("Prodotto")
        table.add_column("Versione")
        table.add_column("OS Guess")
        table.add_column("Risk", no_wrap=True)
        table.add_column("Web/Script", overflow="fold")

        for item in results:
            web_or_script = ""
            if item.get("page_title"):
                web_or_script = item["page_title"]
            elif item.get("nse_scripts"):
                web_or_script = item["nse_scripts"][:100]
            elif item.get("technologies"):
                web_or_script = item["technologies"]
            elif item.get("risk_note") and item.get("risk_level") in ["HIGH", "CRITICAL"]:
                web_or_script = item["risk_note"]

            risk_level = item.get("risk_level", "INFO")
            risk_style = {
                "CRITICAL": "bold red",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "green",
                "INFO": "white"
            }.get(risk_level, "white")

            table.add_row(
                str(item.get("host", "")),
                str(item.get("hostname", "")),
                str(item.get("port", "")),
                str(item.get("state", "")),
                str(item.get("service", "")),
                str(item.get("product", "")),
                str(item.get("version", "")),
                str(item.get("os_guess", ""))[:45],
                f"[{risk_style}]{risk_level}[/{risk_style}]",
                str(web_or_script)
            )

        console.print(table)

    def summarize_results(self, results):
        hosts = sorted(set(item.get("host", "") for item in results if item.get("host")))
        open_ports = [item for item in results if str(item.get("state", "")).lower() in ["open", "open|filtered"] and item.get("port")]
        risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        service_counts = {}

        for item in results:
            level = item.get("risk_level", "INFO")
            risk_counts[level] = risk_counts.get(level, 0) + 1
            service = item.get("service", "") or "unknown"
            if item.get("port"):
                service_counts[service] = service_counts.get(service, 0) + 1

        return {
            "hosts_count": len(hosts),
            "open_ports_count": len(open_ports),
            "risk_counts": risk_counts,
            "service_counts": service_counts
        }

    def save_json(self, results, filename, context):
        payload = {
            "metadata": context,
            "summary": self.summarize_results(results),
            "results": results
        }
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=4, ensure_ascii=False)

    def save_csv(self, results, filename):
        if not results:
            return

        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)

    def html_escape(self, value):
        return html.escape(str(value))

    def risk_badge(self, level):
        css = {
            "CRITICAL": "risk-critical",
            "HIGH": "risk-high",
            "MEDIUM": "risk-medium",
            "LOW": "risk-low",
            "INFO": "risk-info"
        }.get(level, "risk-info")
        return f'<span class="badge {css}">{self.html_escape(level)}</span>'

    def save_html(self, results, filename, target, context):
        rows = ""
        summary = self.summarize_results(results)

        for item in results:
            rows += f"""
            <tr>
                <td>{self.html_escape(item.get('host', ''))}</td>
                <td>{self.html_escape(item.get('hostname', ''))}</td>
                <td>{self.html_escape(item.get('os_guess', ''))}</td>
                <td>{self.html_escape(item.get('os_accuracy', ''))}</td>
                <td>{self.html_escape(item.get('traceroute', ''))}</td>
                <td>{self.html_escape(item.get('protocol', ''))}</td>
                <td>{self.html_escape(item.get('port', ''))}</td>
                <td>{self.html_escape(item.get('state', ''))}</td>
                <td>{self.html_escape(item.get('service', ''))}</td>
                <td>{self.html_escape(item.get('product', ''))}</td>
                <td>{self.html_escape(item.get('version', ''))}</td>
                <td>{self.risk_badge(item.get('risk_level', 'INFO'))}</td>
                <td>{self.html_escape(item.get('risk_note', ''))}</td>
                <td>{self.html_escape(item.get('url', ''))}</td>
                <td>{self.html_escape(item.get('http_status', ''))}</td>
                <td>{self.html_escape(item.get('page_title', ''))}</td>
                <td>{self.html_escape(item.get('server', ''))}</td>
                <td>{self.html_escape(item.get('powered_by', ''))}</td>
                <td>{self.html_escape(item.get('technologies', ''))}</td>
                <td>{self.html_escape(item.get('nse_scripts', ''))}</td>
            </tr>
            """

        risk_cards = "".join(
            f'<div class="metric"><span>{level}</span><strong>{count}</strong></div>'
            for level, count in summary["risk_counts"].items()
        )

        html_doc = f"""
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <title>SPIDER-EYE Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            padding: 30px;
        }}
        h1 {{ color: #ff4d4d; margin-bottom: 5px; }}
        h2 {{ color: #c9d1d9; margin-top: 30px; }}
        code {{ background: #21262d; padding: 3px 6px; border-radius: 5px; }}
        .box {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 12px;
            margin-bottom: 20px;
        }}
        .metric {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 10px;
            padding: 14px;
        }}
        .metric span {{ display: block; color: #8b949e; font-size: 12px; }}
        .metric strong {{ font-size: 24px; color: #f0f6fc; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: #161b22;
        }}
        th, td {{
            border: 1px solid #30363d;
            padding: 8px;
            font-size: 13px;
            vertical-align: top;
        }}
        th {{ background: #21262d; color: #ff7b72; position: sticky; top: 0; }}
        tr:nth-child(even) {{ background: #0d1117; }}
        .footer {{ margin-top: 30px; font-size: 12px; color: #8b949e; }}
        .note {{ color: #f2cc60; }}
        .badge {{ border-radius: 999px; padding: 3px 8px; font-size: 12px; font-weight: bold; }}
        .risk-critical {{ background: #7f1d1d; color: #fecaca; }}
        .risk-high {{ background: #991b1b; color: #fee2e2; }}
        .risk-medium {{ background: #78350f; color: #fde68a; }}
        .risk-low {{ background: #064e3b; color: #bbf7d0; }}
        .risk-info {{ background: #1f2937; color: #e5e7eb; }}
    </style>
</head>
<body>
    <h1>SPIDER-EYE Security Recon Report</h1>
    <p>Professional Security Recon Tool v{VERSION}</p>

    <div class="box">
        <p><strong>Target:</strong> {self.html_escape(target)}</p>
        <p><strong>Data:</strong> {self.html_escape(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</p>
        <p><strong>Modalità:</strong> {self.html_escape(context.get('mode_name', ''))}</p>
        <p><strong>Comando Nmap equivalente:</strong> <code>{self.html_escape(context.get('nmap_command', ''))}</code></p>
        <p class="note">Nota: "Top 1000" indica le 1000 porte più comuni secondo Nmap, non le porte numeriche da 1 a 1000.</p>
    </div>

    <div class="grid">
        <div class="metric"><span>Host rilevati</span><strong>{summary['hosts_count']}</strong></div>
        <div class="metric"><span>Porte aperte</span><strong>{summary['open_ports_count']}</strong></div>
        <div class="metric"><span>Risultati totali</span><strong>{len(results)}</strong></div>
        {risk_cards}
    </div>

    <h2>Risultati</h2>
    <table>
        <thead>
            <tr>
                <th>Host</th>
                <th>Hostname</th>
                <th>OS Guess</th>
                <th>OS Accuracy</th>
                <th>Traceroute</th>
                <th>Proto</th>
                <th>Porta</th>
                <th>Stato</th>
                <th>Servizio</th>
                <th>Prodotto</th>
                <th>Versione</th>
                <th>Risk</th>
                <th>Risk Note</th>
                <th>URL</th>
                <th>HTTP</th>
                <th>Titolo</th>
                <th>Server</th>
                <th>X-Powered-By</th>
                <th>Tecnologie</th>
                <th>NSE Scripts</th>
            </tr>
        </thead>
        <tbody>{rows}</tbody>
    </table>

    <div class="footer">
        Report generato da SPIDER-EYE v{VERSION}. Usare solo su sistemi autorizzati.
    </div>
</body>
</html>
"""

        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_doc)

    def md_escape(self, value):
        return str(value).replace("|", "\\|").replace("\n", " ").strip()

    def save_markdown(self, results, filename, target, context):
        summary = self.summarize_results(results)
        lines = []
        lines.append(f"# SPIDER-EYE Report")
        lines.append("")
        lines.append(f"**Target:** `{target}`  ")
        lines.append(f"**Data:** `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`  ")
        lines.append(f"**Modalità:** `{context.get('mode_name', '')}`  ")
        lines.append(f"**Comando Nmap equivalente:** `{context.get('nmap_command', '')}`")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- Host rilevati: **{summary['hosts_count']}**")
        lines.append(f"- Porte aperte: **{summary['open_ports_count']}**")
        lines.append(f"- Risultati totali: **{len(results)}**")
        for level, count in summary["risk_counts"].items():
            lines.append(f"- {level}: **{count}**")
        lines.append("")
        lines.append("## Results")
        lines.append("")
        lines.append("| Host | Porta | Stato | Servizio | Prodotto | Versione | OS Guess | OS Accuracy | Risk | Note | Web/Script |")
        lines.append("|---|---:|---|---|---|---|---|---:|---|---|---|")

        for item in results:
            web_or_script = item.get("page_title") or item.get("technologies") or item.get("nse_scripts") or item.get("url") or ""
            lines.append(
                "| "
                + " | ".join([
                    self.md_escape(item.get("host", "")),
                    self.md_escape(item.get("port", "")),
                    self.md_escape(item.get("state", "")),
                    self.md_escape(item.get("service", "")),
                    self.md_escape(item.get("product", "")),
                    self.md_escape(item.get("version", "")),
                    self.md_escape(item.get("os_guess", "")),
                    self.md_escape(item.get("os_accuracy", "")),
                    self.md_escape(item.get("risk_level", "")),
                    self.md_escape(item.get("risk_note", "")),
                    self.md_escape(web_or_script[:160])
                ])
                + " |"
            )

        lines.append("")
        lines.append("> Report generato da SPIDER-EYE. Usare solo su sistemi autorizzati.")

        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    def save_reports(self, results, target):
        if not results:
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace("/", "_").replace(":", "_")
        base = os.path.join(OUTPUT_DIR, f"spider_eye_{safe_target}_{timestamp}")

        json_file = f"{base}.json"
        csv_file = f"{base}.csv"
        html_file = f"{base}.html"
        md_file = f"{base}.md"

        self.save_json(results, json_file, self.last_scan_context)
        self.save_csv(results, csv_file)
        self.save_html(results, html_file, target, self.last_scan_context)
        self.save_markdown(results, md_file, target, self.last_scan_context)

        self.restore_sudo_user_ownership([
            OUTPUT_DIR,
            LOG_DIR,
            os.path.join(LOG_DIR, "spider_eye.log"),
            json_file,
            csv_file,
            html_file,
            md_file,
        ])

        console.print("\n[green]Report salvati:[/green]")
        console.print(f"JSON: {json_file}")
        console.print(f"CSV : {csv_file}")
        console.print(f"HTML: {html_file}")
        console.print(f"MD  : {md_file}")

    def ask_target(self):
        while True:
            target = Prompt.ask("[bold red]SPIDER-EYE > Inserisci IP o range CIDR[/bold red]")
            if self.validate_target(target):
                return target

    def ask_timing(self):
        table = Table(title="Timing Nmap", border_style="yellow")
        table.add_column("Valore", style="cyan", justify="center")
        table.add_column("Descrizione")
        table.add_row("0", "Molto lento")
        table.add_row("1", "Lento")
        table.add_row("2", "Conservativo")
        table.add_row("3", "Normale")
        table.add_row("4", "Veloce")
        table.add_row("5", "Molto veloce / rumoroso")
        console.print(table)

        return Prompt.ask(
            "[bold red]SPIDER-EYE > Timing[/bold red]",
            choices=["0", "1", "2", "3", "4", "5"],
            default="3"
        )

    def ask_mode(self):
        table = Table(title="Modalità scansione", border_style="cyan")
        table.add_column("ID", style="cyan", justify="center")
        table.add_column("Modalità", style="white")
        table.add_column("Descrizione")
        table.add_column("Impatto", justify="center")

        table.add_row("1", "Service Scan", "Porte TCP + versioni servizio", "Medio")
        table.add_row("2", "OS Fingerprint", "Service Scan + sistema operativo stimato", "Medio/Alto")
        table.add_row("3", "Full Audit", "Service Scan + OS + script default + traceroute", "Alto")
        table.add_row("4", "UDP Fast", "Scansione UDP rapida su porte comuni", "Medio/Alto")
        table.add_row("5", "Vulnerability NSE", "Versioni servizio + script vuln di Nmap", "Alto")
        table.add_row("6", "Discovery", "Rileva host attivi, senza port scan", "Basso")
        table.add_row("7", "Web Recon", "Fingerprint HTTP/HTTPS, header, title, tecnologie", "Basso/Medio")
        table.add_row("8", "Safe Scan", "Profilo prudente: TCP service scan top 1000, T3", "Basso")
        console.print(table)

        mode = Prompt.ask(
            "[bold red]SPIDER-EYE > Modalità[/bold red]",
            choices=["1", "2", "3", "4", "5", "6", "7", "8"],
            default="1"
        )

        if mode == "5":
            console.print(Panel(
                "[bold yellow]Attenzione:[/bold yellow] la modalità Vulnerability può essere invasiva e rumorosa.\n"
                "Usala solo su sistemi autorizzati.",
                border_style="yellow",
                title="WARNING"
            ))
            if not Confirm.ask("Vuoi continuare con la modalità Vulnerability?", default=False):
                return self.ask_mode()

        return mode

    def ask_ports(self, mode):
        if mode == "6":
            return ""

        if mode == "7":
            table = Table(title="Porte Web Recon", border_style="magenta")
            table.add_column("ID", justify="center", style="cyan")
            table.add_column("Opzione")
            table.add_row("1", f"Porte web comuni: {WEB_COMMON_PORTS}")
            table.add_row("2", "Custom")
            console.print(table)

            choice = Prompt.ask(
                "[bold red]SPIDER-EYE > Porte Web[/bold red]",
                choices=["1", "2"],
                default="1"
            )
            if choice == "1":
                return WEB_COMMON_PORTS
            return Prompt.ask("[bold red]SPIDER-EYE > Inserisci porte custom[/bold red]")

        protocol_name = "UDP" if mode == "4" else "TCP"
        table = Table(title=f"Selezione porte {protocol_name}", border_style="magenta")
        table.add_column("ID", justify="center", style="cyan")
        table.add_column("Opzione")
        if mode == "4":
            table.add_row("1", "UDP Fast set Nmap (-F): porte UDP comuni ridotte")
            table.add_row("2", "Tutte le porte UDP: 1-65535")
            table.add_row("3", "Custom UDP: esempio 53,69,111,123,137,138,161")
        else:
            table.add_row("1", "Top 1000 porte Nmap più comuni (TCP), anche oltre 1000")
            table.add_row("2", "Tutte le porte TCP: 1-65535")
            table.add_row("3", "Custom TCP: esempio 22,80,443 oppure 1-1000")
        console.print(table)

        choice = Prompt.ask(
            "[bold red]SPIDER-EYE > Porte[/bold red]",
            choices=["1", "2", "3"],
            default="1"
        )

        if choice == "1":
            return None
        if choice == "2":
            return "1-65535"
        return Prompt.ask("[bold red]SPIDER-EYE > Inserisci porte custom[/bold red]")

    def execute(self, target, mode, timing, ports):
        result = self.run_scan(target, ports, mode, timing)
        if result:
            parsed = self.parse_results(result)
            self.show_results(parsed)
            self.save_reports(parsed, target)

    def run_interactive(self):
        self.print_banner()
        self.environment_check()
        self.relaunch_with_sudo_if_needed()
        self.disclaimer()

        while True:
            target = self.ask_target()
            mode = self.ask_mode()

            if mode == "8":
                timing = "3"
                console.print(Panel(
                    "[green]Safe Scan selezionata.[/green]\n\n"
                    "Questa modalità usa sempre [bold]T3[/bold] e [bold]Top 1000 porte TCP[/bold] "
                    "per mantenere un profilo prudente.\n"
                    "La scelta del timing viene quindi saltata.",
                    border_style="green",
                    title="SAFE MODE"
                ))
            else:
                timing = self.ask_timing()

            ports = self.ask_ports(mode)
            self.execute(target, mode, timing, ports)

            again = Confirm.ask("\nVuoi eseguire una nuova scansione?", default=True)
            if not again:
                console.print("[green]Chiusura SPIDER-EYE.[/green]")
                break

    def run_cli(self, args):
        self.print_banner()
        self.environment_check()
        self.relaunch_with_sudo_if_needed()
        self.disclaimer()

        target = args.target
        if not self.validate_target(target):
            sys.exit(1)

        mode = self.normalize_mode(args.mode)
        if not mode:
            console.print(f"[red]Modalità non valida:[/red] {args.mode}")
            sys.exit(1)

        timing = "3" if mode == "8" else str(args.timing)
        ports = self.normalize_ports(mode, args.ports)
        self.execute(target, mode, timing, ports)


def build_arg_parser():
    parser = argparse.ArgumentParser(
        description="SPIDER-EYE - Professional Security Recon Tool"
    )
    parser.add_argument("-t", "--target", help="Target IP o CIDR, esempio 192.168.50.20 o 192.168.50.0/24")
    parser.add_argument(
        "-m", "--mode",
        default="service",
        help="Modalità: service, os, os-fingerprint, aggressive, full-audit, udp, vuln, discovery, web, safe oppure 1-8"
    )
    parser.add_argument(
        "-p", "--ports",
        default="top1000",
        help="Porte: top1000, all, web oppure custom tipo 22,80,443 / 1-1000"
    )
    parser.add_argument(
        "--timing",
        default="3",
        choices=["0", "1", "2", "3", "4", "5"],
        help="Timing Nmap da 0 a 5"
    )
    parser.add_argument(
        "-y", "--yes",
        action="store_true",
        help="Conferma automatica dei prompt di autorizzazione, warning e rilancio sudo"
    )
    return parser


def main():
    parser = build_arg_parser()
    args = parser.parse_args()
    app = SpiderEye(assume_yes=args.yes)

    if args.target:
        app.run_cli(args)
    else:
        app.run_interactive()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[red]Interrotto dall'utente.[/red]")
        sys.exit(0)