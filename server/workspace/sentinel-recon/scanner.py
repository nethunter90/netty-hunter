#!/usr/bin/env python3
"""Sentinel Recon - Network Reconnaissance Scanner
Built and validated using Sentinel Primordial IDE
"""
import socket
import json
import sys
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


class SentinelRecon:
    SERVICE_SIGNATURES = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
        445: "SMB", 993: "IMAPS", 995: "POP3S", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
        8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB"
    }

    def __init__(self, target, ports="1-1024", timeout=1.0, threads=50):
        self.target = target
        self.ports = self._parse_ports(ports)
        self.timeout = timeout
        self.threads = threads
        self.results = {"target": target, "scan_start": None, "scan_end": None, "open_ports": [], "summary": {}}

    def _parse_ports(self, port_spec):
        ports = []
        for part in port_spec.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
        return sorted(set(ports))

    def _scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                service = self.SERVICE_SIGNATURES.get(port, "unknown")
                banner = self._grab_banner(sock, port)
                sock.close()
                return {"port": port, "state": "open", "service": service, "banner": banner}
            sock.close()
        except Exception:
            pass
        return None

    def _grab_banner(self, sock, port):
        try:
            if port in (80, 8080, 8443):
                sock.send(b"HEAD / HTTP/1.0\r\nHost: " + self.target.encode() + b"\r\n\r\n")
            elif port == 22:
                pass
            else:
                sock.send(b"\r\n")
            sock.settimeout(2)
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            return banner[:200] if banner else ""
        except Exception:
            return ""

    def scan(self):
        self.results["scan_start"] = datetime.now().isoformat()
        print(f"[*] Sentinel Recon - Scanning {self.target}")
        print(f"[*] Ports: {len(self.ports)} | Threads: {self.threads} | Timeout: {self.timeout}s")
        print(f"[*] Started: {self.results['scan_start']}")
        print("-" * 60)

        open_ports = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._scan_port, port): port for port in self.ports}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
                    print(f"  [+] {result['port']:>5}/tcp  OPEN  {result['service']}")
                    if result["banner"]:
                        print(f"        Banner: {result['banner'][:80]}")

        self.results["scan_end"] = datetime.now().isoformat()
        self.results["open_ports"] = sorted(open_ports, key=lambda x: x["port"])
        self.results["summary"] = {
            "total_ports_scanned": len(self.ports),
            "open_ports_found": len(open_ports),
            "scan_duration_seconds": round(
                (datetime.fromisoformat(self.results["scan_end"]) -
                 datetime.fromisoformat(self.results["scan_start"])).total_seconds(), 2
            )
        }

        print("-" * 60)
        print(f"[*] Scan complete: {self.results['summary']['open_ports_found']} open ports found")
        print(f"[*] Duration: {self.results['summary']['scan_duration_seconds']}s")
        return self.results

    def export_json(self, filepath=None):
        if not filepath:
            filepath = f"scan_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filepath, "w") as f:
            json.dump(self.results, f, indent=2)
        print(f"[*] Results exported to {filepath}")
        return filepath


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    ports = sys.argv[2] if len(sys.argv) > 2 else "22,80,443,3306,5432,6379,8080"
    scanner = SentinelRecon(target=target, ports=ports, timeout=0.5, threads=20)
    results = scanner.scan()
    scanner.export_json()
    return results


if __name__ == "__main__":
    main()
