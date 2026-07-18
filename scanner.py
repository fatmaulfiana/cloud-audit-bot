"""
scanner.py
Bertugas MENGAMBIL DATA MENTAH kondisi konfigurasi cloud/host target.
Tidak melakukan penilaian baik/buruk (itu tugas audit.py) — scanner hanya
mengumpulkan fakta.

Sumber data yang dipakai semuanya GRATIS / tanpa API key wajib:
  1. SSL certificate  -> modul ssl & socket bawaan Python (langsung ke host:443)
  2. Port scan        -> socket connect scan ke daftar port umum
  3. HTTP security header -> requests ke http/https target
  4. S3 bucket publik -> HTTP request langsung ke endpoint S3 (tanpa kredensial,
     memanfaatkan sifat REST API S3 yang publicly readable jika bucket
     misconfigured)
  5. DNS resolve      -> socket.gethostbyname_ex

Jika kamu punya akses ke Google Cloud / AWS / Azure Free Tier dan sudah
setup service account, kamu bisa tambahkan method scan_gcp_firewall(),
scan_aws_security_group(), dll di kelas ini menggunakan SDK resmi
(google-cloud-compute / boto3) — struktur data hasil (dict) dibuat supaya
mudah diperluas.
"""

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import requests

from config import (
    ABUSEIPDB_API_KEY,
    ABUSEIPDB_MAX_AGE_DAYS,
    COMMON_PORTS,
    RISKY_PORTS,
)
from utils import get_logger, now_iso, safe_get

logger = get_logger(__name__)


class CloudScanner:
    def __init__(self, host: str):
        self.host = host

    # ------------------------------------------------------------------
    # DNS
    # ------------------------------------------------------------------
    def scan_dns(self) -> dict:
        try:
            hostname, aliases, ips = socket.gethostbyname_ex(self.host)
            return {"resolved": True, "hostname": hostname, "ips": ips, "aliases": aliases}
        except socket.gaierror as e:
            return {"resolved": False, "error": str(e)}

    # ------------------------------------------------------------------
    # SSL / TLS CERTIFICATE
    # ------------------------------------------------------------------
    def scan_ssl(self, port: int = 443) -> dict:
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((self.host, port), timeout=6) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert()

            not_after = cert.get("notAfter")
            expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry_dt - datetime.utcnow()).days

            issuer = dict(x[0] for x in cert.get("issuer", []))
            subject = dict(x[0] for x in cert.get("subject", []))

            return {
                "present": True,
                "issuer": issuer.get("organizationName", issuer.get("commonName", "unknown")),
                "subject_cn": subject.get("commonName", "unknown"),
                "expires_at": expiry_dt.isoformat(),
                "days_left": days_left,
            }
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            return {"present": False, "error": f"Tidak dapat konek ke {self.host}:{port} -> {e}"}
        except ssl.SSLError as e:
            return {"present": False, "error": f"SSL error: {e}"}

    # ------------------------------------------------------------------
    # PORT SCAN (connect-scan sederhana, bukan SYN scan agar tidak butuh root)
    # ------------------------------------------------------------------
    def scan_ports(self, ports=None) -> dict:
        ports = ports or COMMON_PORTS
        try:
            ip = socket.gethostbyname(self.host)
        except socket.gaierror as e:
            return {"error": f"Gagal resolve host: {e}"}

        def _check(port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            is_open = sock.connect_ex((ip, port)) == 0
            sock.close()
            return port, is_open

        results = {}
        with ThreadPoolExecutor(max_workers=min(16, len(ports))) as executor:
            futures = [executor.submit(_check, p) for p in ports]
            for future in as_completed(futures):
                port, is_open = future.result()
                results[port] = {
                    "open": is_open,
                    "service_guess": RISKY_PORTS.get(port, "HTTP/HTTPS" if port in (80, 443) else "unknown"),
                }
        return results

    # ------------------------------------------------------------------
    # HTTP SECURITY HEADERS
    # ------------------------------------------------------------------
    def scan_http_headers(self) -> dict:
        url = f"https://{self.host}"
        resp, err = safe_get(url)
        if resp is None:
            # fallback ke http jika https gagal
            url = f"http://{self.host}"
            resp, err = safe_get(url)
        if resp is None:
            return {"reachable": False, "error": err}

        headers = {k: v for k, v in resp.headers.items()}
        return {
            "reachable": True,
            "final_url": resp.url,
            "status_code": resp.status_code,
            "headers": headers,
            "server": headers.get("Server", "unknown"),
        }

    # ------------------------------------------------------------------
    # ABUSEIPDB — reputasi IP (https://www.abuseipdb.com), free tier API
    # ------------------------------------------------------------------
    @staticmethod
    def scan_abuseipdb(ip: str) -> dict:
        if not ABUSEIPDB_API_KEY:
            return {"ip": ip, "checked": False, "error": "ABUSEIPDB_API_KEY belum diatur di .env"}

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": ABUSEIPDB_MAX_AGE_DAYS, "verbose": ""}

        try:
            resp = requests.get(url, headers=headers, params=params, timeout=10)
            if resp.status_code == 401:
                return {"ip": ip, "checked": False, "error": "API key AbuseIPDB tidak valid (401)."}
            if resp.status_code == 429:
                return {"ip": ip, "checked": False, "error": "Kuota harian AbuseIPDB habis (429)."}
            resp.raise_for_status()
            data = resp.json().get("data", {})
            return {
                "ip": ip,
                "checked": True,
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country_code": data.get("countryCode"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "is_tor": data.get("isTor", False),
                "last_reported_at": data.get("lastReportedAt"),
            }
        except requests.exceptions.RequestException as e:
            return {"ip": ip, "checked": False, "error": str(e)}

    # ------------------------------------------------------------------
    # S3 BUCKET PUBLIC CHECK (tanpa kredensial — REST API publik)
    # ------------------------------------------------------------------
    @staticmethod
    def scan_s3_bucket(bucket_name: str) -> dict:
        url = f"https://{bucket_name}.s3.amazonaws.com/"
        resp, err = safe_get(url)
        if resp is None:
            return {"bucket": bucket_name, "reachable": False, "error": err}

        # Status 200 dengan listing XML -> bucket & isinya bisa di-list publik
        # Status 403 -> bucket ada tapi listing ditolak (lebih aman)
        # Status 404 -> nama bucket tidak ada / typo
        publicly_listable = resp.status_code == 200 and "<ListBucketResult" in resp.text
        return {
            "bucket": bucket_name,
            "reachable": True,
            "status_code": resp.status_code,
            "publicly_listable": publicly_listable,
        }

    # ------------------------------------------------------------------
    # AGREGASI SEMUA SCAN
    # ------------------------------------------------------------------
    def run_full_scan(self, ports=None, s3_buckets=None) -> dict:
        logger.info(f"Mulai scan untuk target: {self.host}")
        dns_info = self.scan_dns()
        ips = dns_info.get("ips", []) if dns_info.get("resolved") else []

        result = {
            "host": self.host,
            "scanned_at": now_iso(),
            "dns": dns_info,
            "ssl": self.scan_ssl(),
            "ports": self.scan_ports(ports),
            "http_headers": self.scan_http_headers(),
            "s3_buckets": [self.scan_s3_bucket(b) for b in (s3_buckets or [])],
            "abuseipdb": [self.scan_abuseipdb(ip) for ip in ips[:3]],  # batasi max 3 IP/scan
        }
        logger.info(f"Selesai scan untuk target: {self.host}")
        return result
