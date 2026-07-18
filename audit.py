"""
audit.py
Logika audit / rule engine.
Menerima data mentah dari scanner.py, lalu menerapkan aturan keamanan
(mirip prinsip CIS Benchmark / OWASP) untuk menghasilkan daftar temuan
(findings) beserta level severity dan rekomendasi mitigasi.

Setiap finding berbentuk dict:
{
    "category": str,        # contoh: "SSL/TLS", "Firewall", "HTTP Header", "Storage"
    "severity": str,        # LOW / MEDIUM / HIGH / CRITICAL
    "title": str,
    "description": str,
    "recommendation": str,
}
"""

from config import (
    ABUSEIPDB_CRITICAL_THRESHOLD,
    ABUSEIPDB_HIGH_THRESHOLD,
    REQUIRED_SECURITY_HEADERS,
    RISKY_PORTS,
    SSL_EXPIRY_CRITICAL_DAYS,
    SSL_EXPIRY_WARNING_DAYS,
)


class AuditEngine:
    def __init__(self, scan_result: dict):
        self.scan = scan_result
        self.findings = []

    # ------------------------------------------------------------------
    def _add(self, category, severity, title, description, recommendation):
        self.findings.append({
            "category": category,
            "severity": severity,
            "title": title,
            "description": description,
            "recommendation": recommendation,
        })

    # ------------------------------------------------------------------
    # RULE 1: Sertifikat SSL/TLS
    # ------------------------------------------------------------------
    def check_ssl(self):
        ssl_data = self.scan.get("ssl", {})

        if not ssl_data.get("present"):
            self._add(
                category="SSL/TLS",
                severity="CRITICAL",
                title="Sertifikat SSL tidak ditemukan / tidak dapat diverifikasi",
                description=ssl_data.get("error", "Koneksi HTTPS ke host gagal."),
                recommendation=(
                    "Aktifkan HTTPS menggunakan sertifikat gratis dari Let's Encrypt "
                    "(certbot) atau proxy Cloudflare (mode Full/Strict SSL)."
                ),
            )
            return

        days_left = ssl_data.get("days_left", 0)
        if days_left < 0:
            self._add("SSL/TLS", "CRITICAL", "Sertifikat SSL sudah kedaluwarsa",
                       f"Sertifikat untuk {ssl_data.get('subject_cn')} kedaluwarsa "
                       f"{abs(days_left)} hari lalu.",
                       "Segera perbarui sertifikat (certbot renew) dan aktifkan auto-renewal.")
        elif days_left <= SSL_EXPIRY_CRITICAL_DAYS:
            self._add("SSL/TLS", "CRITICAL", "Sertifikat SSL akan kedaluwarsa segera",
                       f"Sertifikat tersisa {days_left} hari sebelum kedaluwarsa.",
                       "Perbarui sertifikat sekarang, jangan menunggu hingga jatuh tempo.")
        elif days_left <= SSL_EXPIRY_WARNING_DAYS:
            self._add("SSL/TLS", "MEDIUM", "Sertifikat SSL mendekati masa kedaluwarsa",
                       f"Sertifikat tersisa {days_left} hari sebelum kedaluwarsa.",
                       "Jadwalkan perpanjangan otomatis (certbot renew --dry-run) sebelum jatuh tempo.")

    # ------------------------------------------------------------------
    # RULE 2: Port berisiko terbuka ke publik (firewall)
    # ------------------------------------------------------------------
    def check_ports(self):
        ports = self.scan.get("ports", {})
        if "error" in ports:
            return

        for port, info in ports.items():
            port = int(port)
            if info.get("open") and port in RISKY_PORTS:
                service = RISKY_PORTS[port]
                self._add(
                    category="Firewall/IAM",
                    severity="HIGH" if port in (3389, 23, 6379, 27017, 9200) else "MEDIUM",
                    title=f"Port {port} ({service}) terbuka ke publik",
                    description=(
                        f"Port {port} yang digunakan oleh layanan {service} terdeteksi "
                        f"terbuka dan dapat diakses dari internet."
                    ),
                    recommendation=(
                        f"Batasi akses port {port} hanya dari IP tertentu melalui firewall "
                        f"cloud (Security Group / VPC Firewall Rule), atau gunakan VPN/SSH "
                        f"tunneling. Jangan expose layanan database/administrasi langsung ke publik."
                    ),
                )

    # ------------------------------------------------------------------
    # RULE 3: HTTP security headers
    # ------------------------------------------------------------------
    def check_http_headers(self):
        http_data = self.scan.get("http_headers", {})
        if not http_data.get("reachable"):
            self._add("HTTP Header", "MEDIUM", "Host tidak dapat diakses via HTTP/HTTPS",
                       http_data.get("error", "Tidak ada respons dari server."),
                       "Pastikan web server berjalan dan dapat diakses publik jika memang dimaksudkan.")
            return

        headers = http_data.get("headers", {})
        missing = [h for h in REQUIRED_SECURITY_HEADERS if h not in headers]

        for h in missing:
            self._add(
                category="HTTP Header",
                severity="LOW" if h != "Strict-Transport-Security" else "MEDIUM",
                title=f"Header keamanan '{h}' tidak ditemukan",
                description=f"Response HTTP dari {self.scan.get('host')} tidak menyertakan header {h}.",
                recommendation=self._header_recommendation(h),
            )

    @staticmethod
    def _header_recommendation(header: str) -> str:
        mapping = {
            "Strict-Transport-Security": "Tambahkan header HSTS agar browser selalu memaksa koneksi HTTPS.",
            "X-Frame-Options": "Tambahkan 'X-Frame-Options: DENY' atau 'SAMEORIGIN' untuk mencegah clickjacking.",
            "X-Content-Type-Options": "Tambahkan 'X-Content-Type-Options: nosniff' untuk mencegah MIME sniffing.",
            "Content-Security-Policy": "Terapkan CSP untuk membatasi sumber script/style yang boleh dimuat.",
            "Referrer-Policy": "Tambahkan Referrer-Policy (misal 'no-referrer-when-downgrade') untuk kontrol kebocoran referrer.",
        }
        return mapping.get(header, "Tambahkan header keamanan ini pada konfigurasi web server.")

    # ------------------------------------------------------------------
    # RULE 4: Reputasi IP (AbuseIPDB) — apakah IP target pernah dilaporkan
    # terlibat aktivitas mencurigakan (brute-force, spam, scanning, dll)
    # ------------------------------------------------------------------
    def check_abuseipdb(self):
        for entry in self.scan.get("abuseipdb", []):
            if not entry.get("checked"):
                continue  # key belum diatur / rate limit -> tidak dinilai, bukan error keamanan

            score = entry.get("abuse_confidence_score", 0)
            reports = entry.get("total_reports", 0)
            ip = entry.get("ip")

            if score >= ABUSEIPDB_CRITICAL_THRESHOLD:
                severity = "CRITICAL"
            elif score >= ABUSEIPDB_HIGH_THRESHOLD:
                severity = "HIGH"
            elif reports > 0:
                severity = "LOW"
            else:
                continue  # bersih, tidak perlu jadi temuan

            self._add(
                category="Threat Intelligence",
                severity=severity,
                title=f"IP {ip} memiliki riwayat reputasi buruk (AbuseIPDB score {score}/100)",
                description=(
                    f"IP ini telah dilaporkan sebanyak {reports} kali oleh komunitas AbuseIPDB "
                    f"(ISP: {entry.get('isp', 'tidak diketahui')}, terakhir dilaporkan: "
                    f"{entry.get('last_reported_at') or 'tidak ada data'})."
                ),
                recommendation=(
                    "Periksa apakah IP ini benar milik infrastruktur kamu (bukan IP shared/"
                    "CDN yang dipakai bersama pihak lain). Jika ini server sendiri, cek log "
                    "untuk aktivitas anomali (brute-force, spam relay, scanning keluar), lalu "
                    "terapkan rate-limiting, fail2ban, dan tinjau kembali aturan firewall."
                ),
            )

    # ------------------------------------------------------------------
    # RULE 5: Storage (S3 bucket) publik
    # ------------------------------------------------------------------
    def check_storage(self):
        for bucket in self.scan.get("s3_buckets", []):
            if bucket.get("publicly_listable"):
                self._add(
                    category="Storage/Backup",
                    severity="CRITICAL",
                    title=f"Bucket '{bucket['bucket']}' dapat di-list publik",
                    description=(
                        "Isi bucket storage dapat dilihat oleh siapa saja tanpa autentikasi. "
                        "Ini berisiko tinggi terhadap kebocoran data/backup."
                    ),
                    recommendation=(
                        "Ubah Bucket Policy / ACL menjadi private, nonaktifkan public listing, "
                        "dan aktifkan enkripsi at-rest (SSE-S3/SSE-KMS) serta versioning untuk backup."
                    ),
                )

    # ------------------------------------------------------------------
    # JALANKAN SEMUA RULE
    # ------------------------------------------------------------------
    def run_all(self) -> list:
        self.check_ssl()
        self.check_ports()
        self.check_http_headers()
        self.check_abuseipdb()
        self.check_storage()
        return self.findings

    def risk_score(self) -> int:
        """Skor risiko sederhana 0-100 berdasarkan severity temuan."""
        weights = {"LOW": 2, "MEDIUM": 5, "HIGH": 12, "CRITICAL": 25}
        score = sum(weights.get(f["severity"], 0) for f in self.findings)
        return min(score, 100)
