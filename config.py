"""
config.py
Konfigurasi terpusat untuk Cloud Audit Bot.
Semua nilai sensitif (token, chat id, api key) diambil dari environment
variable / file .env agar TIDAK di-hardcode dan aman jika repo di-push
ke GitHub (tambahkan .env ke .gitignore!).
"""

import os
from dotenv import load_dotenv

# Load variabel dari file .env jika ada (letakkan file .env di root project)
load_dotenv()


# ---------------------------------------------------------------------------
# TELEGRAM BOT
# ---------------------------------------------------------------------------
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

# ---------------------------------------------------------------------------
# TARGET YANG AKAN DIAUDIT
# Bisa berupa domain (untuk cek SSL/HTTP header) atau IP publik VM cloud
# (Google Cloud Free Tier / Oracle Free Tier / AWS EC2 Free Tier, dst).
# Bisa diisi lebih dari satu, dipisah koma di .env -> TARGET_HOSTS=host1,host2
# ---------------------------------------------------------------------------
TARGET_HOSTS = [h.strip() for h in os.getenv("TARGET_HOSTS", "example.com").split(",") if h.strip()]

# (opsional) Nama S3 bucket / bucket publik lain yang mau dicek expose-nya
S3_BUCKETS = [b.strip() for b in os.getenv("S3_BUCKETS", "").split(",") if b.strip()]

# ---------------------------------------------------------------------------
# ABUSEIPDB API (https://www.abuseipdb.com) — free tier: 1000 request/hari
# Dipakai untuk mengecek reputasi IP target (apakah pernah dilaporkan
# terlibat serangan/abuse dari internet).
# ---------------------------------------------------------------------------
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_MAX_AGE_DAYS = int(os.getenv("ABUSEIPDB_MAX_AGE_DAYS", 90))

# Skor confidence (0-100) dari AbuseIPDB yang dianggap HIGH / CRITICAL
ABUSEIPDB_HIGH_THRESHOLD = int(os.getenv("ABUSEIPDB_HIGH_THRESHOLD", 25))
ABUSEIPDB_CRITICAL_THRESHOLD = int(os.getenv("ABUSEIPDB_CRITICAL_THRESHOLD", 75))

# ---------------------------------------------------------------------------
# PORT YANG DIANGGAP BERISIKO JIKA TERBUKA KE PUBLIK
# ---------------------------------------------------------------------------
RISKY_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

# Port tambahan yang ikut dipindai (selain daftar berisiko di atas)
COMMON_PORTS = [80, 443] + list(RISKY_PORTS.keys())

# ---------------------------------------------------------------------------
# THRESHOLD AUDIT
# ---------------------------------------------------------------------------
SSL_EXPIRY_WARNING_DAYS = int(os.getenv("SSL_EXPIRY_WARNING_DAYS", 30))
SSL_EXPIRY_CRITICAL_DAYS = int(os.getenv("SSL_EXPIRY_CRITICAL_DAYS", 7))

# Header keamanan HTTP wajib yang dicek
REQUIRED_SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "Referrer-Policy",
]

# ---------------------------------------------------------------------------
# PATH
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database", "audit.db")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

# ---------------------------------------------------------------------------
# JADWAL SCAN OTOMATIS (mode --loop di app.py), dalam detik
# ---------------------------------------------------------------------------
SCAN_INTERVAL_SECONDS = int(os.getenv("SCAN_INTERVAL_SECONDS", 3600))  # default 1 jam

# Hanya kirim notifikasi Telegram untuk temuan dengan level >= ini
NOTIFY_MIN_SEVERITY = os.getenv("NOTIFY_MIN_SEVERITY", "MEDIUM")  # LOW/MEDIUM/HIGH/CRITICAL

# ---------------------------------------------------------------------------
# WEB DASHBOARD (webapp.py)
# ---------------------------------------------------------------------------
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "dev-secret-change-this")
WEB_HOST = os.getenv("WEB_HOST", "0.0.0.0")
# Platform seperti Render/Railway/Heroku menyuntikkan env var PORT secara
# otomatis dan mengharuskan app listen di port tersebut -> prioritaskan PORT,
# baru fallback ke WEB_PORT (untuk kebutuhan lokal) lalu default 5000.
WEB_PORT = int(os.getenv("PORT", os.getenv("WEB_PORT", 5000)))
