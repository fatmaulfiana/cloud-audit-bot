# Cloud Audit Bot

Sistem audit otomatis konfigurasi keamanan cloud menggunakan Python dan Free API/tools,
dengan notifikasi Telegram dan laporan PDF.

Dibuat untuk tugas **"Perancangan dan Implementasi Sistem Aman Berbasis Cloud"**.

---

## 1. Arsitektur Sistem

```
                    ┌─────────────┐
                    │   config.py │  (kredensial & pengaturan dari .env)
                    └──────┬──────┘
                           │
   ┌───────────────────────┼────────────────────────┐
   │                       ▼                        │
   │   ┌─────────────┐   ┌───────────┐   ┌────────┐ │
   │   │ scanner.py  │──▶│ audit.py  │──▶│database│ │
   │   │ (ambil data)│   │(nilai rule)│   │.py(DB)│ │
   │   └─────────────┘   └─────┬─────┘   └────────┘ │
   │            app.py (orkestrator)  │              │
   │                              ▼                  │
   │                     ┌───────────────┐            │
   │                     │  report.py    │──▶ PDF     │
   │                     └───────┬───────┘            │
   │                             ▼                     │
   │                     ┌───────────────┐             │
   │                     │telegram_bot.py│──▶ Telegram │
   │                     └───────────────┘             │
   └─────────────────────────────────────────────────────┘
```

**Alur kerja:**
1. `scanner.py` mengambil data konfigurasi mentah dari target (SSL certificate,
   status port firewall, HTTP security header, dan public bucket storage) — semua
   memakai koneksi langsung / API gratis, tanpa API key berbayar.
2. `audit.py` menilai data tersebut terhadap rule keamanan (mirip prinsip CIS
   Benchmark) dan menghasilkan daftar temuan (*findings*) beserta level severity
   (LOW/MEDIUM/HIGH/CRITICAL) dan rekomendasi mitigasi.
3. `database.py` menyimpan setiap hasil scan dan temuan ke SQLite (`database/audit.db`)
   sehingga ada histori/log audit dari waktu ke waktu.
4. `report.py` membuat laporan PDF profesional dari hasil audit.
5. `telegram_bot.py` mengirim ringkasan hasil + lampiran PDF ke Telegram secara
   otomatis (fungsi *logging/monitoring* dan *alerting*).
6. `app.py` adalah program utama yang mengorkestrasi seluruh alur di atas, bisa
   dijalankan sekali (`--host`) atau berulang otomatis (`--loop`, mirip cron job).

---

## 2. Instalasi

```bash
git clone <repo-kamu>
cd cloud-audit-bot
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` dan isi:
- `TELEGRAM_BOT_TOKEN` & `TELEGRAM_CHAT_ID` — buat bot via **@BotFather** di Telegram
  (gratis), lalu ambil chat_id dari `https://api.telegram.org/bot<TOKEN>/getUpdates`.
- `TARGET_HOSTS` — domain/IP publik VM cloud gratis kamu (Google Cloud Free Tier,
  Oracle Cloud Free Tier, AWS EC2 Free Tier, Render, dsb).
- `S3_BUCKETS` — (opsional) nama bucket S3 yang mau dicek expose publiknya.

## 3. Menjalankan

Ada dua cara menjalankan Cloud Audit Bot: **CLI** (`app.py`, target diatur di `.env`)
atau **Web Dashboard** (`webapp.py`, target dikelola langsung dari browser — direkomendasikan).

### 3a. Mode Web Dashboard (disarankan)

```bash
python3 webapp.py
```

Buka `http://localhost:5000` di browser. Dari dashboard kamu bisa:
- Menambahkan domain/IP baru untuk diaudit (tombol **+ Tambah target**)
- Menjalankan scan kapan saja (tombol **▶ Scan sekarang**), dengan opsi
  centang "kirim ke Telegram"
- Melihat riwayat scan & detail temuan tiap target (tombol **Riwayat**)
- Mengunduh laporan PDF tiap scan
- Menghapus target yang tidak diperlukan lagi

Semua target yang ditambahkan lewat dashboard disimpan permanen di
`database/audit.db` (tabel `targets`), jadi tidak perlu edit `.env` setiap
kali ingin mengaudit domain baru.

### 3b. Mode CLI

```bash
# Audit sekali jalan untuk semua host di .env -> TARGET_HOSTS
python3 app.py

# Audit host tertentu saja
python3 app.py --host myserver.example.com

# Audit terus-menerus (interval diatur di .env -> SCAN_INTERVAL_SECONDS)
python3 app.py --loop

# Uji coba tanpa kirim ke Telegram
python3 app.py --no-telegram
```

Hasil laporan PDF otomatis tersimpan di folder `reports/`, dan seluruh histori
scan/temuan tersimpan di `database/audit.db` (dipakai bersama oleh CLI dan
web dashboard, jadi hasil scan dari kedua mode saling terlihat).

---

## 3c. Mode Otomatis Terjadwal (GitHub Actions) — direkomendasikan untuk "bukti sistem berjalan otomatis"

Menjalankan bot 24 jam di server (Render/Railway) itu boros dan free tier-nya
sering *spin-down*. Cara yang lebih pas untuk tugas kuliah (dan **gratis tanpa
batas** untuk repo publik) adalah pakai **GitHub Actions terjadwal (cron)** —
tidak perlu server yang harus terus menyala.

**Setup:**

1. Push project ini ke GitHub (repo publik agar Actions-nya gratis tanpa batas;
   kalau privat masih dapat jatah 2000 menit/bulan gratis, tetap cukup).
2. Buka repo di GitHub → **Settings → Secrets and variables → Actions**.
3. Tab **Secrets** (data rahasia), tambahkan:
   - `TELEGRAM_BOT_TOKEN`
   - `TELEGRAM_CHAT_ID`
   - `ABUSEIPDB_API_KEY`
4. Tab **Variables** (data tidak rahasia), tambahkan:
   - `TARGET_HOSTS` → contoh: `notes-app.vercel.app` atau domain final kamu
   - `S3_BUCKETS` → (opsional, kosongkan jika tidak dipakai)
   - `NOTIFY_MIN_SEVERITY` → contoh: `MEDIUM`
5. Selesai — workflow di `.github/workflows/scheduled-audit.yml` akan:
   - Berjalan otomatis **setiap 6 jam** (bisa diubah di baris `cron:`)
   - Bisa dipicu **manual** kapan saja lewat tab **Actions → Scheduled Cloud
     Security Audit → Run workflow** (bagus untuk didemokan di video)
   - Mengirim hasil ke Telegram
   - **Meng-commit balik** `database/audit.db` dan `reports/*.pdf` ke repo,
     jadi histori audit tersimpan permanen dan terlihat oleh siapa pun yang
     membuka repo GitHub kamu — ini bukti "logging" yang kuat untuk laporan
   - Mengunggah laporan PDF sebagai **artifact** (bisa diunduh dari tab Actions)

   📸 **Screenshot untuk laporan**: tab **Actions** yang menunjukkan riwayat
   run (hijau = sukses), dan isi satu run yang menunjukkan log tiap step.

## 4. Pemetaan Rule Audit ke Aspek Keamanan (untuk Laporan Teknis)

| Aspek Keamanan   | Implementasi di Proyek Ini |
|-------------------|----------------------------|
| **Enkripsi (in-transit)** | `scan_ssl()` mengecek sertifikat TLS aktif & masa berlaku (rule di `audit.py::check_ssl`) |
| **Firewall / Network Security** | `scan_ports()` mendeteksi port berisiko (SSH, RDP, DB) yang terbuka ke publik (`audit.py::check_ports`) |
| **IAM / Access Control** | Temuan port administrasi/database terbuka direkomendasikan dibatasi via Security Group/VPC Firewall (least privilege) |
| **Backup & Storage Security** | `scan_s3_bucket()` mengecek bucket storage yang bisa di-list publik (`audit.py::check_storage`) |
| **Logging & Monitoring** | Setiap hasil scan & temuan dicatat ke SQLite (`database.py`) sebagai log historis, dan dikirim real-time ke Telegram (`telegram_bot.py`) |
| **Hardening HTTP** | `scan_http_headers()` mengecek header keamanan wajib (HSTS, CSP, X-Frame-Options, dll) |
| **Threat Intelligence** | `scan_abuseipdb()` mengecek reputasi IP target ke [AbuseIPDB](https://www.abuseipdb.com) (`audit.py::check_abuseipdb`) — mendeteksi jika IP pernah dilaporkan komunitas karena aktivitas mencurigakan |

## 5. Cara Deploy dengan Layanan Cloud Gratis (contoh)

1. **VM target yang diaudit**: buat instance gratis di Google Cloud Free Tier
   (f1-micro) / Oracle Cloud Free Tier / AWS EC2 t2.micro, install web server
   sederhana (nginx), aktifkan SSL gratis dengan **Let's Encrypt (certbot)**,
   dan atur firewall/security group.
2. **Hosting bot audit ini**: jalankan di Render.com / Railway.app / Fly.io
   (free tier) dengan mode `--loop` sehingga scan berjalan otomatis berkala,
   atau jadwalkan dengan cron job di VM yang sama.
3. **Notifikasi**: Telegram Bot API (gratis tanpa batas wajar).
4. **(Opsional) Monitoring uptime tambahan**: UptimeRobot free plan untuk
   memantau apakah target masih online, melengkapi hasil audit konfigurasi ini.

## 6. Struktur Proyek

```
cloud-audit-bot/
├── app.py                # Program utama / orkestrator (mode CLI)
├── webapp.py              # Web dashboard (Flask) — kelola target & scan dari browser
├── audit.py               # Rule engine penilaian keamanan
├── telegram_bot.py        # Kirim notifikasi & laporan ke Telegram
├── config.py              # Konfigurasi & environment variable
├── requirements.txt
├── report.py              # Generate laporan PDF
├── database.py            # Penyimpanan histori & daftar target (SQLite)
├── scanner.py              # Pengambilan data konfigurasi dari target
├── utils.py                # Fungsi bantu (logging, severity, dll)
├── templates/              # Template HTML untuk web dashboard
│   ├── base.html
│   ├── dashboard.html
│   └── history.html
├── .env.example
├── reports/                # Output laporan PDF
└── database/
    └── audit.db
```

## 7. Batasan & Pengembangan Lanjutan

- Port scan pada proyek ini adalah *connect-scan* sederhana (tanpa root/raw
  socket), cukup untuk mendeteksi port yang benar-benar dapat diakses dari
  posisi bot dijalankan.
- Untuk audit yang lebih dalam terhadap layanan resmi cloud (IAM policy,
  firewall rule detail, dsb), tambahkan method baru di `scanner.py` memakai
  SDK resmi masing-masing provider (`google-cloud-compute`, `boto3`, dst)
  dengan service account/API key sendiri — struktur data hasil scan (dict)
  sudah dirancang agar mudah diperluas tanpa mengubah `audit.py`/`report.py`.
- Disarankan menjalankan bot ini dari luar jaringan target (misal cloud hosting
  gratis terpisah) agar hasil port scan merepresentasikan pandangan penyerang
  dari internet publik.
