"""
app.py
Entry point / program utama Cloud Audit Bot.

Alur kerja:
  1. Ambil daftar target dari config.py (atau argumen CLI --host)
  2. scanner.py  -> ambil data konfigurasi mentah
  3. audit.py    -> nilai data terhadap rule keamanan -> findings + risk score
  4. database.py -> simpan hasil scan & findings ke SQLite
  5. report.py   -> generate laporan PDF
  6. telegram_bot.py -> kirim ringkasan + PDF ke Telegram

Contoh pemakaian:
    python app.py                       # audit semua TARGET_HOSTS di config.py sekali jalan
    python app.py --host example.com    # audit satu host tertentu
    python app.py --loop                # jalankan terus-menerus sesuai SCAN_INTERVAL_SECONDS
    python app.py --no-telegram         # jalankan tanpa kirim notifikasi (mode uji coba)
"""

import argparse
import time

import config
from audit import AuditEngine
from database import (
    get_findings_for_scan,
    init_db,
    save_findings,
    save_scan,
    update_scan_report_path,
)
from report import generate_pdf_report
from scanner import CloudScanner
from telegram_bot import notify_audit_result
from utils import get_logger

logger = get_logger("app")


def run_audit_for_host(host: str, send_telegram: bool = True) -> dict:
    """Jalankan satu siklus penuh audit untuk satu host, kembalikan ringkasan hasil."""
    scanner = CloudScanner(host)
    scan_result = scanner.run_full_scan(
        ports=config.COMMON_PORTS,
        s3_buckets=config.S3_BUCKETS,
    )

    engine = AuditEngine(scan_result)
    findings = engine.run_all()
    risk_score = engine.risk_score()

    scan_id = save_scan(host, scan_result, risk_score)
    save_findings(scan_id, findings)
    stored_findings = get_findings_for_scan(scan_id)

    pdf_path = generate_pdf_report(host, scan_result, findings, risk_score)
    update_scan_report_path(scan_id, pdf_path)

    if send_telegram:
        notify_audit_result(host, findings, risk_score, pdf_path)

    logger.info(f"[{host}] Risk score: {risk_score}/100 | Findings: {len(findings)} | Report: {pdf_path}")

    return {
        "host": host,
        "scan_id": scan_id,
        "risk_score": risk_score,
        "findings_count": len(findings),
        "report_path": pdf_path,
        "findings": stored_findings,
    }


def run_once(hosts, send_telegram: bool = True):
    init_db()
    results = []
    for host in hosts:
        try:
            results.append(run_audit_for_host(host, send_telegram=send_telegram))
        except Exception as e:
            logger.exception(f"Gagal audit host {host}: {e}")
    return results


def run_loop(hosts, send_telegram: bool = True):
    init_db()
    logger.info(f"Mode loop aktif. Interval: {config.SCAN_INTERVAL_SECONDS} detik. Tekan Ctrl+C untuk berhenti.")
    try:
        while True:
            for host in hosts:
                try:
                    run_audit_for_host(host, send_telegram=send_telegram)
                except Exception as e:
                    logger.exception(f"Gagal audit host {host}: {e}")
            logger.info(f"Menunggu {config.SCAN_INTERVAL_SECONDS} detik sebelum scan berikutnya...")
            time.sleep(config.SCAN_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        logger.info("Dihentikan oleh pengguna (Ctrl+C).")


def main():
    parser = argparse.ArgumentParser(description="Cloud Audit Bot - audit otomatis konfigurasi keamanan cloud")
    parser.add_argument("--host", action="append", help="Target host tertentu (bisa diulang beberapa kali)")
    parser.add_argument("--loop", action="store_true", help="Jalankan berulang sesuai SCAN_INTERVAL_SECONDS")
    parser.add_argument("--no-telegram", action="store_true", help="Nonaktifkan notifikasi Telegram (uji coba lokal)")
    args = parser.parse_args()

    hosts = args.host if args.host else config.TARGET_HOSTS
    send_telegram = not args.no_telegram

    if not hosts:
        logger.error("Tidak ada target host. Set TARGET_HOSTS di .env atau gunakan --host <domain>.")
        return

    if args.loop:
        run_loop(hosts, send_telegram=send_telegram)
    else:
        run_once(hosts, send_telegram=send_telegram)


if __name__ == "__main__":
    main()
