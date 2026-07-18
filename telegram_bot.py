"""
telegram_bot.py
Mengirim notifikasi hasil audit ke Telegram menggunakan Telegram Bot API
(gratis, tidak perlu kartu kredit). Cara membuat bot:
  1. Chat ke @BotFather di Telegram -> /newbot -> ikuti instruksi -> dapat TOKEN
  2. Chat bot barumu sekali, lalu buka:
     https://api.telegram.org/bot<TOKEN>/getUpdates
     untuk mendapatkan chat_id kamu
  3. Isi TELEGRAM_BOT_TOKEN dan TELEGRAM_CHAT_ID di file .env
"""

import requests

from config import NOTIFY_MIN_SEVERITY, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
from utils import SEVERITY_EMOJI, get_logger, severity_at_least

logger = get_logger(__name__)

API_BASE = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"


def _is_configured() -> bool:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        logger.warning("TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID belum diatur di .env — notifikasi dilewati.")
        return False
    return True


def send_message(text: str) -> bool:
    if not _is_configured():
        return False
    try:
        resp = requests.post(
            f"{API_BASE}/sendMessage",
            data={"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "HTML"},
            timeout=10,
        )
        resp.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Gagal mengirim pesan Telegram: {e}")
        return False


def send_document(filepath: str, caption: str = "") -> bool:
    if not _is_configured():
        return False
    try:
        with open(filepath, "rb") as f:
            resp = requests.post(
                f"{API_BASE}/sendDocument",
                data={"chat_id": TELEGRAM_CHAT_ID, "caption": caption},
                files={"document": f},
                timeout=30,
            )
        resp.raise_for_status()
        return True
    except (requests.exceptions.RequestException, FileNotFoundError) as e:
        logger.error(f"Gagal mengirim dokumen Telegram: {e}")
        return False


def build_summary_message(host: str, findings: list, risk_score: int) -> str:
    """Buat teks ringkasan hasil audit untuk dikirim ke Telegram."""
    lines = [f"<b>🔍 Laporan Audit Cloud — {host}</b>", f"Skor risiko: <b>{risk_score}/100</b>", ""]

    notifiable = [f for f in findings if severity_at_least(f["severity"], NOTIFY_MIN_SEVERITY)]

    if not notifiable:
        lines.append("✅ Tidak ada temuan signifikan pada level ambang notifikasi.")
        return "\n".join(lines)

    counts = {}
    for f in notifiable:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    count_line = " | ".join(f"{SEVERITY_EMOJI.get(s,'')} {s}: {c}" for s, c in counts.items())
    lines.append(count_line)
    lines.append("")

    for f in notifiable[:10]:  # batasi agar pesan tidak terlalu panjang
        emoji = SEVERITY_EMOJI.get(f["severity"], "")
        lines.append(f"{emoji} <b>[{f['category']}] {f['title']}</b>")
        lines.append(f"↳ {f['description']}")
        lines.append(f"💡 {f['recommendation']}")
        lines.append("")

    if len(notifiable) > 10:
        lines.append(f"...dan {len(notifiable) - 10} temuan lainnya (lihat laporan PDF terlampir).")

    return "\n".join(lines)


def notify_audit_result(host: str, findings: list, risk_score: int, pdf_path: str = None):
    """Kirim ringkasan teks + (opsional) lampiran PDF ke Telegram."""
    message = build_summary_message(host, findings, risk_score)
    sent = send_message(message)
    if sent and pdf_path:
        send_document(pdf_path, caption=f"Laporan lengkap audit {host}")
    return sent
