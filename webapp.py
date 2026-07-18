"""
webapp.py
Dashboard web sederhana (Flask) untuk Cloud Audit Bot.

Fitur:
  - Tambah/hapus domain atau IP yang ingin diaudit langsung dari browser
    (tidak perlu edit .env / restart aplikasi setiap ganti target)
  - Tombol "Scan Sekarang" untuk menjalankan audit on-demand
  - Melihat histori scan & detail temuan per target
  - Unduh laporan PDF hasil scan

Menjalankan:
    python3 webapp.py
Lalu buka http://localhost:5000 (atau sesuai WEB_PORT di .env)
"""

import os

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

import config
from app import run_audit_for_host
from database import (
    get_history,
    get_findings_for_scan,
    init_db,
    list_targets,
    add_target,
    remove_target,
    get_target,
)
from utils import get_logger

logger = get_logger("webapp")

app = Flask(__name__)
app.secret_key = config.FLASK_SECRET_KEY

init_db()


def _ring_color(score: int) -> str:
    if score >= 75:
        return "var(--critical)"
    if score >= 50:
        return "var(--high)"
    if score >= 20:
        return "var(--medium)"
    return "var(--low)"


@app.route("/")
def dashboard():
    targets = list_targets()
    # lampirkan info scan terakhir untuk tiap target
    for t in targets:
        history = get_history(t["host"], limit=1)
        t["last_scan"] = history[0] if history else None
        t["ring_color"] = _ring_color(t["last_scan"]["risk_score"]) if t["last_scan"] else "var(--border)"
    return render_template("dashboard.html", targets=targets)


@app.route("/targets/add", methods=["POST"])
def add_target_route():
    host = request.form.get("host", "").strip()
    s3_buckets = request.form.get("s3_buckets", "").strip()

    if not host:
        flash("Nama domain/IP tidak boleh kosong.", "error")
        return redirect(url_for("dashboard"))

    # sanitasi ringan: buang skema/path jika user tempel URL lengkap
    host = host.replace("https://", "").replace("http://", "").split("/")[0]

    if add_target(host, s3_buckets):
        flash(f"Target '{host}' berhasil ditambahkan.", "success")
    else:
        flash(f"Target '{host}' sudah ada di daftar.", "error")
    return redirect(url_for("dashboard"))


@app.route("/targets/<host>/delete", methods=["POST"])
def delete_target_route(host):
    remove_target(host)
    flash(f"Target '{host}' dihapus dari daftar.", "success")
    return redirect(url_for("dashboard"))


@app.route("/targets/<host>/scan", methods=["POST"])
def scan_target_route(host):
    target = get_target(host)
    if not target:
        abort(404)

    s3_buckets = [b.strip() for b in (target.get("s3_buckets") or "").split(",") if b.strip()]
    send_telegram = request.form.get("send_telegram") == "on"

    try:
        # override sementara daftar bucket khusus target ini
        original_buckets = config.S3_BUCKETS
        config.S3_BUCKETS = s3_buckets or original_buckets
        result = run_audit_for_host(host, send_telegram=send_telegram)
        config.S3_BUCKETS = original_buckets

        flash(
            f"Scan '{host}' selesai. Risk score: {result['risk_score']}/100, "
            f"{result['findings_count']} temuan.",
            "success",
        )
    except Exception as e:
        logger.exception(f"Scan gagal untuk {host}: {e}")
        flash(f"Scan '{host}' gagal: {e}", "error")

    return redirect(url_for("history_route", host=host))


@app.route("/history/<host>")
def history_route(host):
    target = get_target(host)
    if not target:
        abort(404)

    scans = get_history(host, limit=20)
    for s in scans:
        s["findings"] = get_findings_for_scan(s["id"])
        s["ring_color"] = _ring_color(s["risk_score"])

    return render_template("history.html", host=host, scans=scans)


@app.route("/report/<int:scan_id>")
def download_report(scan_id):
    from database import get_connection

    with get_connection() as conn:
        row = conn.execute("SELECT report_path FROM scans WHERE id = ?", (scan_id,)).fetchone()

    if not row or not row["report_path"] or not os.path.exists(row["report_path"]):
        abort(404)

    return send_file(row["report_path"], as_attachment=True)


if __name__ == "__main__":
    logger.info(f"Dashboard berjalan di http://{config.WEB_HOST}:{config.WEB_PORT}")
    app.run(host=config.WEB_HOST, port=config.WEB_PORT, debug=False)
