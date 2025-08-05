from flask import Flask, request, jsonify
from threading import Thread
import logging
import time
from scanner import WebVulnScanner
from backend.utils.notification import send_email_alert, send_sms_alert
from backend.scanner.scheduler import scheduled_scan

app = Flask(__name__)


def run_manual_scan(target_url, include_subdomains, generate_report_flag, user_email, user_phone):
    try:
        start_time = time.time()
        scanner = WebVulnScanner(
            target_url=target_url, max_depth=2, max_workers=10, include_subdomains=include_subdomains
        )
        vulnerabilities = scanner.run()
        end_time = time.time()
        duration = round(end_time - start_time, 2)

        result = {
            "scan_duration": duration,
            "vulnerabilities": vulnerabilities
        }

        if generate_report_flag:
            scanner.generate_report("vuln_report.csv", scan_duration=duration)
            result["report_saved"] = True

        critical = [v for v in vulnerabilities if v.get("type") in (
            "XSS", "SQL Injection", "Missing Security Headers",
            "Potential CSRF Vulnerability", "Directory Traversal Vulnerability",
            "File Inclusion Vulnerability")]

        if critical:
            send_email_alert(target_url, critical, receiver_email=user_email)
            send_sms_alert(target_url, critical, receiver_phone=user_phone)

        return result

    except Exception as e:
        logging.exception("Error during manual scan")
        return {"error": str(e)}


def run_scheduled_scan(target_url, hour, minute, user_email, user_phone):
    try:
        scheduled_scan(target_url, scheduled_hour=hour, scheduled_minute=minute)
        return {"status": "Scheduled scan completed"}
    except Exception as e:
        logging.exception("Error during scheduled scan")
        return {"error": str(e)}


@app.route("/scan", methods=["POST"])
def scan():
    data = request.json
    target_url = data.get("target_url")
    user_email = data.get("email")
    user_phone = data.get("phone")
    include_subdomains = data.get("include_subdomains", False)
    generate_report_flag = data.get("generate_report", False)
    scan_type = data.get("scan_type", "manual")

    if not target_url or not user_email or not user_phone:
        return jsonify({"error": "Missing required fields."}), 400

    if scan_type == "manual":
        def scan_thread():
            result = run_manual_scan(target_url, include_subdomains, generate_report_flag, user_email, user_phone)
            # Store result if needed

        Thread(target=scan_thread).start()
        return jsonify({"status": "Manual scan started"})

    elif scan_type == "scheduled":
        try:
            hour = int(data.get("hour"))
            minute = int(data.get("minute"))
        except (TypeError, ValueError):
            return jsonify({"error": "Invalid hour or minute for scheduled scan."}), 400

        def scheduled_thread():
            run_scheduled_scan(target_url, hour, minute, user_email, user_phone)

        Thread(target=scheduled_thread).start()
        return jsonify({"status": f"Scheduled scan set for {hour}:{minute:02d}"})

    else:
        return jsonify({"error": "Invalid scan type."}), 400


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    app.run(debug=True)
