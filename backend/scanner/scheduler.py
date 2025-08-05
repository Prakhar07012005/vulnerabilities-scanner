# scheduler.py
import datetime
from apscheduler.schedulers.background import BackgroundScheduler
import time
import logging
from scanner.scanner import WebVulnScanner
from backend.utils.notification import send_email_alert

def scheduled_scan(target_url, scheduled_hour, scheduled_minute):
    """
    Scheduled scan function that waits until the specified hour and minute,
    then runs the scan on the target URL.
    """
    now = datetime.datetime.now()
    scheduled_time = now.replace(hour=scheduled_hour, minute=scheduled_minute, second=0, microsecond=0)
    if scheduled_time < now:
        # Agar aaj ka scheduled time pass ho chuka hai, to kal ka schedule set karo
        scheduled_time += datetime.timedelta(days=1)
    wait_seconds = (scheduled_time - now).total_seconds()
    logging.info(f"Waiting {wait_seconds:.0f} seconds until scheduled scan time {scheduled_time}")
    time.sleep(wait_seconds)
    
    logging.info(f"Scheduled scan started for {target_url}")
    scanner = WebVulnScanner(
        target_url=target_url, max_depth=2, max_workers=10, include_subdomains=True
        )
    vulnerabilities = scanner.run()
    scanner.generate_report("vuln_report.csv", scan_duration=wait_seconds)
    
    # Agar critical vulnerabilities hain, email alert bhejein
    critical = [v for v in vulnerabilities if v.get("type") in (
        "SQL Injection", "Directory Traversal Vulnerability", "File Inclusion Vulnerability")]
    if critical:
        send_email_alert(target_url, critical)
    logging.info("Scheduled scan completed.")

if __name__ == "__main__":
    # For standalone testing, you can hardcode a URL here.
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    scheduler = BackgroundScheduler()
    # Example: schedule scan every day at 2 AM for a fixed URL.
    scheduler.add_job(scheduled_scan, 'cron', hour=2, minute=0, args=["https://example.com"])
    scheduler.start()
    
    try:
        while True:
            time.sleep(60)
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()
