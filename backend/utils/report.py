# utils/report.py

import csv
import logging

def generate_csv_report(vulnerabilities, filename="vuln_report.csv"):
    try:
        fieldnames = ["url", "type", "parameter", "payload", "details"]
        with open(filename, mode="w", newline='', encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for vuln in vulnerabilities:
                writer.writerow({
                    "url": vuln.get("url", ""),
                    "type": vuln.get("type", ""),
                    "parameter": vuln.get("parameter", ""),
                    "payload": vuln.get("payload", ""),
                    "details": vuln.get("details", "")
                })
        logging.info(f"Report generated successfully: {filename}")
    except Exception as e:
        logging.error(f"Error generating report: {e}")
