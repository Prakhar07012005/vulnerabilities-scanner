import tkinter as tk
from tkinter import messagebox
from threading import Thread
import logging
import time
from backend.scanner import WebVulnScanner
from backend.scanner.scheduler import scheduled_scan  # Ensure scheduled_scan accepts target_url, scheduled_hour, scheduled_minute

class ScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Web Vulnerability Scanner")
        self.create_widgets()
        self.scheduler_running = False
        
    def create_widgets(self):
        # URL input
        self.url_label = tk.Label(self.root, text="Enter Target URL:")
        self.url_label.pack(pady=5)
        
        self.url_entry = tk.Entry(self.root, width=50)
        self.url_entry.pack(pady=5)
        
        # User Email input for notifications
        self.email_label = tk.Label(self.root, text="Enter Your Email Address:")
        self.email_label.pack(pady=5)
        self.email_entry = tk.Entry(self.root, width=50)
        self.email_entry.pack(pady=5)
        
        # User Phone input for SMS notifications
        self.phone_label = tk.Label(self.root, text="Enter Your Phone Number:")
        self.phone_label.pack(pady=5)
        self.phone_entry = tk.Entry(self.root, width=20)
        self.phone_entry.pack(pady=5)
        
        # Checkbox for subdomain scanning
        self.subdomain_var = tk.IntVar()
        self.subdomain_checkbox = tk.Checkbutton(
            self.root, text="Include Subdomain Scanning", variable=self.subdomain_var
        )
        self.subdomain_checkbox.pack(pady=5)
        
        # Checkbox for generating a CSV report
        self.report_var = tk.IntVar()
        self.report_checkbox = tk.Checkbutton(
            self.root, text="Generate CSV Report", variable=self.report_var
        )
        self.report_checkbox.pack(pady=5)
        
        # Radio buttons for Scan Type
        self.scan_type = tk.StringVar(value="manual")
        self.manual_radio = tk.Radiobutton(
            self.root, text="Manual Scan", variable=self.scan_type, value="manual"
        )
        self.manual_radio.pack(pady=5)
        self.scheduled_radio = tk.Radiobutton(
            self.root, text="Scheduled Scan", variable=self.scan_type, value="scheduled"
        )
        self.scheduled_radio.pack(pady=5)
        
        # For scheduled scan: Hour and Minute inputs
        self.time_frame = tk.Frame(self.root)
        self.hour_label = tk.Label(self.time_frame, text="Scheduled Hour (0-23):")
        self.hour_label.grid(row=0, column=0, padx=5)
        self.hour_entry = tk.Entry(self.time_frame, width=5)
        self.hour_entry.grid(row=0, column=1, padx=5)
        self.minute_label = tk.Label(self.time_frame, text="Minute (0-59):")
        self.minute_label.grid(row=0, column=2, padx=5)
        self.minute_entry = tk.Entry(self.time_frame, width=5)
        self.minute_entry.grid(row=0, column=3, padx=5)
        self.time_frame.pack(pady=5)
        
        # Status label
        self.status_label = tk.Label(self.root, text="Status: Idle")
        self.status_label.pack(pady=5)
        
        # Scan button
        self.scan_button = tk.Button(self.root, text="Start Scan", command=self.start_scan)
        self.scan_button.pack(pady=5)
        
        # Results text area
        self.results_text = tk.Text(self.root, width=80, height=20)
        self.results_text.pack(pady=5)
        
    def start_scan(self):
        target_url = self.url_entry.get().strip()
        if not target_url:
            messagebox.showwarning("Input Error", "Please enter a valid URL.")
            return
        
        # Collect user email and phone
        user_email = self.email_entry.get().strip()
        user_phone = self.phone_entry.get().strip()
        if not user_email or not user_phone:
            messagebox.showwarning("Input Error", "Please enter both your email address and phone number for notifications.")
            return
        
        # Clear previous results
        self.results_text.delete(1.0, tk.END)
        self.status_label.config(text="Status: Scanning...")
        self.scan_button.config(state=tk.DISABLED)
        
        include_subdomains = bool(self.subdomain_var.get())
        generate_report_flag = bool(self.report_var.get())
        scan_type = self.scan_type.get()  # "manual" or "scheduled"
        
        if scan_type == "manual":
            scan_thread = Thread(target=self.run_manual_scan, args=(target_url, include_subdomains, generate_report_flag, user_email, user_phone))
            scan_thread.start()
        elif scan_type == "scheduled":
            # Validate time inputs for scheduled scan
            try:
                hour = int(self.hour_entry.get().strip())
                minute = int(self.minute_entry.get().strip())
                if not (0 <= hour < 24 and 0 <= minute < 60):
                    raise ValueError
            except ValueError:
                messagebox.showerror("Input Error", "Please enter valid numeric values for hour (0-23) and minute (0-59).")
                self.scan_button.config(state=tk.NORMAL)
                return
            scan_thread = Thread(target=self.run_scheduled_scan, args=(target_url, hour, minute, user_email, user_phone))
            scan_thread.start()
        
    def run_manual_scan(self, target_url, include_subdomains, generate_report_flag, user_email, user_phone):
        try:
            start_time = time.time()
            scanner = WebVulnScanner(
                target_url=target_url, max_depth=2, max_workers=10, include_subdomains=include_subdomains
            )
            vulnerabilities = scanner.run()
            end_time = time.time()
            duration = round(end_time - start_time, 2)
            result_text = f"Manual Scan Duration: {duration} seconds\n\n"
            if vulnerabilities:
                for vuln in vulnerabilities:
                    result_text += f"Vulnerability: {vuln.get('type')}\n"
                    result_text += f"URL: {vuln.get('url')}\n"
                    if vuln.get('parameter'):
                        result_text += f"Parameter: {vuln.get('parameter')}\n"
                    if vuln.get('payload'):
                        result_text += f"Payload: {vuln.get('payload')}\n"
                    if vuln.get('details'):
                        result_text += f"Details: {vuln.get('details')}\n"
                    result_text += "\n"
            else:
                result_text += "No vulnerabilities found.\n"
                
            if generate_report_flag:
                scanner.generate_report("vuln_report.csv", scan_duration=duration)
                result_text += "\nReport saved as vuln_report.csv\n"
            
            self.root.after(0, lambda: self.results_text.insert(tk.END, result_text))
            self.root.after(0, lambda: self.status_label.config(text="Status: Manual Scan Completed"))
            
            # For manual scans, you may choose to send notifications as well
            # For example, if critical vulnerabilities are found:
            critical = [v for v in vulnerabilities if v.get("type") in ("XSS", "SQL Injection", "Missing Security Headers","Potential CSRF Vulnerability","Directory Traversal Vulnerability","File Inclusion Vulnerability")]
            if critical:
                from backend.utils.notification import send_email_alert, send_sms_alert
                send_email_alert(target_url, critical, receiver_email=user_email)
                send_sms_alert(target_url, critical, receiver_phone=user_phone)
        except Exception as e:
            error_message = f"Error during manual scan: {e}"
            logging.exception(error_message)
            self.root.after(0, lambda: self.results_text.insert(tk.END, error_message + "\n"))
            self.root.after(0, lambda: self.status_label.config(text="Status: Error"))
        finally:
            self.root.after(0, lambda: self.scan_button.config(state=tk.NORMAL))
    
    def run_scheduled_scan(self, target_url, hour, minute, user_email, user_phone):
        try:
            self.status_label.config(text=f"Status: Scheduled Scan Set for {hour}:{minute:02d}")
            # Call the scheduler function with the target URL and time parameters.
            # We assume scheduled_scan() is modified to accept these parameters.
            from backend.scanner.scheduler import scheduled_scan
            scheduled_scan(target_url, scheduled_hour=hour, scheduled_minute=minute)
            self.root.after(0, lambda: self.status_label.config(text="Status: Scheduled Scan Completed"))
            # After scheduled scan completes, you can add similar notification logic if desired.
            # For example, you might call send_email_alert/send_sms_alert based on scan results.
        except Exception as e:
            logging.exception(e)
            self.root.after(0, lambda: self.status_label.config(text="Status: Scheduled Scan Error"))
        finally:
            self.root.after(0, lambda: self.scan_button.config(state=tk.NORMAL))

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    root = tk.Tk()
    app = ScannerGUI(root)
    root.mainloop()
