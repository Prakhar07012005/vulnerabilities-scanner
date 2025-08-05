# notification.py

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import logging

def send_email_alert(target_url, vulnerabilities, receiver_email,csv_filename="vuln_report.csv"):
    """
    Sends an email alert with details of critical vulnerabilities to the receiver_email.
    Configure the sender settings below.
    """
    # Configure these details with your actual SMTP settings (e.g., Gmail with an app-specific password)
  
    
    subject = f"Critical Vulnerability Alert for {target_url}"
    body = "Critical vulnerabilities found:\n\n"
    for vuln in vulnerabilities:
        body += f"Type: {vuln.get('type')}\n"
        body += f"URL: {vuln.get('url')}\n"
        if vuln.get("parameter"):
            body += f"Parameter: {vuln.get('parameter')}\n"
        if vuln.get("payload"):
            body += f"Payload: {vuln.get('payload')}\n"
        if vuln.get("details"):
            body += f"Details: {vuln.get('details')}\n"
        body += "\n"
    
    #Create the email message
    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = receiver_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))


      # Attach the CSV report file
    try:
        with open(csv_filename, "rb") as attachment:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(attachment.read())
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f"attachment; filename= {csv_filename}")
        msg.attach(part)
        logging.info("CSV report attached successfully.")
    except Exception as e:
        logging.exception(f"Error attaching CSV file: {e}")
    
    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.sendmail(sender_email, receiver_email, msg.as_string())
        server.quit()
        logging.info("Email alert sent successfully.")
    except Exception as e:
        logging.exception(f"Error sending email alert: {e}")

def send_sms_alert(target_url, vulnerabilities, receiver_phone):
    """
    Sends an SMS alert with a summary of critical vulnerabilities to the receiver_phone.
    This example uses Twilio.
    """
    try:
        from twilio.rest import Client
    except ImportError:
        logging.error("Twilio library is not installed. Install it using 'pip install twilio'.")
        return

  
    
    body = f"Critical Vulnerability Alert for {target_url}:\n"
    for vuln in vulnerabilities[:5]:
        body += f"{vuln.get('type')} on {vuln.get('url')}\n"
    
    # Agar message 1600 characters se zyada ho jaye, to isse shorten kar do
    if len(body) > 5:
        body +=  "...and more vulnerabilities" 

    # Agar message 1600 characters se zyada ho jaye, to usse truncate karein
    if len(body) > 1600:
        body = body[:1590] + "..."

    try:
        client = Client(account_sid, auth_token)
        message = client.messages.create(
            body=body,
            from_=from_phone,
            to=receiver_phone
        )
        logging.info(f"SMS alert sent successfully. Message SID: {message.sid}")
    except Exception as e:
        logging.exception(f"Error sending SMS alert: {e}")
