import smtplib
import os
from email.message import EmailMessage

EMAIL_SENDER = os.environ.get("EMAIL_SENDER")
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD")
EMAIL_RECEIVER = os.environ.get("EMAIL_RECEIVER")

REPORT_PATH = "nikto_reports/nikto_report.html"

msg = EmailMessage()
msg["Subject"] = "Nikto Scan Report"
msg["From"] = EMAIL_SENDER
msg["To"] = EMAIL_RECEIVER
msg.set_content("Attached is the Nikto scan report.")

with open(REPORT_PATH, "rb") as f:
    file_data = f.read()
    file_name = os.path.basename(REPORT_PATH)
    msg.add_attachment(file_data, maintype="text", subtype="html", filename=file_name)

with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
    smtp.login(EMAIL_SENDER, EMAIL_PASSWORD)
    smtp.send_message(msg)
