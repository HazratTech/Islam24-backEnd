from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
import os
from dotenv import  load_dotenv


load_dotenv()


def send_verification_email(email, code):
    sender_email = os.getenv("EMAIL_USER")
    email_code = os.getenv("EMAIL_APP_CODE")

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = email
    msg['Subject'] = f"{code} Your Verification Code"

    body = f"Your Verification code is {code}. It expires in 10 minutes"
    msg.attach(MIMEText(body, 'plain'))
    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(sender_email, email_code)
            server.send_message(msg)
        print(f"Verification email sent to {email} with code {code}")
    except Exception as e:
        print(f"Error sending email: {e}")