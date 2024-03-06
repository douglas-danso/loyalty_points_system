from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
import os
import requests
import logging
from dotenv import load_dotenv
from twilio.rest import Client

load_dotenv()

logger = logging.getLogger(__name__)

email_config = {
    "smtp_server": os.getenv("smtp_server"),
    "smtp_port": 587, 
    "smtp_user": os.getenv("smtp_user"),
    "smtp_password": os.getenv("smtp_password"),
    "sender_email": os.getenv("sender_email"),
}


async def send_email(to_email: str, subject: str, body: str):
    msg = MIMEMultipart()
    msg.attach(MIMEText(body, 'plain'))

    msg['From'] = email_config["sender_email"]
    msg['To'] = to_email
    msg['Subject'] = subject

    with smtplib.SMTP(email_config["smtp_server"], email_config["smtp_port"]) as server:
        server.starttls()
        server.login(email_config["smtp_user"], email_config["smtp_password"])
        server.sendmail(email_config["sender_email"], to_email, msg.as_string())

# async def send_sms_to_user(phone_number, message):
#     url = os.getenv("sms_url")
#     headers = {
#         "api-key": os.getenv("sms_api_key"), 
#         "Content-Type": "application/json"
#     }
#     logger.info(phone_number)
#     recipients = phone_number
#     requestBody = {
#         "sender": "Admin",
#         "message": message,
#         "recipients": [recipients]
#     }
#     try:
#         response = requests.post(url, headers=headers, json=requestBody)
#         response.raise_for_status()

#         if response.status_code == 200:
#             logger.info(response.text)
#         else:
#             logger.error(f"Unexpected code {response.status_code}")
#             logger.error(response.text)  
#     except requests.exceptions.RequestException as e:
#         logger.error(f"Request failed: {e}")
#         logger.error(response.text)  

TWILIO_ACCOUNT_SID = os.getenv("account_sid")
TWILIO_AUTH_TOKEN = os.getenv("auth_token")
TWILIO_PHONE_NUMBER = os.getenv("phone_number")
async def send_sms_to_user(to_number: str, message: str):
    try:
        # Initialize Twilio client
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

        # Send SMS
        message = client.messages.create(
            body=message,
            from_=TWILIO_PHONE_NUMBER,
            to=to_number
        )

        return {"status": "success", "message_sid": message.sid}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
