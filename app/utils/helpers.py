import random
import string
from fastapi import HTTPException
from passlib.context import CryptContext
from cryptography.fernet import Fernet
from .crud import get_repository
import os
import logging

logger = logging.getLogger(__name__)

pwd_context = CryptContext(schemes = ["bcrypt"], deprecated = "auto")

class OTPManager:
    repository = get_repository("OTP")
    @staticmethod
    async def get_otp(email: dict):
        otp_data = await OTPManager.repository.get(email)
        logger.info(otp_data)
        return otp_data

    @staticmethod
    async def generate_otp(email: str):
        
        existing_otp = await OTPManager.get_otp({"identifier":email})
        otp_code = ''.join(random.choices(string.digits, k=6))
        data = {
            "identifier": email,
            "otp": otp_code
        }
        if existing_otp:
            otp = await existing_otp.update({"$set": data})
            # return {"message": "OTP updated successfully"}
        else:
            otp = await OTPManager.repository.create(data)

        return otp.otp


    @staticmethod
    async def verify_email(data:dict):
       
        otp = await OTPManager.get_otp(data)
        if otp:
            return "email verified"
        return "not verified"




def hash_password(password:str):
    return pwd_context.hash(password)

def verify(plain_password,hashed_password):
    return pwd_context.verify(plain_password,hashed_password)



KEY = os.getenv("id_key")
def encrypt_ids(id):
    id_str = str(id)
    cipher_suite = Fernet(KEY)
    cipher_text = cipher_suite.encrypt(id_str.encode())
    return cipher_text

def decrypt_ids(encrypted_id):
    if encrypted_id:
        cipher_suite = Fernet(KEY)
        decrypted_model_id = cipher_suite.decrypt(encrypted_id).decode()
        return decrypted_model_id
    else:
        pass