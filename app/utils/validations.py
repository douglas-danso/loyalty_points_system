import re
from fastapi import status
from .responses import error_message
import logging

logger = logging.getLogger(__name__)

class CustomValidator:
    async def validate_password(password):
        pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
        if not re.match(pattern, password):
            return await error_message(
                "Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character",
                status=status.HTTP_400_BAD_REQUEST
            )
        return None
    async def validate_name(name):
        if not (2 <= len(name) <= 50):
            logger.info("hiiiiiii")
            return await error_message(
                "Name must be between 2 and 50 characters",
                status=status.HTTP_400_BAD_REQUEST
            )

        if not name.isalpha():
            return error_message(
                "Name must contain only alphabetical characters",
                status=status.HTTP_400_BAD_REQUEST
            )
        return None

    async def validate_email(email):
        email_pattern = r'^\S+@\S+\.\S+$'
        if not re.match(email_pattern, email):
            return error_message(
                "Invalid email format",
                status=status.HTTP_400_BAD_REQUEST
            )
        return None