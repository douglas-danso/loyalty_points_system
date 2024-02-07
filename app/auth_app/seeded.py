from .models import SuperAdmin
from .schema import PasswordMixin
import logging
logger = logging.getLogger(__name__)
async def create_super_admin(email: str, password: str, name:str):
    existing_user = await SuperAdmin.find_one({"email": email})
    if  not existing_user:
        password_mixin = PasswordMixin(password=password)

    # Hash the password using the instance's hash_password method
        hashed_password = password_mixin.hash_password(password)
        owner = SuperAdmin(
            email=email,
            password=hashed_password,
            name=name
        )
        await owner.save()
        logger.info("super Admin registration successful")
        return {"message": "Registration successful"}