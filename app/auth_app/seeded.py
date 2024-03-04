from beanie import WriteRules
from .models import SuperAdmin
import logging
from ..utils.crud import get_repository
from ..utils.helpers import hash_password
from .schema import UserCreate

logger = logging.getLogger(__name__)
async def create_super_admin(email: str, password: str, name:str):
    repository = get_repository("UserBase")
    existing_user = await repository.get({"email": email})
    if  not existing_user:

        hashed_password = hash_password(password)
        user_data:UserCreate = {
            "email":email,
            "password":hashed_password,
            "name":name,
            "role":"super_admin",
            "is_active":True
        }
        user = await repository.create(user_data)
        logger.info(user.id)
        super_admin = SuperAdmin(user_base=user.id)
        await super_admin.save(link_rule=WriteRules.WRITE)
        logger.info("super Admin registration successful")
        return {"message": "Registration successful"}