from typing import List,Optional
from pydantic import BaseModel, EmailStr, Field, validator
from beanie import Document, PydanticObjectId,Link
from . import schema
import logging
from uuid import UUID, uuid4


logger = logging.getLogger(__name__)



class PasswordMixin(BaseModel):
    password: str = Field(..., min_length=8)
    # @validator('password')
    # def hash_model_password(cls, v):
    #     from ..utils.helpers import hash_password
    #     logger.info(v)
    #     return hash_password(v)


class UserBase(Document, schema.UserSchema,PasswordMixin):
    class Settings:
        name = 'user_base'
    
    @classmethod
    def from_dict(cls, data: dict): 
        return cls(**data)
class SuperAdmin( Document):
    user_base:PydanticObjectId
    class Settings:
        name = 'super_admins'

class Admin(Document):
    user_base:PydanticObjectId
    class Settings:
        name = 'admins'


class BusinessAdmin(Document):
    user_base:PydanticObjectId

    class Settings:
        name = 'business_admins'

class Teller(Document):
    user_base:PydanticObjectId

    class Settings:
        name = 'tellers'

class Customer(Document):
    phone_number: str | None = Field(default=None, unique=True)
    google_id: str | None = Field(default=None, unique=True)
    user_base:PydanticObjectId

    class Settings:
        name = 'customers'

class BusinessOwner(Document):
    business_id: UUID = Field(default_factory=uuid4)
    user_base:PydanticObjectId
    business_admins:Optional[List[PydanticObjectId]] = []
    tellers:Optional[List[PydanticObjectId]] = []

    class Settings:
        name = 'business_owners'


class OTP(Document):
    identifier:str
    otp:str