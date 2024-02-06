from pydantic import BaseModel, EmailStr, Field, validator
from beanie import Document, PydanticObjectId
from fastapi import HTTPException, status
from .schema import UserBase,PasswordMixin

class SuperAdmin(Document, UserBase, PasswordMixin):
    class Settings:
        name = 'super_admins'

class Admin(Document, UserBase, PasswordMixin):
    business_id: PydanticObjectId = Field(...)

    class Settings:
        name = 'admins'

class BusinessOwner(Document, UserBase, PasswordMixin):
    business_id: PydanticObjectId = Field(...)

    class Settings:
        name = 'business_owners'

class BusinessAdmin(Document, UserBase, PasswordMixin):
    business_id: PydanticObjectId = Field(...)

    class Settings:
        name = 'business_admins'

class Teller(Document, UserBase, PasswordMixin):
    business_id: PydanticObjectId = Field(...)

    class Settings:
        name = 'tellers'

class Customer(Document, UserBase):
    phone_number: str | None = Field(default=None, unique=True)
    google_id: str | None = Field(default=None, unique=True)

    class Settings:
        name = 'customers'
