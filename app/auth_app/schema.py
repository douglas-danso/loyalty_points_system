from pydantic import BaseModel, EmailStr, Field, validator
from beanie import PydanticObjectId
from enum import Enum


class Roles(str, Enum):
    customer = "customer"
    super_admin = "super_admin"
    admin = "admin"
    business_owner = "business_owner"
    business_admin = "business_admin"
    teller = "teller"


class UserSchema(BaseModel):
    email: EmailStr|None = Field(default=None)
    name: str = Field(...)
    role:str|Roles
    is_active:bool = False
    is_verified:bool = False
    refresh_token:str=None


class UserBody(BaseModel):
    name:str
    email:str = None
    phone_number:str =  None
    google_id: str =  None
    password:str
   
class CustomerCreate(BaseModel):
    phone_number: str = None
    google_id: str = None,
    user_base: BaseModel
    
    

class UserCreate(BaseModel):
    name:str
    email:EmailStr = None
    password:str
    role: Roles

class UserData(BaseModel):
    _id:PydanticObjectId
    name:str
    email:EmailStr|None
    role: Roles
    is_active:bool

class FilterUserData(UserData):
    relations:dict
    
class TokenData(BaseModel):
    id: str | None = None

class CustomerLogin(BaseModel):
    email:EmailStr = None
    phone_number: str = None
    google_id: str = None 
    password:str

class ForgotPassword(BaseModel):
    email:EmailStr = None
    phone_number: str = None

class ResetPassword(BaseModel):
    password:str
    new_password:str
    confirm_password:str

class EditUserData(BaseModel):
    name:str

    
class BusinessData(UserCreate):
    email:EmailStr
    role:Roles=None

class AdminLogin(BaseModel):
    email:EmailStr
    password:str

class InviteUserData(BaseModel):
    email:EmailStr
    role:Roles = None

class OTPData(BaseModel):
    otp:str = None
    credential:str

class PasswordChange(OTPData):
    new_password:str
    confirm_password:str

class CreateInviteUserData(BusinessData):
    otp:str=None
    business_id:PydanticObjectId


class CreateInvitedAdmin(CreateInviteUserData):
    role:Roles = "admin"
    business_id:PydanticObjectId = None

class Filter(BaseModel):
    match:dict
    