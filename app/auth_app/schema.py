from pydantic import BaseModel, EmailStr, Field, validator
import bcrypt

class UserBase(BaseModel):
    email: EmailStr = Field(..., unique=True)
    name: str = Field(...)



class PasswordMixin(BaseModel):
    password: str = Field(..., min_length=8)

    @validator('password')
    def hash_password(cls, v):
        hashed_password = bcrypt.hashpw(v.encode('utf-8'), bcrypt.gensalt())
        return hashed_password.decode('utf-8')
