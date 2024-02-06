from pydantic import BaseModel, EmailStr, Field, validator
class UserBase(BaseModel):
    email: EmailStr = Field(..., unique=True)
    name: str = Field(...)

class PasswordMixin(BaseModel):
    password: str = Field(..., min_length=8)

    @validator('password')
    def hash_password(cls, v):
        # Use a secure hashing algorithm like bcrypt here
        # Store the hashed password in the database
        return v