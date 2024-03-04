from jose import JWTError, jwt
from datetime import datetime, timedelta
from . import schema
from fastapi import Depends,status,HTTPException
from fastapi.security import OAuth2PasswordBearer
from dotenv import load_dotenv
import os
import logging
from ..utils.crud import get_repository

logger = logging.getLogger(__name__)


load_dotenv()

oauth2_url = OAuth2PasswordBearer(tokenUrl="login")
admin_oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login/admin")

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE = int(os.getenv("ACCESS_TOKEN_EXPIRE"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS"))


def create_access_token(data:dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes = ACCESS_TOKEN_EXPIRE)
    to_encode.update({"exp":expire})
    return jwt.encode(to_encode,SECRET_KEY,algorithm=ALGORITHM)

async def verify_access_token(token:str, is_admin:bool=False):
    credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
    detail ="could not validate credentials",headers = {"WWW-Authenticate":"Bearer"})
    
    try:
        payload = jwt.decode(token,SECRET_KEY)
        
        user_id:str = payload.get("user_id")
        user_id = str(user_id)
        logger.info(user_id)
        if user_id is None:
            raise credentials_exception
        repo = get_repository("UserBase")
        token_data = await repo.get_by_id(user_id)
        if is_admin and token_data.role not in ["admin","business_owner","teller",
                        "super_admin","business_admin"]:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
    detail ="User is not allowed")
    except JWTError:
        raise credentials_exception
    return token_data
    
async def get_current_user(token:str = Depends(oauth2_url)):
    return await verify_access_token(token)

async def get_current_admin_user(token: str = Depends(admin_oauth2_scheme)):
    return await verify_access_token(token,is_admin=True)



async def create_new_token(refresh_token: str):
    
    payload = await verify_access_token(refresh_token)
    user_id = payload.id
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE)
    new_access_token = create_access_token(data={"user_id": user_id}, expires_delta=access_token_expires)
    
    return {"access_token": new_access_token, "token_type": "bearer"}


def create_refresh_token(data:dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days= REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp":expire})
    return jwt.encode(to_encode,SECRET_KEY,algorithm=ALGORITHM)

async def store_refresh_token(token:str, user):
    user.refresh_token = token
    return await user.save()