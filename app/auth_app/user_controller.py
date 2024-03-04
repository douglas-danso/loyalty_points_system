from typing import List
from urllib.parse import parse_qs
from beanie import PydanticObjectId
from fastapi import APIRouter,Depends, Path
import logging
from .user_service import UserService
from . schema import (Filter, FilterUserData, OTPData, UserBody,CustomerLogin,
                      ForgotPassword,ResetPassword,
                      EditUserData, BusinessData,
                      AdminLogin,InviteUserData,
                      PasswordChange,CreateInviteUserData, 
                      CreateInvitedAdmin, UserData)
from . import oauth2

auth_router = APIRouter(
    prefix="/users"
)
logger = logging.getLogger(__name__)

@auth_router.post("/signup/")
async def signup_customer(data:UserBody):
    return await UserService.create_customer(data)

@auth_router.post("/verify-email/{email}")
async def verify_email_route(email: str, otp: str):
    return await UserService.verify_email(email, otp)

@auth_router.post("/login")
async def login(data:CustomerLogin):
    logger.info("hello service")
    return await UserService.login_service(data)

@auth_router.post("/forgot-password")
async def forgot_password(data:ForgotPassword):
    logger.info("hello")
    return await UserService.forgot_password(data)

@auth_router.post("/reset-password")
async def reset_password(data:ResetPassword, user = Depends(oauth2.get_current_user)):
    logger.info(user)
    return await UserService.reset_password(data, user)

@auth_router.put("/edit")
async def edit_user(data:EditUserData, user = Depends(oauth2.get_current_user)):
    return await UserService.edit_user(data, user)


@auth_router.post("/business")
async def create_business(data:BusinessData):
    return await UserService.create_business(data)

@auth_router.post("/login/admin")
async def admin_login(data:AdminLogin):
    return await UserService.login_admin(data)


@auth_router.post("/invite")
async def invite(data:InviteUserData,user = Depends(oauth2.get_current_admin_user)):
    return await UserService.invite_users(data,user)


@auth_router.post("/activate/{otp}")
async def activate_user(data: OTPData, otp: str):
    logger.info("controooleeer")
    data.otp = otp
    return await UserService.activate_user(data)


@auth_router.put("/change-password/{otp}")
async def change_password(data: PasswordChange,otp:str):  
    data.otp = otp
    return await UserService.change_password(data)

@auth_router.post("/register/{otp}")
async def create_invite_business_users(data:CreateInviteUserData ,otp:str):
    data.otp = otp
    return await UserService.create_invited_users(data)

@auth_router.post("/register/admin/{otp}")
async def create_invite_admin_users(data:CreateInvitedAdmin, otp:str):
    data.otp = otp
    return await UserService.create_admin(data)

@auth_router.get("/", response_model=List[UserData])
async def get_all_users():
    return await UserService.get_all_users()

@auth_router.get("/filter")
async def filter_users(filter_role: str = None):
    filter = {}
    if filter_role:
        filter["role"] = filter_role
    
    return await UserService.filter_users(filter=filter)

@auth_router.post("/refresh_token")
async def refresh_token(token:str):
    return await UserService.create_new_token(token)