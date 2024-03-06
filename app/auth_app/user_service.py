import json
from app.utils.helpers import OTPManager,verify,hash_password
from . import models
from . import schema
from app.utils.crud import UserBaseRepository,get_repository
from app.utils import send_message, validations,responses
from fastapi import status,Depends
import logging
import bcrypt
from . import oauth2
from bson import json_util
from beanie import PydanticObjectId


logger = logging.getLogger(__name__)

class UserService:
    customer_repository: UserBaseRepository = get_repository("Customer")
    user_repository:UserBaseRepository = get_repository("UserBase")
    business_owner_repo:UserBaseRepository = get_repository("BusinessOwner")
    admin_repo:UserBaseRepository = get_repository("Admin")
    teller_repo:UserBaseRepository = get_repository("Teller")
    business_admin_repo:UserBaseRepository = get_repository("BusinessAdmin")
    validator = validations.CustomValidator


    @classmethod
    async def create_customer(cls,user: schema.UserBody):
        
        logger.info(user.name)
        
        name_validation_result = await cls.validator.validate_name(user.name)
        
        if name_validation_result:
            return name_validation_result

        if user.email:
            existing_user_email = await cls.user_repository.get({"email": user.email})
            email_validation_result = await cls.validator.validate_email(user.email)
            if email_validation_result:
                return email_validation_result
            if existing_user_email:
                return await responses.error_message(
                    f"User with email {user.email} already exists",
                    status=status.HTTP_400_BAD_REQUEST
                )
        password_validation_result = await cls.validator.validate_password(user.password)
        if password_validation_result:
            return password_validation_result

        
        

        user_data:schema.UserCreate = {
            "email": user.email if user.email else None,
            "name": user.name,
            "password": hash_password(user.password),
            "role":"customer",
            }
    
        if user.phone_number:
            existing_user_phone = await cls.customer_repository.get({"phone_number": user.phone_number})
            if existing_user_phone:
                return await responses.error_message(
                    f"User with phone number {user.phone_number} already exists",
                    status=status.HTTP_400_BAD_REQUEST
                )
            user_data:schema.UserCreate = {
            "name": user.name,
            "password": hash_password(user.password),
            "role":"customer",
            }

        
        
        logger.info(user_data)
        user_base_data = await cls.user_repository.create(user_data)

        customer_data:schema.CustomerCreate = {
            "phone_number": user.phone_number if user.phone_number else None,
            "google_id": user.google_id if user.google_id else None,
            }
        link_filter = {"user_base":user_base_data.id}
        await cls.customer_repository.create_with_link(link_filter,**customer_data)
        identifier= user.email if user.email else user.phone_number
        OTP = await OTPManager.generate_otp(identifier)
        
        link = "frontend_link"
        msg = f"""
            Hello {user.name}, 
            click on the link below to activate your account
            link: {link}/{OTP} 
        """
        if user.email:
            subject = "Activate your account"
            body = msg
            await send_message.send_email(user.email,subject,body)
        else:
            message = msg
            await send_message.send_sms_to_user(user.phone_number,message)

        return await responses.success_message("user","created")

        
        
    @classmethod
    async def verify_otp(cls,data:schema.OTPData): 

        # logger.info(data.otp)      
        otp = await OTPManager.get_otp({"identifier":data.credential})
        logger.info("otp", otp)
        if otp:
            if otp.otp == data.otp:
                return True
            return False
        return False

    @classmethod
    async def activate_user(cls,data:schema.OTPData):
        logger.info("activating userrr")
        otp = await cls.verify_otp(data)
        if otp:
            is_email = "@" in data.credential
            if is_email:
                user_filter = {"email": data.credential} 
                user_base = await cls.user_repository.get(user_filter)
            else:
                user_filter = {"phone_number": data.credential}      
                customer = await cls.customer_repository.get(user_filter)
                user_base = await cls.user_repository.get_by_id(customer.user_base.id)
            logger.info(user_base)
            user_base.is_active = True
            await user_base.save()
            return await responses.success_message("user", "activated")
        return await responses.error_message(
            "wrong otp",
            status=status.HTTP_404_NOT_FOUND
        )
    
    @classmethod
    async def login_service(cls,credentials: schema.CustomerLogin):
        logger.info("hiiii")
        
        is_email =  credentials.email
        if is_email:
            user_filter = {"email": credentials.email} 
            user_base = await cls.user_repository.get(user_filter)
        else:
            user_filter = {"phone_number": credentials.phone_number}      
            customer = await cls.customer_repository.get(user_filter)
            user_base = await cls.user_repository.get_by_id(customer.user_base)
        
        if not user_base or not verify(credentials.password, user_base.password):
            return await responses.error_message(
                "Incorrect email/phone number or password",
                status=status.HTTP_401_UNAUTHORIZED,
            )

    
        access_token_data = {"user_id": str(user_base.id)}
        access_token = oauth2.create_access_token(access_token_data)
        refresh_token = oauth2.create_refresh_token(access_token_data)
        await oauth2.store_refresh_token(refresh_token,user_base)
        return await responses.success_message_data(
            "logged in successfully",
        {
        "access_token": access_token, 
         "refresh_token":refresh_token,
         "token_type": "bearer"})

    @classmethod
    async def forgot_password(cls,credentials:schema.ForgotPassword):
        is_email = credentials.email
        user_filter = {"email": credentials.email} if is_email else {"phone_number": credentials.phone_number}
        identifier = credentials.email if is_email else credentials.phone_number
        repository = cls.user_repository if is_email else cls.customer_repository
        user = await repository.get(user_filter)
        logger.info(user)
        if user:
            OTP = await OTPManager.generate_otp(identifier)
            link = "frontend_link"
            msg = f"""
                Hello, if you have have requested to change your password,
                click on the link below to proceed with your user registration
                link: {link}/{OTP} otherwise ignore this message.
            """
            if is_email:
                subject = "Request to change passage"
                body = msg
                await send_message.send_email(credentials.email,subject,body)
            else:
                message = msg
                await send_message.send_sms_to_user(credentials.phone_number,message)
                return await responses.send_message_success()

        return await responses.error_message(
            "user not found",
            status=status.HTTP_404_NOT_FOUND
        )
    
    @classmethod
    async def reset_password(cls,passwords:schema.ResetPassword, user):
        password_validator = await cls.validator.validate_password(passwords.new_password)
        if password_validator:
            logger.info(password_validator)
            return password_validator
        if not verify(passwords.password, user.password):
            return await responses.error_message(
                "Incorrect password",
                status=status.HTTP_401_UNAUTHORIZED,
            )
        
        if passwords.new_password ==passwords.password:
            return await responses.error_message(
                "Your old password should the same as you new password",
                status=status.HTTP_401_UNAUTHORIZED,
            )
        if passwords.new_password!=passwords.confirm_password:
            return await responses.error_message(
                "passwords do not match",
                status=status.HTTP_401_UNAUTHORIZED,
            )
        hashed_password = hash_password(passwords.new_password)
        user.password = hashed_password
        await user.save()
        return responses.success_message("password", "reset")


    @classmethod
    async def change_password(cls, data:schema.PasswordChange):
        filter = schema.OTPData (credential=data.credential, otp=data.otp)
        # logger.info(filter.otp)
        otp = await cls.verify_otp(filter)
        if otp:
            is_email = "@" in data.credential
            if is_email:
                user_filter = {"email": data.credential} 
                user_base = await cls.user_repository.get(user_filter)
            else:
                user_filter = {"phone_number": data.credential}      
                customer = await cls.customer_repository.get(user_filter)
                user_base = await cls.user_repository.get_by_id(customer.user_base)
            password_validation_result = await cls.validator.validate_password(data.new_password)
            if password_validation_result:
                return password_validation_result
            if data.new_password != data.confirm_password:
                return await responses.error_message(
                    "passwords do not match",
                    status=status.HTTP_400_BAD_REQUEST
                )
            hashed_password = hash_password(data.new_password)
            user_base.password = hashed_password
            await user_base.save()
            return await responses.success_message("password","changed")
        return await responses.error_message(
            "wrong otp",
            status=status.HTTP_404_NOT_FOUND
        )

    @classmethod
    async def edit_user(cls,data:schema.EditUserData,user):
        data = data.model_dump() if type(data) != dict else data == data
        logger.info(user)
        await cls.user_repository.edit_data(user, **data)
        return await responses.success_message("user", "updated")

    @classmethod
    async def create_business(cls,data:schema.BusinessData):
        email_validation_result = await cls.validator.validate_email(data.email)
        if email_validation_result:
            return email_validation_result
        
        password_validation_result = await cls.validator.validate_password(data.password)
        if password_validation_result:
            return password_validation_result
        
        existing_user_email = await cls.user_repository.get({"email": data.email})
        if existing_user_email:
            return await responses.error_message(
                f"User with email {data.email} already exists",
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user_data:schema.UserCreate = {
            "email": data.email,
            "name": data.name,
            "password": hash_password(data.password),
            "role":"business_owner",
            }
        user_base_data = await cls.user_repository.create(user_data)
        link_filter = {"user_base":user_base_data.id}
        await cls.business_owner_repo.create_with_link(link_filter)
        OTP = await OTPManager.generate_otp(data.email)
        subject="Verify your account"
        link = "frontend_link"
        msg = f"""
            Hello {data.name}, 
            click on the link below to activate your account
            link: {link}/{OTP} 
        """
        await send_message.send_email(data.email,subject,body=msg)
        return await responses.success_message("buisness","created")

    @classmethod
    async def login_admin(cls,data:schema.AdminLogin):
        user_filter = {"email": data.email} 
        user_base = await cls.user_repository.get(user_filter)       
        if not user_base or not verify(data.password, user_base.password):
            return await responses.error_message(
                "Incorrect email/phone number or password",
                status=status.HTTP_401_UNAUTHORIZED,
            )

    
        access_token_data = {"user_id": str(user_base.id)}
        access_token = oauth2.create_access_token(access_token_data)
        refresh_token = oauth2.create_refresh_token(access_token_data)
        await oauth2.store_refresh_token(refresh_token,user_base)

        return await responses.success_message_data(
            "logged in successfully",
        {
        "access_token": access_token, 
         "refresh_token":refresh_token,
         "token_type": "bearer"})


    @classmethod
    async def invite_users(cls,data:schema.InviteUserData, user):

        if user.role != "business_owner" and user.role != "super_admin":
            return await responses.error_message(
                "you are not allowed to perform this function",
                status=status.HTTP_401_UNAUTHORIZED
            )
        email_validation_result = await cls.validator.validate_email(data.email)
        if email_validation_result:
            return email_validation_result
        repository = cls.user_repository
        existing_user_email = await repository.get({"email": data.email})
        if existing_user_email:
            return await responses.error_message(
                f"User with email {data.email} already exists",
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if user.role == "super_admin":
            data.role = "admin"
        link = "frontend link/ "
        role = data.role.value
        OTP = await OTPManager.generate_otp(data.email)
        subject = "Invition to join the Loyalty system app"
        body = f"""
            Hello, you have have been invited to to our system as a {role}
            click the link below to proceed with your user registration
            link: {link}/{OTP}/{role}
        """
        await send_message.send_email(data.email,subject,body)
        return await responses.success_message("user", "invited")

    @classmethod
    async def create_invited_users(cls,data:schema.CreateInviteUserData):
        filter = schema.OTPData (credential=data.email, otp=data.otp)
        otp = await cls.verify_otp(filter)
        if otp:
            email_validation_result = await cls.validator.validate_email(data.email)
            if email_validation_result:
                return email_validation_result
            
            password_validation_result = await cls.validator.validate_password(data.password)
            if password_validation_result:
                return password_validation_result
            
            existing_user_email = await cls.user_repository.get({"email": data.email})
            if existing_user_email:
                return await responses.error_message(
                    f"User with email {data.email} already exists",
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            user_data:schema.UserCreate = {
                "email": data.email,
                "name": data.name,
                "password": hash_password(data.password),
                "role":data.role,
                }
            user_base_data = await cls.user_repository.create(user_data)
            business_owner = await cls.business_owner_repo.get_by_id(data.business_id)
    
            link_filter = {"user_base":user_base_data.id}
            if data.role=="teller":
                teller = await cls.teller_repo.create_with_link(link_filter)
                business_owner.tellers.append(teller.id)
                await business_owner.save()
                
                return await responses.success_message("teller","created")
            elif data.role=="business_admin":
                business_admin = await cls.business_admin_repo.create_with_link(link_filter)
                business_owner.business_admins.append(business_admin.id)
                await business_owner.save()
                return await responses.success_message("business admin","created")
        return await responses.error_message(
            "wrong otp",
            status=status.HTTP_404_NOT_FOUND
        )
        
    
    @classmethod
    async def create_admin(cls,data:schema.CreateInviteUserData):
        filter = schema.OTPData (credential=data.email, otp=data.otp)
        otp = await cls.verify_otp(filter)
        if otp:
            email_validation_result = await cls.validator.validate_email(data.email)
            if email_validation_result:
                return email_validation_result
            
            password_validation_result = await cls.validator.validate_password(data.password)
            if password_validation_result:
                return password_validation_result
            
            existing_user_email = await cls.user_repository.get({"email": data.email})
            if existing_user_email:
                return await responses.error_message(
                    f"User with email {data.email} already exists",
                    status=status.HTTP_400_BAD_REQUEST
                )
            user_data:schema.UserCreate = {
                "email": data.email,
                "name": data.name,
                "password": hash_password(data.password),
                "role":data.role,
                }
            user_base_data = await cls.user_repository.create(user_data)
            link_filter = {"user_base":user_base_data.id}
           
            await cls.admin_repo.create_with_link(link_filter)
            
            return await responses.success_message("admin","created")
        return await responses.error_message(
            "wrong otp",
            status=status.HTTP_404_NOT_FOUND
        )
    

    
    @classmethod
    async def filter_users(cls, filter):
        logger.info(filter)
        pipeline = []
        
        if filter:
            pipeline.append({"$match": filter})
            logger.info(pipeline)
        
        pipeline.extend([
            {
                "$lookup": {
                    "from": "business_owners",
                    "localField": "_id",
                    "foreignField": "user_base",
                    "as": "business_owner"
                }
            },
            {
                "$lookup": {
                    "from": "admins",
                    "localField": "_id",
                    "foreignField": "user_base",
                    "as": "admin"
                }
            },
            {
                "$lookup": {
                    "from": "tellers",
                    "localField": "_id",
                    "foreignField": "user_base",
                    "as": "teller"
                },
            },
            {
                "$lookup":{
                    "from":"customers",
                    "localField": "_id",
                    "foreignField": "user_base",
                    "as": "customer"
                }
            },
             {
                "$lookup":{
                    "from":"super_admins",
                    "localField": "_id",
                    "foreignField": "user_base",
                    "as": "super_admin"
                }
            }
            

        ])
        logger.info(pipeline)
        users = await models.UserBase.aggregate(pipeline).to_list()
        
        logger.info(users)
        user_data_list = []
        for user in users:
            logger.info(user)
            user_data = {
                "_id": str(user["_id"]),
                "name": user["name"],
                "email": user.get("email", None),
                "role": user["role"],
                "is_active": user["is_active"]
            }

            user=json.loads(json_util.dumps(user))

            if user_data["role"] == "business_owner" and user["business_owner"]:
                user_data["business_owner"] = user["business_owner"][0] 
                for user in  user["business_owner"][0]:
                    logger.info(user)
                id_list = []
                teller_ids = user_data["business_owner"].get("tellers", [])
                for ids in teller_ids:
                    id_list.append(PydanticObjectId(ids["$oid"]))

                logger.info({"id_list":id_list})
                
                tellers = await models.Teller.aggregate([
                    {"$match": {"_id": {"$in": id_list}}},
                    
                    {
                        "$lookup": {
                            "from": "user_base",
                            "localField": "user_base",
                            "foreignField": "_id",
                            "as": "teller_info"
                },
            },
                    ]).to_list()
                logger.info({"tellers":tellers})

                tellers = json.loads(json_util.dumps(tellers))
                
                teller_data_list = []
                for teller in tellers:
                    teller_info = teller.get("teller_info", [])
                    for teller_info_item in teller_info:
                        teller_data_list.append({
                            "_id": str(teller_info_item["_id"]),
                            "name": teller_info_item["name"],
                            "email": teller_info_item.get("email", None),
                            "role": teller_info_item["role"],
                            "is_active": teller_info_item["is_active"]
                        })

                user_data["business_owner"]["tellers"] = teller_data_list



                admin_id_list = []
                admins_ids = user_data["business_owner"].get("business_admins", [])
                for ids in admins_ids:
                    admin_id_list.append(PydanticObjectId(ids["$oid"]))

                logger.info({"admin_id_list":admin_id_list})
                
                admins = await models.BusinessAdmin.aggregate([
                    {"$match": {"_id": {"$in": admin_id_list}}},
                    
                    {
                        "$lookup": {
                            "from": "user_base",
                            "localField": "user_base",
                            "foreignField": "_id",
                            "as": "business_admin_info"
                },
            },
                    ]).to_list()
                logger.info({"admins":admins})

                admins = json.loads(json_util.dumps(admins))
                
                admin_data_list = []
                for admin in admins:
                    admin_info = admin.get("business_admin_info", [])
                    for admin_info_item in admin_info:
                        admin_data_list.append({
                            "_id": str(admin_info_item["_id"]),
                            "name": admin_info_item["name"],
                            "email": admin_info_item.get("email", None),
                            "role": admin_info_item["role"],
                            "is_active": admin_info_item["is_active"]
                        })

                user_data["business_owner"]["business_admins"] = admin_data_list

               
            if user_data["role"] == "admin" and user["admin"]:
                user_data["admin"] = user["admin"][0]

            if user_data["role"] == "teller" and user["teller"]:
                user_data["teller"] = user["teller"][0]
            
            if user_data["role"] == "customer" and user["customer"]:
                user_data["customer"] = user["customer"][0]
            logger.info(user_data)
            if user_data["role"] == "super_admin" and user["super_admin"]:
                user_data["super_admin"] = user["super_admin"][0]
            
            user_data_list.append(user_data)
        
        
        return user_data_list

    @classmethod
    async def create_new_token(token:str):
        access_token = await oauth2.create_new_token(token)
        return await responses.success_message_data("new token created successfully",
                                                 {"access_token":access_token})