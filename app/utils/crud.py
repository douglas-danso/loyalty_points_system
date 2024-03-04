from typing import Type
from fastapi import HTTPException, status
from pydantic import BaseModel
from app.auth_app.models import (UserBase, SuperAdmin, 
Admin, BusinessOwner, BusinessAdmin, Teller, Customer, OTP)
from . import responses 

from beanie import PydanticObjectId, WriteRules
import logging

logger = logging.getLogger(__name__)

class UserBaseRepository:
    def __init__(self, model: Type):
        self.model = model

    async def create(self, item: BaseModel):
        logger.info(type(item))
        if type(item) != dict:
            item.model_dump()
        document = self.model(**item)
        await document.insert()
        return document
    
    async def create_with_link(self,link:dict,**kwargs):
        logger.info("heloooooooooooo")
        instance = self.model(**link)
        logger.info(instance)
        for key, value in kwargs.items():
            setattr(instance, key, value)
        logger.info(instance)
        return await instance.save(link_rule=WriteRules.WRITE)
    
    async def edit_data(self, instance,**kwargs):
        for key, value in kwargs.items():
            if value:
                setattr(instance, key, value)
        return await instance.save()
    
    async def get(self, filters: dict):
        logger.info(filters)
        return await self.model.find(filters,fetch_links=True).first_or_none()
    
    async def get_by_id(self, filters:str):
        return await self.model.get(filters,fetch_links=True)
    
    async def get_many(self):
        return await self.model.find_many().to_list()


    async def update(self, filter: dict, updated_item: BaseModel):
        document = await self.get(filter)
        if document:
            data = updated_item.model_dump()
            return await document.update({"$set": data})
    
        else:
            response = await responses.error_message(
            f"{self.model.__name__} not found",
            status=status.HTTP_404_NOT_FOUND
        )
        logger.error(response)
        return response
    async def delete(self, filter: dict):
        document = await self.get(filter)
        if document:
            await document.delete()
        else:
            response = await responses.error_message(
            f"{self.model.__name__} not found",
            status=status.HTTP_404_NOT_FOUND
        )
        logger.error(response)
        return response

class UserDocumentFactory:
    @staticmethod
    def create_document(model_name: str) -> Type:
        model_map = {
            'UserBase':UserBase,
            'SuperAdmin': SuperAdmin,
            'Admin': Admin,
            'BusinessOwner': BusinessOwner,
            'BusinessAdmin': BusinessAdmin,
            'Teller': Teller,
            'Customer': Customer,
            "OTP": OTP
        }
        model_maps = model_map.get(model_name, UserBase)
        return model_maps

def get_repository(model_name: str):
    document_model = UserDocumentFactory.create_document(model_name)
    return UserBaseRepository(document_model)