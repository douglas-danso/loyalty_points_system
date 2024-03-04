from fastapi import status
from enum import Enum
from fastapi.responses import JSONResponse

class ActionsEnum(str,Enum):
    deleted = "deleted"
    created = "created"
    updated = "updated"

async def success_message(object:str,action:ActionsEnum):
    return {
        "details":f"{object}  {action} successfully",
        "status": status.HTTP_200_OK
    }

async def success_message_data(msg, data):
    return {
        "details":msg,
        "data":data,
        "status": status.HTTP_200_OK
    }


async def error_message(message:str, status:status):
    return {
        "error": message,
        "status": status
    }

async def send_message_success():
    return {
        "details":"message sent successfully",
        "status": status.HTTP_200_OK
    }