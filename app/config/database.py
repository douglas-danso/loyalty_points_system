import os
from dotenv import load_dotenv
from beanie import init_beanie
from motor.motor_asyncio import AsyncIOMotorClient
from app.auth_app.models import (
    SuperAdmin,Admin,BusinessOwner,BusinessAdmin,
    Customer,Teller
)
import logging

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
logger = logging.getLogger(__name__)

async def startup_db():
    logger.info("starting db")
    try:
        client = AsyncIOMotorClient(DATABASE_URL)
        await init_beanie(client.get_default_database(), 
            document_models=[
                SuperAdmin,
                 Admin,BusinessAdmin,
                 BusinessOwner,Customer,
                 Teller
                 ]  
        )
        logger.info("db started")
    except Exception as e:
        logger.error("Failed to start database: %s", e)


async def get_db():
    db = await startup_db()
    try:
        yield db
    finally:
        await db.close()