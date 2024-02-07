from fastapi import FastAPI
import logging
from contextlib import asynccontextmanager
from .config.database import startup_db
from .auth_app.seeded import create_super_admin
from dotenv import load_dotenv
import os

logger = logging.getLogger(__name__)
load_dotenv()
email = os.getenv("email")
password = os.getenv("password")
@asynccontextmanager
async def lifespan(app:FastAPI):
    await startup_db() 
    await create_super_admin(email, password, name="douglas")
    yield

app = FastAPI(lifespan=lifespan)
@app.get("/")
async def func():
    logger.info(f"request / endpoint!")
    return {"message": "hello world!"}