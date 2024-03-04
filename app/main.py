from fastapi import FastAPI
import logging
from contextlib import asynccontextmanager
from .config.database import startup_db
from .auth_app.seeded import create_super_admin

from dotenv import load_dotenv
import os
from .routes import router


logger = logging.getLogger(__name__)
load_dotenv()
email = os.getenv("email")
password = os.getenv("password")
name = os.getenv("name")

@asynccontextmanager
async def lifespan(app:FastAPI):
    await startup_db() 
    await create_super_admin(email, password, name)
    yield

app = FastAPI(lifespan=lifespan)
@app.get("/")
async def func():
    logger.info("first endpoint!")
    return {"message": "hello world!"}


prefix ="/api/v1"
app.include_router(router, prefix = prefix)


