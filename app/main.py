from fastapi import FastAPI
import logging
from contextlib import asynccontextmanager
from .config.database import startup_db


logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app:FastAPI):
    await startup_db() 
    yield

app = FastAPI(lifespan=lifespan)
@app.get("/")
async def func():
    logger.info(f"request / endpoint!")
    return {"message": "hello world!"}