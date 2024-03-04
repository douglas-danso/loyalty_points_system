from .auth_app.user_controller import auth_router

from fastapi import APIRouter

router = APIRouter()
router.include_router(auth_router)