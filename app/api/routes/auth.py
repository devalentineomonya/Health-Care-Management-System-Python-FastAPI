from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.config import settings
from app.core.security import create_access_token
from app.crud.crud_user import user
from app.schemas.user import User, UserCreate, Token
from app.db.session import get_db
from pydantic import BaseModel, EmailStr

router = APIRouter()


class LoginRequest(BaseModel):
    email: EmailStr = "demo@example.com"
    password: str = "password123"

    class Config:
        schema_extra = {
            "example": {"email": "user@example.com", "password": "supersecret"}
        }


@router.post("/login", response_model=Token, status_code=status.HTTP_200_OK)
def login_access_token(
    login_data: LoginRequest,
    db: Session = Depends(get_db)
) -> Any:
    """
    Token login with JSON, get an access token for future requests.

    - **email**: Email address
    - **password**: User password
    """
    user_obj = user.authenticate(
        db, email=login_data.email, password=login_data.password
    )
    if not user_obj:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    elif not user_obj.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )

    access_token_expires = timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    return {
        "access_token": create_access_token(
            user_obj.id, user_obj.role, expires_delta=access_token_expires
        ),
        "token_type": "bearer",
    }


@router.post("/register", response_model=User, status_code=status.HTTP_201_CREATED)
def create_user(
    *,
    db: Session = Depends(get_db),
    user_in: UserCreate,
) -> Any:
    """
    Create new user.
    """
    user_obj = user.get_by_email(db, email=user_in.email)
    if user_obj:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The user with this email already exists in the system.",
        )
    return user.create(db, obj_in=user_in)


@router.get("/me", response_model=User)
def read_users_me(
    current_user: User = Depends(get_current_user)
) -> Any:
    """
    Get current user.
    """
    return current_user
