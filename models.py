from typing import Optional
from sqlmodel import SQLModel, Field
from datetime import datetime


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    email: str
    hashed_password: str


class UserCreate(SQLModel):
    name: str
    email: str
    password: str


class UserRead(SQLModel):
    id: int
    name: str
    email: str


class BlacklistedToken(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    token_id: str = Field(index=True) # JTI (JWT ID)
    blacklist_at: datetime = Field(default_factory=datetime.now)
    expires_at: datetime