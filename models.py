from typing import Optional
from sqlmodel import SQLModel, Field
from datetime import datetime, timezone
from pydantic import BaseModel


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
    email: str


class BlacklistedToken(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    token_id: str = Field(index=True) # JTI (JWT ID)
    blacklist_at: datetime = Field(default_factory=datetime.now)
    expires_at: datetime

class SummarizeRequest(BaseModel):
    text: str

class SummarizeResponse(BaseModel):
    summary: str

class Summary(SQLModel, table=True):
    __tablename__ = "summaries"
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    original_text: str
    summary_text: str
    title: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class SummaryHistoryItem(BaseModel):
    id: int
    title: str
    preview: str
    timestamp: str  # ISO formatted string

class SummaryDetailResponse(BaseModel):
    id: int
    title: str
    original_text: str
    summary_text: str
    timestamp: str