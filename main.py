from fastapi import FastAPI, HTTPException, Depends, Cookie, Response
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer, HTTPAuthorizationCredentials, HTTPBearer
from sqlmodel import Session, select, SQLModel
from typing import List, Optional
from contextlib import asynccontextmanager
from fastapi.middleware.cors import CORSMiddleware

from database import engine, init_db
from models import User, UserCreate, UserRead
from auth import (get_password_hash, 
                  verify_password, 
                  verify_email,
                  create_access_token, 
                  create_refresh_token,
                  decode_token,
                  is_refresh_token_expired,
                  blacklist_token,
                  validate_token)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/login')

# startup DB
@asynccontextmanager
async def lifespan(app: SQLModel):
    print('Startup')
    init_db()
    yield
    print('Shutdown')
    pass

app = FastAPI()

origins = [
    "http://localhost:3000",
    "http://127.0.0.1:8000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# start session
def get_session():
    with Session(engine) as session:
        yield session

@app.get('/')
def index():
    return {
        'app_name': 'distilbart-text-summarizer',
        'version': '0.0.1',
        'contributor/s': ['Jehu Casimiro']
    }