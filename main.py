from fastapi import FastAPI, HTTPException, Depends, Cookie, Response
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from sqlmodel import Session, select, SQLModel
from typing import Optional
from contextlib import asynccontextmanager
from fastapi.middleware.cors import CORSMiddleware
import os
from datetime import timedelta
from dotenv import load_dotenv

from database import engine, init_db
from models import User, UserCreate, UserRead
from auth import (
    get_password_hash, 
    verify_password, 
    verify_email,
    create_access_token, 
    create_refresh_token,
    decode_token,
    is_refresh_token_expired,
    blacklist_token,
    validate_token
)

load_dotenv()
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv('REFRESH_TOKEN_EXPIRE_DAYS', 7))
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/login')

@asynccontextmanager
async def lifespan(app: SQLModel):
    print('Startup')
    init_db()
    yield
    print('Shutdown')

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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

@app.post('/register', response_model=UserRead)
def register(user: UserCreate, session: Session = Depends(get_session)):
    if session.exec(select(User).where(User.email == user.email)).first():
        raise HTTPException(status_code=400, detail='email already exist')
    if not verify_email(user.email):
        raise HTTPException(status_code=400, detail='email is invalid')
    db_user = User(
        name=user.name,
        email=user.email,
        hashed_password=get_password_hash(user.password)
    )
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return {'id': db_user.id, 'email': db_user.email}

@app.post('/login')
def login(
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: Session = Depends(get_session)
):
    user = session.exec(select(User).where(User.email == form_data.username)).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail='Invalid Credentials')
    access_token = create_access_token(data={'sub': str(user.id)})
    refresh_token = create_refresh_token(data={'sub': str(user.id)})
    max_age = int(timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS).total_seconds())
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        samesite='strict',
        max_age=max_age
    )
    return {
        'access_token': access_token,
        'refresh_token': refresh_token,
        'token_type': 'bearer'
    }

def get_current_user(token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)):
    validate_token(token, session)
    payload = decode_token(token)
    user_id = int(payload.get('sub'))
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail='User not found')
    return user

@app.get('/current_user', response_model=UserRead)
def read_current_user(current_user: User = Depends(get_current_user)):
    return current_user

@app.post('/refresh')
def refresh_token(
    response: Response,
    refresh_token: Optional[str] = Cookie(None),
    session: Session = Depends(get_session)
):
    if not refresh_token:
        raise HTTPException(status_code=401, detail='Refresh token not found')
    payload = decode_token(refresh_token)
    if not payload:
        raise HTTPException(status_code=401, detail='Invalid refresh token')
    if is_refresh_token_expired(refresh_token):
        raise HTTPException(status_code=401, detail='Refresh token expired')
    user_id = int(payload.get('sub'))
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail='User not found')
    new_access_token = create_access_token(data={'sub': str(user.id)})
    new_refresh_token = create_refresh_token(data={'sub': str(user.id)})
    max_age = int(timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS).total_seconds())
    response.set_cookie(
        key='refresh_token',
        value=new_refresh_token,
        httponly=True,
        samesite='strict',
        max_age=max_age
    )
    return {
        'new_access_token': new_access_token,
        'token_type': 'bearer'
    }

@app.post('/logout')
def logout(
    response: Response, 
    access_token: str = Depends(oauth2_scheme),
    refresh_token: Optional[str] = Cookie(None),
    session: Session = Depends(get_session)
):
    if not blacklist_token(access_token, session):
        raise HTTPException(status_code=400, detail='Failed to invalidate access token')
    if refresh_token and not blacklist_token(refresh_token, session):
        raise HTTPException(status_code=400, detail='Failed to invalidate refresh token')
    response.delete_cookie(
        key="refresh_token",
        httponly=True,
        secure=True,
        samesite="strict"
    )
    return {"message": "Successfully logged out"}

@app.post('/validate')
def token_validate(
    token: str = Depends(oauth2_scheme),
    session: Session = Depends(get_session)
):  
    try:
        validate_token(token, session)
        payload = decode_token(token)
        user_id = int(payload.get('sub'))
        user = session.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail='User not found')
        return {
            "valid": True,
            "user_id": user_id,
        }
    except HTTPException as e:
        return {
            "valid": False,
            "detail": e.detail
        }