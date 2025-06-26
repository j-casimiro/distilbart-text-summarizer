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

app = FastAPI(lifespan=lifespan)

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


# register user
@app.post('/register', response_model=UserRead)
def register(user: UserCreate, session: Session = Depends(get_session)):
    user_exists = session.exec(select(User).where(User.email == user.email)).first()
    if user_exists:
        raise HTTPException(status_code=400, detail='email already exist')
    
    if not verify_email(user.email):
        raise HTTPException(status_code=400, detail='email is invalid')
    
    db_user = User(name=user.name, email=user.email, hashed_password=get_password_hash(user.password))
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return {'id': db_user.id, 'email': db_user.email}


# login user
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

    # set refresh token in HTTP-only cookie
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        samesite='strict',
        max_age=60 * 60 * 24 * 7 # 7 days
    )

    return {
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user': user,
        'token_type': 'bearer'
    }


# get current user
def get_current_user(token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)):
    validate_token(token, session)
    payload = decode_token(token)
    user_id = int(payload.get('sub'))
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail='User not found')
    return user