from datetime import datetime, timedelta
from jose import jwt, JWTError
import bcrypt
from dotenv import load_dotenv
import os
import re
import uuid
from sqlmodel import Session, select
from models import BlacklistedToken
from fastapi import HTTPException


load_dotenv()
# Google OAuth 2.0 endpoints
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"

ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES'))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv('REFRESH_TOKEN_EXPIRE_DAYS'))
SECRET_KEY = os.getenv('SECRET_KEY')
ALGORITHM = os.getenv('ALGORITHM')


def verify_password(plain_password: str, hashed_password: str):
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))


def verify_email(email: str):
    return True if re.search(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email) else False


def get_password_hash(password: str):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def create_access_token(data: dict):
    expire = datetime.now() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = data.copy()
    to_encode.update({
        'exp': int(expire.timestamp()),
        'iat': int(datetime.now().timestamp()),
        'type': 'access',
        'jti': str(uuid.uuid4())
    })
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(data: dict):
    expire = datetime.now() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode = data.copy()
    to_encode.update({
        'exp': int(expire.timestamp()),
        'iat': int(datetime.now().timestamp()),
        'type': 'refresh',
        'jti': str(uuid.uuid4())
    })
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def is_access_token_expired(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get('type') != 'access':
            return True
        exp_timestamp = payload['exp']
        current_timestamp = datetime.now().timestamp()
        return exp_timestamp < current_timestamp
    except JWTError:
        return True
    

def is_refresh_token_expired(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get('type') != 'refresh':
            return True
        exp_timestamp = payload['exp']
        current_timestamp = datetime.now().timestamp()
        return exp_timestamp < current_timestamp
    except JWTError:
        return True
    

def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get('type') not in ('access', 'refresh'):
            raise HTTPException(status_code=401, detail='Invalid token type')
        return payload
    except JWTError as e:
        raise HTTPException(status_code=401, detail='Invalid token') from e
    

def is_token_blacklisted(token: str, session: Session) -> bool:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        token_id = payload.get('jti')
        if not token_id:
            return True
        blacklisted = session.exec(
            select(BlacklistedToken).where(BlacklistedToken.token_id == token_id)
        ).first()
        return blacklisted is not None
    except JWTError:
        return True
    

def blacklist_token(token: str, session: Session):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        token_id = payload.get('jti')
        exp_timestamp = payload.get('exp')
        if not token_id or not exp_timestamp:
            raise HTTPException(status_code=400, detail='Invalid token for blacklisting')
        # add token to blacklist
        blacklist_token = BlacklistedToken(
            token_id=token_id,
            expires_at=datetime.fromtimestamp(exp_timestamp)
        )
        session.add(blacklist_token)
        session.commit()
        return True
    except JWTError as e:
        raise HTTPException(status_code=400, detail='Invalid token for blacklisting') from e
    

def validate_token(token: str, session: Session):
    payload = decode_token(token)
    if payload is None:
        raise HTTPException(status_code=401, detail='Invalid access token')
    
    if is_access_token_expired(token):
        raise HTTPException(status_code=401, detail='Access token expired')
    
    if is_token_blacklisted(token, session):
        raise HTTPException(status_code=401, detail='Token has been invalidated')
