from fastapi import FastAPI, HTTPException, Depends, Cookie, Response, Request, logger
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from sqlmodel import Session, select, SQLModel
from typing import Optional, List
from contextlib import asynccontextmanager
from fastapi.middleware.cors import CORSMiddleware
import os
from datetime import timedelta
from dotenv import load_dotenv
from fastapi.responses import RedirectResponse
import requests
from transformers import pipeline
# from fastapi import status
from transformers import AutoTokenizer

from database import engine, init_db
from models import User, UserCreate, UserRead, SummarizeRequest, SummarizeResponse, Summary, SummaryDetailResponse, SummaryHistoryItem
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
ENV = os.getenv("ENV", "prod")
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
GOOGLE_REDIRECT_URI = os.getenv('GOOGLE_REDIRECT_URI')
FRONTEND_URL = os.getenv('FRONTEND_URL')
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv('REFRESH_TOKEN_EXPIRE_DAYS', 7))

summarizer = None
tokenizer = None
MAX_TOKENS = 1024
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/login')

@asynccontextmanager
async def lifespan(app: SQLModel):
    print('Startup')
    init_db()
    global summarizer, tokenizer
    print('[Startup] Loading DistilBART summarization model...')
    try:
        summarizer = pipeline("summarization", model="sshleifer/distilbart-cnn-12-6")
        tokenizer = AutoTokenizer.from_pretrained("sshleifer/distilbart-cnn-12-6")
        print('[Startup] DistilBART model loaded successfully.')
    except Exception as e:
        summarizer = None
        tokenizer = None
        print(f'[Startup] Failed to load DistilBART model: {e}')
    yield
    print('Shutdown')

app = FastAPI(lifespan=lifespan)

if ENV == "dev":
    allow_origins = [
        "http://localhost:3000",
        "http://127.0.0.1:8000",
    ]
else:
    allow_origins = [
        "https://your-production-frontend.com",
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
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
        secure=True,
        samesite="none",
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
        secure=True,
        samesite="none",
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
        samesite="none",
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

@app.get('/auth/google/login')
def google_login():
    params = {
        'client_id': GOOGLE_CLIENT_ID,
        'redirect_uri': GOOGLE_REDIRECT_URI,
        'response_type': 'code',
        'scope': 'openid email profile',
        'access_type': 'offline',
        'prompt': 'consent',
    }
    from urllib.parse import urlencode
    url = f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"
    return RedirectResponse(url)

@app.post('/auth/google/callback')
async def google_callback(request: Request, response: Response, session: Session = Depends(get_session)):
    data = await request.json()
    code = data.get("code")
    if not code:
        raise HTTPException(status_code=400, detail="Missing code")
    # Exchange code for tokens
    token_data = {
        'code': code,
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'redirect_uri': GOOGLE_REDIRECT_URI,
        'grant_type': 'authorization_code',
    }
    token_resp = requests.post('https://oauth2.googleapis.com/token', data=token_data)
    if not token_resp.ok:
        raise HTTPException(status_code=400, detail='Failed to obtain token from Google')
    tokens = token_resp.json()
    access_token = tokens.get('access_token')
    if not access_token:
        raise HTTPException(status_code=400, detail='No access token from Google')

    # Fetch user info
    userinfo_resp = requests.get(
        'https://www.googleapis.com/oauth2/v3/userinfo',
        headers={'Authorization': f'Bearer {access_token}'}
    )
    if not userinfo_resp.ok:
        raise HTTPException(status_code=400, detail='Failed to fetch user info from Google')
    userinfo = userinfo_resp.json()
    email = userinfo.get('email')
    name = userinfo.get('name')
    if not email:
        raise HTTPException(status_code=400, detail='Google account has no email')

    # Check if user exists, else create
    user = session.exec(select(User).where(User.email == email)).first()
    if not user:
        user = User(
            name=name or email.split('@')[0],
            email=email,
            hashed_password=get_password_hash(os.urandom(16).hex())  # random password
        )
        session.add(user)
        session.commit()
        session.refresh(user)

    # Issue tokens
    app_access_token = create_access_token(data={'sub': str(user.id)})
    app_refresh_token = create_refresh_token(data={'sub': str(user.id)})
    max_age = int(timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS).total_seconds())

    # Set refresh token as HTTP-only cookie
    response.set_cookie(
        key='refresh_token',
        value=app_refresh_token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=max_age
    )

    # Return access token in JSON response
    return {
        "access_token": app_access_token,
        "token_type": "bearer",
        "user": {"id": user.id, "email": user.email, "name": user.name}
    }

def chunk_text(text, max_tokens=MAX_TOKENS):
    tokens = tokenizer.encode(text)
    for i in range(0, len(tokens), max_tokens):
        yield tokenizer.decode(tokens[i:i+max_tokens])

@app.post("/summarize_text", response_model=SummarizeResponse)
def summarize_document(
    request: SummarizeRequest,
    current_user: dict = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    input_text = request.text.strip()
    if not input_text:
        raise HTTPException(status_code=400, detail="Input text must not be empty or whitespace.")

    # Chunk and summarize
    summaries = []
    for chunk in chunk_text(input_text):
        summary = summarizer(
            chunk,
            max_length=256,
            min_length=64,
            do_sample=False,
            num_beams=8
        )[0]["summary_text"]
        summaries.append(summary)
    # Optionally, summarize the summaries for a final summary
    if len(summaries) > 1:
        final_summary = summarizer(
            " ".join(summaries),
            max_length=256,
            min_length=64,
            do_sample=False,
            num_beams=6
        )[0]["summary_text"]
    else:
        final_summary = summaries[0]

    # Generate a title from the summary
    title_source = final_summary if final_summary else input_text
    title_words = title_source.split()
    title = " ".join(title_words[:10]) + ("..." if len(title_words) > 10 else "")
    title = title[:252] + "..." if len(title) > 255 else title

    # Save to database
    summary = Summary(
        user_id=current_user.id,
        original_text=input_text,
        summary_text=final_summary,
        title=title
    )
    session.add(summary)
    session.commit()
    session.refresh(summary)

    return SummarizeResponse(summary=final_summary)

@app.get("/summaries", response_model=List[SummaryHistoryItem])
def get_summaries(
    current_user: dict = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    user_id = current_user["sub"] if isinstance(current_user, dict) else current_user.id
    summaries = session.exec(
        select(Summary).where(Summary.user_id == user_id).order_by(Summary.created_at.desc())
    ).all()
    def make_preview(text):
        # Use the first sentence as preview, or first 100 chars if no period
        if "." in text:
            return text.split('. ')[0] + "."
        return text[:100] + ("..." if len(text) > 100 else "")
    return [
        SummaryHistoryItem(
            id=s.id,
            title=s.title or make_preview(s.original_text),
            preview=make_preview(s.summary_text),
            timestamp=s.created_at.isoformat() if hasattr(s.created_at, 'isoformat') else str(s.created_at)
        )
        for s in summaries
    ]

@app.get("/summaries/{summary_id}", response_model=SummaryDetailResponse)
def get_summary_by_id(
    summary_id: int,
    current_user: dict = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    user_id = current_user["sub"] if isinstance(current_user, dict) else current_user.id
    summary = session.get(Summary, summary_id)
    if not summary or summary.user_id != user_id:
        raise HTTPException(status_code=404, detail="Summary not found")
    return SummaryDetailResponse(
        id=summary.id,
        title=summary.title or " ".join(summary.original_text.strip().split()[:10]),
        original_text=summary.original_text,
        summary_text=summary.summary_text,
        timestamp=summary.created_at.isoformat() if hasattr(summary.created_at, 'isoformat') else str(summary.created_at)
    )

@app.delete("/summaries/{summary_id}")
def delete_summary(
    summary_id: int,
    current_user: dict = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    user_id = current_user["sub"] if isinstance(current_user, dict) else current_user.id
    summary = session.get(Summary, summary_id)
    if not summary or summary.user_id != user_id:
        raise HTTPException(status_code=404, detail="Summary not found")
    session.delete(summary)
    session.commit()
    return {"message": "Summary deleted successfully"}





