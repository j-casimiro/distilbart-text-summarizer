# import os
from sqlmodel import SQLModel, create_engine, Session
# from dotenv import load_dotenv

DATABASE_URL = 'sqlite:///.database.db' #replace with your actual database url
engine = create_engine(DATABASE_URL, echo=True)

def init_db():
    SQLModel.metadata.create_all(engine)