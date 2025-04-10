from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from models.models import Base
from database.database import engine
from router import router  # This imports your router from routers/auth.py

# Create all database tables
Base.metadata.create_all(bind=engine)

# Initialize FastAPI app
app = FastAPI()

# Set up CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
    "http://localhost:3000",
    "https://71e1-2401-4900-67aa-bf5e-2d49-e8df-91fa-c206.ngrok-free.app"
],  # Update this in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include the auth routes
app.include_router(router.router)
