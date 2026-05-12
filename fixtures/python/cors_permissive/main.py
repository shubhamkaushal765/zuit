"""FastAPI application with a permissive CORS configuration."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# SEC011: allow_origins=["*"] is overly permissive
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)
