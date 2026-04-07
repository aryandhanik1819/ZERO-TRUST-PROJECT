#!/usr/bin/env python3
"""
Zero Trust Network Security Framework
Main application entry point
"""

import uvicorn
from fastapi import FastAPI

from api.routes import router as api_router
from config import settings

app = FastAPI(
    title="Zero Trust Network Security Framework",
    description="A comprehensive zero trust security implementation",
    version="1.0.0"
)

# Include routers
app.include_router(api_router, prefix="/api/v1")

@app.get("/")
async def root():
    return {"message": "Zero Trust Network Security Framework"}

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=True
    )