from fastapi import FastAPI
from datetime import datetime

app = FastAPI()

@app.get("/")
async def root():
    return {"message": "Hello World", "timestamp": datetime.utcnow()}

@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": datetime.utcnow()}

# Vercel compatibility
app = app
