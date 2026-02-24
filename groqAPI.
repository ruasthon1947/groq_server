from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import requests
import os
from dotenv import load_dotenv

load_dotenv()

# Paste your Groq API key here or set the GROQ_API_KEY env var on Render
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
# Default Groq API URL; update if Render or Groq provide a different endpoint
GROQ_API_URL = os.getenv("GROQ_API_URL") or "https://api.groq.ai/v1/models/groq-1/outputs"

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


class DetectRequest(BaseModel):
    text: str
    model: str = "groq-1"


@app.post("/detect")
def detect(req: DetectRequest):
    if not GROQ_API_KEY or GROQ_API_KEY == "PASTE_YOUR_KEY_HERE":
        raise HTTPException(status_code=500, detail="GROQ_API_KEY not set. Paste your API key into the file or set env var.")

    payload = {"input": req.text}
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json",
    }

    try:
        resp = requests.post(GROQ_API_URL, json=payload, headers=headers, timeout=20)
        resp.raise_for_status()
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=str(e))

    # Return Groq response directly; adapt parsing if you want a normalized schema
    return resp.json()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("groq_server:app", host="0.0.0.0", port=8000, log_level="info")
