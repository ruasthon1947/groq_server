from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import requests
import os
from dotenv import load_dotenv

load_dotenv()

# Set your Groq API key in the environment on Render
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
# Correct Groq chat completions endpoint
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


class DetectRequest(BaseModel):
    text: str
    model: str = "groq-1"


@app.post("/detect")
def detect(req: DetectRequest):
    if not GROQ_API_KEY:
        raise HTTPException(status_code=500, detail="GROQ_API_KEY not set. Set GROQ_API_KEY in environment.")

    payload = {
        "model": req.model,
        "messages": [{"role": "user", "content": req.text}],
    }
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json",
    }

    try:
        resp = requests.post(GROQ_API_URL, json=payload, headers=headers, timeout=15)
        resp.raise_for_status()
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=str(e))

    try:
        data = resp.json()
    except Exception:
        data = {"raw": resp.text}

    # Normalize response: extract assistant content and a simple suspicious boolean
    normalized = {"raw_response": data}
    try:
        content = data.get("choices", [])[0].get("message", {}).get("content", "")
        normalized["content"] = content
        lc = (content or "").lower()
        normalized["suspicious"] = any(k in lc for k in ["phish", "phishing", "malicious", "suspicious", "scam"])
    except Exception:
        normalized["content"] = None
        normalized["suspicious"] = False

    return normalized


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("groq_server:app", host="0.0.0.0", port=8000, log_level="info")
