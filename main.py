from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import requests
import os
from dotenv import load_dotenv
import json
load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_API_URL = "https://api.groq.com/openai/v1/responses"

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

class DetectRequest(BaseModel):
    text: str
    model: str = "openai/gpt-oss-20b"


@app.post("/detect")
def detect(req: DetectRequest):
    if not GROQ_API_KEY:
        raise HTTPException(
            status_code=500,
            detail="GROQ_API_KEY not set. Set GROQ_API_KEY in environment."
        )

    system_instruction = (
        "You are a phishing detection AI. "
        "Return ONLY valid JSON with keys: "
        "risk_score (0-100), risk_level (Low|Moderate|High), "
        "is_phishing (true|false), reason (max 12 words). "
        "No explanation."
    )

    payload = {
        "model": req.model,
        "input": [
            {"role": "system", "content": system_instruction},
            {"role": "user", "content": req.text}
        ],
        "max_output_tokens": 60,      
        "temperature": 0,
        "top_p": 0.1,
        "reasoning": {"effort": "low"}  
    }

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json",
    }

    try:
        resp = requests.post(
            GROQ_API_URL,
            json=payload,
            headers=headers,
            timeout=15
        )
        resp.raise_for_status()
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=str(e))

    try:
        data = resp.json()
    except Exception:
        data = {"raw": resp.text}

    normalized = {"raw_response": data}

    try:
        output_text = ""

        if "output" in data:
            for item in data["output"]:
                if item.get("type") == "message":
                    for part in item.get("content", []):
                        if part.get("type") == "output_text":
                            output_text += part.get("text", "")

        normalized["content"] = output_text.strip()

        lc = output_text.lower()
        normalized["suspicious"] = any(
            k in lc for k in ["phish", "phishing", "malicious", "suspicious", "scam"]
        )

    except Exception:
        normalized["content"] = None
        normalized["suspicious"] = False
    return json.loads(output_text.strip())


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("groq_server:app", host="0.0.0.0", port=8000, log_level="info")
