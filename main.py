from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import requests
import os
from dotenv import load_dotenv
import json
import re
from urllib.parse import urlparse

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


SAFE_DOMAINS = [
    
    "amazon.in", "amazon.com", "amazon.co.in",
    "flipkart.com", "myntra.com", "ajio.com",
    "snapdeal.com", "meesho.com",

    
    "magicbricks.com", "99acres.com", "housing.com",

    
    "paytm.com", "phonepe.com", "gpay.com",
    "razorpay.com", "upi.com",


    "hdfcbank.com", "icicibank.com", "sbi.co.in",
    "axisbank.com", "kotak.com", "indusind.com",


    "google.com", "accounts.google.com",
    "microsoft.com", "apple.com",
    "linkedin.com", "facebook.com", "instagram.com",


    "makemytrip.com", "goibibo.com",
    "booking.com", "airbnb.com",


    "coursera.org", "udemy.com",

    "swiggy.com", "zomato.com",


    "github.com", "vercel.com", "netlify.com",

    "gov.in", "nic.in"
]

class DetectRequest(BaseModel):
    text: str
    model: str = "openai/gpt-oss-20b"



def clean_text(text: str):
    return re.sub(r'[\u200B-\u200D\uFEFF]', '', text)



def extract_domain(text: str):
    urls = re.findall(r'https?://[^\s]+', text)
    if not urls:
        return None
    try:
        parsed = urlparse(urls[0])
        return parsed.netloc.lower()
    except:
        return None


@app.post("/detect")
def detect(req: DetectRequest):

    if not GROQ_API_KEY:
        raise HTTPException(
            status_code=500,
            detail="GROQ_API_KEY not set. Set GROQ_API_KEY in environment."
        )

    cleaned_text = clean_text(req.text)
    sender_domain = extract_domain(cleaned_text)

    system_instruction = (
        "You are a phishing detection AI. "
        "Return ONLY valid JSON with keys: "
        "risk_score (0-100), risk_level (Low|Moderate|High), "
        "is_phishing (true|false), reason (max 12 words). "
        "Mark phishing ONLY if strong malicious indicators exist "
        "(credential theft, fake login, domain impersonation, urgent data request). "
        "Legitimate marketing emails from known companies are NOT phishing."
    )

    payload = {
        "model": req.model,
        "input": [
            {"role": "system", "content": system_instruction},
            {"role": "user", "content": cleaned_text}
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

    output_text = ""

    if "output" in data:
        for item in data["output"]:
            if item.get("type") == "message":
                for part in item.get("content", []):
                    if part.get("type") == "output_text":
                        output_text += part.get("text", "")

    output_text = output_text.strip()

    try:
        ai_result = json.loads(output_text)
    except Exception:
        raise HTTPException(status_code=500, detail="AI returned invalid JSON")

    if sender_domain:
        for safe in SAFE_DOMAINS:
            if safe in sender_domain:
                if ai_result.get("risk_score", 0) > 60:
                    ai_result["risk_score"] = 15
                    ai_result["risk_level"] = "Low"
                    ai_result["is_phishing"] = False
                    ai_result["reason"] = "Trusted legitimate domain"
                break


    return ai_result


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("groq_server:app", host="0.0.0.0", port=8000, log_level="info")
