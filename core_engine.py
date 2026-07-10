import whois
import tldextract
import requests
from urllib.parse import urlparse
import datetime
import google.generativeai as genai
import json
import os
from dotenv import load_dotenv

load_dotenv()

# Securely load Gemini API Key
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

def extract_url_features(url):
    """Extracts deterministic features from a URL."""
    if not url.startswith("http"):
        url = "http://" + url
        
    parsed_url = urlparse(url)
    ext = tldextract.extract(url)
    
    domain = ext.domain + "." + ext.suffix
    
    features = {
        "url": url,
        "domain": domain,
        "subdomain": ext.subdomain,
        "is_https": parsed_url.scheme == "https",
        "url_length": len(url),
        "has_ip_in_domain": any(char.isdigit() for char in domain.replace(".", "")),
        "hyphens_in_domain": domain.count("-"),
        "suspicious_words": check_suspicious_words(url)
    }
    return features

def check_suspicious_words(url):
    """Checks for common phishing keywords often used in BD."""
    keywords = ["free", "offer", "bkash", "daraz", "nagad", "lottery", "login", "update", "verify", "account", "gov", "bcs", "job"]
    found = [word for word in keywords if word in url.lower()]
    return found

def get_whois_data(domain):
    """Retrieves domain registration age and details."""
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        
        if type(creation_date) == list:
            creation_date = creation_date[0]
            
        if creation_date:
            age_days = (datetime.datetime.now() - creation_date).days
            return {"domain_age_days": age_days, "registrar": domain_info.registrar, "error": None}
        return {"domain_age_days": "Unknown", "registrar": "Hidden", "error": None}
    except Exception as e:
        return {"domain_age_days": "Unknown", "registrar": "Unknown", "error": str(e)}

def analyze_with_ai(url_features, whois_features):
    """Uses Gemini API to act as a Cyber Analyst and score the risk."""
    if not GEMINI_API_KEY:
        return {"score": 50, "verdict": "⚠️ AI Offline", "reasoning": "Gemini API Key missing in .env file."}
    
    prompt = f"""
    You are an elite Cybersecurity Threat Intelligence Analyst. 
    Analyze the following URL features and WHOIS data to determine if this link is a phishing scam, especially targeting Bangladeshi users (e.g., fake bKash, Daraz, Gov jobs).
    
    URL Features: {json.dumps(url_features)}
    WHOIS Data: {json.dumps(whois_features)}
    
    Provide your analysis in JSON format exactly like this:
    {{
        "risk_score": <int 0-100 where 100 is definitely phishing>,
        "verdict": "<Safe | Suspicious | High Risk Phishing>",
        "reasoning_bengali": "<Explain in clear, professional Bengali why this is safe or a scam. Mention domain age, lack of HTTPS, typosquatting, etc.>"
    }}
    Do NOT include markdown formatting like ```json, just output the raw JSON object.
    """
    
    try:
        model = genai.GenerativeModel('gemini-1.5-flash')
        response = model.generate_content(prompt)
        text = response.text.replace('```json', '').replace('```', '').strip()
        analysis = json.loads(text)
        return analysis
    except Exception as e:
        return {"risk_score": 0, "verdict": "Error", "reasoning_bengali": f"AI Engine Error: {str(e)}"}

def full_scan(url):
    """Runs the complete phishing analysis pipeline."""
    url_features = extract_url_features(url)
    whois_features = get_whois_data(url_features["domain"])
    ai_analysis = analyze_with_ai(url_features, whois_features)
    
    return {
        "url_features": url_features,
        "whois_features": whois_features,
        "ai_analysis": ai_analysis
    }
