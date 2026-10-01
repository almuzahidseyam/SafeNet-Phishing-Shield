import whois
import tldextract
import requests
from urllib.parse import urlparse
import datetime
import google.generativeai as genai
import json
import os
import socket
import ssl
import re
import concurrent.futures
from bs4 import BeautifulSoup
from dotenv import load_dotenv

load_dotenv()

# Securely load Gemini API Key
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

def unmask_url(url):
    """Premium Feature: Chases redirects to unmask shorteners (e.g., bit.ly)."""
    if not url.startswith("http"):
        url = "http://" + url
    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
        return response.url
    except:
        return url

def get_ssl_details(hostname):
    """Premium Feature: Deep SSL Certificate Inspection."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get('issuer', []))
                return {"issuer": issuer.get('organizationName', issuer.get('commonName', 'Unknown')), "valid": True}
    except Exception as e:
        return {"issuer": "Invalid/No SSL", "valid": False}

def scrape_page_context(url):
    """Premium Feature: Scrapes DOM to see what the page is actually claiming to be."""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }
        res = requests.get(url, headers=headers, timeout=5)
        soup = BeautifulSoup(res.text, 'html.parser')
        title = soup.title.string if soup.title else "No Title"
        meta = soup.find('meta', attrs={'name': 'description'})
        desc = meta['content'] if meta else "No Description"
        return {"page_title": title.strip()[:100], "meta_description": desc.strip()[:150]}
    except:
        return {"page_title": "Offline or Blocked (403)", "meta_description": "N/A"}

def extract_url_features(original_url):
    """Extracts deterministic features from a URL."""
    final_url = unmask_url(original_url)
    parsed_url = urlparse(final_url)
    ext = tldextract.extract(final_url)
    
    domain = ext.domain + "." + ext.suffix
    
    try:
        # Premium Security Feature: Detect Homograph Attacks (Punycode) e.g., bкash.com -> xn--
        is_punycode = domain.encode('idna').decode('utf-8').startswith("xn--")
    except:
        is_punycode = False
    
    features = {
        "original_url": original_url,
        "final_url": final_url,
        "domain": domain,
        "subdomain": ext.subdomain,
        "is_https": parsed_url.scheme == "https",
        "url_length": len(final_url),
        "has_ip_in_domain": any(char.isdigit() for char in domain.replace(".", "")),
        "hyphens_in_domain": domain.count("-"),
        "is_punycode_homograph": is_punycode,
        "suspicious_words": check_suspicious_words(final_url)
    }
    return features

def check_suspicious_words(url):
    """Checks for common phishing keywords often used in BD."""
    keywords = ["free", "offer", "bkash", "daraz", "nagad", "lottery", "login", "update", "verify", "account", "gov", "bcs", "job"]
    found = [word for word in keywords if word in url.lower()]
    return found

def get_whois_data(domain):
    """Retrieves domain registration age and details with strict timeout."""
    def fetch_whois():
        return whois.whois(domain)
        
    try:
        # Premium Bug Fix: Prevent Streamlit Freezing by wrapping WHOIS in a ThreadPool with a strict 4-second timeout
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(fetch_whois)
            domain_info = future.result(timeout=4)
            
        creation_date = domain_info.creation_date
        
        if type(creation_date) == list:
            creation_date = creation_date[0]
            
        if creation_date:
            age_days = (datetime.datetime.now() - creation_date).days
            return {"domain_age_days": age_days, "registrar": domain_info.registrar, "error": None}
        return {"domain_age_days": "Unknown", "registrar": "Hidden", "error": None}
    except concurrent.futures.TimeoutError:
        return {"domain_age_days": "Unknown", "registrar": "Timeout (Server Hidden)", "error": "WHOIS Timeout"}
    except Exception as e:
        return {"domain_age_days": "Unknown", "registrar": "Unknown", "error": str(e)}

def analyze_with_ai(url_features, whois_features, ssl_details, dom_context):
    """Uses Gemini API to act as a Cyber Analyst and score the risk."""
    if not GEMINI_API_KEY:
        return {"score": 50, "verdict": "⚠️ AI Offline", "reasoning": "Gemini API Key missing in .env file."}
    
    prompt = f"""
    You are an elite Cybersecurity Threat Intelligence Analyst. 
    Analyze the following URL features, WHOIS data, SSL Cert, and Page Title to determine if this link is a phishing scam, especially targeting Bangladeshi users (e.g., fake bKash, Daraz, Gov jobs).
    
    URL Features (Redirect Chased): {json.dumps(url_features)}
    WHOIS Data: {json.dumps(whois_features)}
    SSL Details: {json.dumps(ssl_details)}
    Scraped DOM Context (What the page claims to be): {json.dumps(dom_context)}
    
    Provide your analysis in JSON format exactly like this:
    {{
        "risk_score": <int 0-100 where 100 is definitely phishing>,
        "verdict": "<Safe | Suspicious | High Risk Phishing>",
        "reasoning_bengali": "<Explain in clear, professional Bengali why this is safe or a scam. Mention redirect masking, domain age, lack of SSL, mismatch between URL and Page Title, etc.>"
    }}
    Do NOT include markdown formatting like ```json, just output the raw JSON object.
    """
    
    try:
        model = genai.GenerativeModel('gemini-1.5-flash')
        response = model.generate_content(prompt)
        text = response.text
        
        # Premium Bug Fix: Strict Regex Parsing to prevent JSONDecodeError if LLM hallucinates
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if match:
            analysis = json.loads(match.group(0))
        else:
            analysis = json.loads(text.replace('```json', '').replace('```', '').strip())
            
        return analysis
    except Exception as e:
        return {"risk_score": 0, "verdict": "Error", "reasoning_bengali": f"AI Parsing Error: {str(e)}"}

def full_scan(url):
    """Runs the complete phishing analysis pipeline."""
    url_features = extract_url_features(url)
    whois_features = get_whois_data(url_features["domain"])
    ssl_details = get_ssl_details(url_features["domain"])
    dom_context = scrape_page_context(url_features["final_url"])
    
    ai_analysis = analyze_with_ai(url_features, whois_features, ssl_details, dom_context)
    
    return {
        "url_features": url_features,
        "whois_features": whois_features,
        "ssl_details": ssl_details,
        "dom_context": dom_context,
        "ai_analysis": ai_analysis
    }
