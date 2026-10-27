from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
import re
import math
from urllib.parse import urlparse
import os
import sqlite3
from datetime import datetime
import requests
import base64

# ==========================================
# PASTE YOUR VIRUSTOTAL API KEY HERE
# ==========================================
VT_API_KEY = "YOUR_API_KEY_HERE"

def init_db():
    conn = sqlite3.connect('scans.db', check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            risk_score INTEGER,
            verdict TEXT,
            timestamp TEXT
        )
    ''')
    conn.commit()
    return conn

db_conn = init_db()
app = FastAPI(title="Actual Threat Intelligence Analyzer")

class URLRequest(BaseModel):
    url: str

class AnalysisResponse(BaseModel):
    url: str
    risk_score: int
    is_phishing: bool
    flags: list[str]
    simulation_logs: list[str]

def calculate_entropy(text: str) -> float:
    if not text: return 0
    entropy = 0
    for x in set(text):
        p_x = float(text.count(x)) / len(text)
        entropy += - p_x * math.log2(p_x)
    return entropy

def check_virustotal(url: str, logs: list):
    """Queries the VirusTotal v3 API for real-world threat data."""
    if VT_API_KEY == "YOUR_API_KEY_HERE" or not VT_API_KEY:
        logs.append("[!] VIRUSTOTAL SKIPPED: You didn't put your API key in the code, genius.")
        return None

    logs.append("[SYSTEM] Initiating encrypted tunnel to VirusTotal API...")
    
    # VT requires URLs to be base64 encoded without padding
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
    
    try:
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
        if response.status_code == 200:
            logs.append("[+] VT Connection Established. Parsing vendor consensus...")
            return response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        elif response.status_code == 404:
            logs.append("[-] VT target not found in database. Relying purely on local heuristics.")
            return None
        elif response.status_code == 401:
            logs.append("[!] VT ERROR: Unauthorized. Your API key is invalid.")
            return None
        else:
            logs.append(f"[!] VT ERROR: Unexpected status code {response.status_code}.")
            return None
    except Exception as e:
        logs.append(f"[!] VT CONNECTION FAILED: {str(e)}")
        return None

@app.get("/")
def serve_frontend():
    if not os.path.exists("index.html"):
        raise HTTPException(status_code=404, detail="index.html missing.")
    return FileResponse("index.html")

@app.get("/api/history")
def get_history():
    cursor = db_conn.cursor()
    cursor.execute("SELECT url, risk_score, verdict, timestamp FROM history ORDER BY id DESC LIMIT 10")
    rows = cursor.fetchall()
    return [{"url": r[0], "score": r[1], "verdict": r[2], "time": r[3]} for r in rows]

@app.post("/api/analyze", response_model=AnalysisResponse)
def analyze_url(req: URLRequest):
    raw_url = req.url.strip()
    flags = []
    logs = [f"[SYSTEM] Target locked: {raw_url}"]
    risk_score = 0

    if not raw_url.startswith(('http://', 'https://')):
        url_to_parse = 'http://' + raw_url
    else:
        url_to_parse = raw_url

    try:
        domain = urlparse(url_to_parse).netloc.lower()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid URL structure.")

    # --- 1. VIRUSTOTAL INTELLIGENCE (THE HEAVY HITTER) ---
    vt_stats = check_virustotal(raw_url, logs)
    if vt_stats:
        malicious = vt_stats.get("malicious", 0)
        suspicious = vt_stats.get("suspicious", 0)
        
        logs.append(f"[VT] Intel returned: {malicious} malicious flags, {suspicious} suspicious flags.")
        
        if malicious > 0:
            flags.append(f"CRITICAL: {malicious} security vendors flagged this as MALICIOUS on VirusTotal.")
            risk_score += (malicious * 30) # Massive penalty for actual known threats
        if suspicious > 0:
            flags.append(f"WARNING: {suspicious} security vendors flagged this as SUSPICIOUS.")
            risk_score += (suspicious * 15)

    # --- 2. LOCAL HEURISTICS (FALLBACK) ---
    logs.append("[*] Running local heuristic checks...")
    
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$", domain):
        flags.append("Raw IP address used instead of domain")
        risk_score += 30

    if calculate_entropy(domain.split('.')[0]) > 3.8:
        flags.append("High domain entropy (Randomly generated)")
        risk_score += 20

    if raw_url.startswith("http://"):
        flags.append("Unencrypted HTTP protocol")
        risk_score += 10

    # Normalization
    risk_score = min(risk_score, 100)
    is_phishing = risk_score >= 50
    verdict = "CRITICAL THREAT" if is_phishing else ("SUSPICIOUS" if risk_score > 20 else "CLEAN")

    if risk_score == 0:
        flags.append("No local heuristics or remote API threats detected.")

    logs.append(f"[SYSTEM] Analysis complete. Final Computed Risk: {risk_score}/100")

    # Save to SQLite
    cursor = db_conn.cursor()
    cursor.execute("INSERT INTO history (url, risk_score, verdict, timestamp) VALUES (?, ?, ?, ?)",
                   (raw_url, risk_score, verdict, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    db_conn.commit()

    return AnalysisResponse(
        url=raw_url,
        risk_score=risk_score,
        is_phishing=is_phishing,
        flags=flags,
        simulation_logs=logs
    )