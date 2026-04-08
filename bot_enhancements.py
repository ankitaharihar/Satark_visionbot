# Enhanced Features for Telegram Phishing Detection Bot

import base64
import json
import logging
import os
import sqlite3
from datetime import datetime
from typing import Dict

import requests
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
THREAT_DB_PATH = os.getenv("THREAT_DB_PATH", "analysis_logs.db")

# Additional Enhancement Functions

def setup_logging():
    """Set up logging for bot activities"""
    logging.basicConfig(
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        level=logging.INFO,
        handlers=[
            logging.FileHandler('phishing_bot.log'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

def check_url_redirects(url: str, max_redirects: int = 5) -> Dict:
    """Check for suspicious URL redirections"""
    import requests
    redirect_info = {
        'redirect_count': 0,
        'final_url': url,
        'suspicious_redirects': False,
        'redirect_chain': [],
        'risk_score': 0
    }
    
    try:
        response = requests.head(url, allow_redirects=True, timeout=10)
        
        # Check redirect history
        if hasattr(response, 'history') and response.history:
            redirect_info['redirect_count'] = len(response.history)
            redirect_info['final_url'] = response.url
            
            # Build redirect chain
            for resp in response.history:
                redirect_info['redirect_chain'].append(resp.url)
            redirect_info['redirect_chain'].append(response.url)
            
            # Risk scoring for redirects
            if redirect_info['redirect_count'] > 3:
                redirect_info['risk_score'] = 25
                redirect_info['suspicious_redirects'] = True
            elif redirect_info['redirect_count'] > 1:
                redirect_info['risk_score'] = 10
                
    except Exception as e:
        redirect_info['risk_score'] = 5
        redirect_info['error'] = str(e)
    
    return redirect_info

def check_malicious_patterns(url: str) -> Dict:
    """Advanced pattern matching for malicious URLs"""
    pattern_info = {
        'suspicious_patterns': [],
        'phishing_keywords': [],
        'risk_score': 0
    }
    
    # Advanced suspicious patterns
    suspicious_patterns = [
        r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses
        r'[a-zA-Z0-9]+-[a-zA-Z0-9]+-[a-zA-Z0-9]+\.',  # Multiple hyphens
        r'[a-zA-Z]{20,}',  # Very long strings
        r'[0-9]{10,}',  # Long numbers
        r'[a-zA-Z0-9]{50,}',  # Very long alphanumeric strings
    ]
    
    # Phishing keywords
    phishing_keywords = [
        'urgent', 'verify', 'suspended', 'limited', 'confirm', 'update',
        'secure', 'alert', 'warning', 'expire', 'click', 'now', 'immediate',
        'action', 'required', 'temporary', 'restore', 'validate', 'activate'
    ]
    
    url_lower = url.lower()
    
    # Check patterns
    import re
    for pattern in suspicious_patterns:
        if re.search(pattern, url):
            pattern_info['suspicious_patterns'].append(pattern)
            pattern_info['risk_score'] += 15
    
    # Check keywords
    for keyword in phishing_keywords:
        if keyword in url_lower:
            pattern_info['phishing_keywords'].append(keyword)
            pattern_info['risk_score'] += 5
    
    return pattern_info

def check_blacklists(domain: str) -> Dict:
    """Check domain against known blacklists (mock implementation)"""
    # In production, you would integrate with actual blacklist APIs
    blacklist_info = {
        'is_blacklisted': False,
        'blacklist_sources': [],
        'risk_score': 0
    }
    
    # Mock blacklist check (replace with real API calls)
    known_bad_domains = [
        'phishing-example.com',
        'fake-paypal.net',
        'malicious-site.org'
    ]
    
    if domain in known_bad_domains:
        blacklist_info['is_blacklisted'] = True
        blacklist_info['blacklist_sources'].append('Internal Blacklist')
        blacklist_info['risk_score'] = 100
    
    return blacklist_info


def check_threat_intel(url: str, domain: str) -> Dict:
    """Check URL/domain against external threat intelligence providers."""
    intel = {
        'is_malicious': False,
        'risk_score': 0,
        'sources': [],
        'details': []
    }

    # 1) Internal static blacklist fallback
    local_blacklist = check_blacklists(domain)
    if local_blacklist['is_blacklisted']:
        intel['is_malicious'] = True
        intel['risk_score'] += 60
        intel['sources'].extend(local_blacklist['blacklist_sources'])
        intel['details'].append('Matched internal blacklist')

    # 2) VirusTotal URL reputation (if key configured)
    if VT_API_KEY:
        try:
            encoded_url = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            vt_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
            vt_response = requests.get(
                vt_url,
                headers={"x-apikey": VT_API_KEY},
                timeout=12
            )
            if vt_response.status_code == 200:
                vt_json = vt_response.json()
                stats = vt_json.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                malicious = int(stats.get('malicious', 0) or 0)
                suspicious = int(stats.get('suspicious', 0) or 0)
                if malicious > 0 or suspicious > 0:
                    intel['is_malicious'] = True
                    intel['sources'].append('VirusTotal')
                    intel['details'].append(
                        f"VirusTotal detections: malicious={malicious}, suspicious={suspicious}"
                    )
                    intel['risk_score'] += min(50, malicious * 8 + suspicious * 5)
            elif vt_response.status_code in [401, 403]:
                intel['details'].append('VirusTotal auth failed (check VT_API_KEY)')
            elif vt_response.status_code == 404:
                intel['details'].append('VirusTotal has no prior record for this URL')
            else:
                intel['details'].append(f"VirusTotal API error: {vt_response.status_code}")
        except Exception as exc:
            intel['details'].append(f"VirusTotal lookup failed: {exc}")
    else:
        intel['details'].append('VT_API_KEY not set; skipped VirusTotal lookup')

    intel['risk_score'] = min(100, intel['risk_score'])
    return intel


def init_analysis_db(db_path: str = THREAT_DB_PATH):
    """Initialize SQLite database for analysis logs and user stats."""
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS url_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                user_id INTEGER,
                url TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                verdict TEXT NOT NULL,
                ai_label TEXT,
                ai_confidence REAL,
                llm_label TEXT,
                llm_confidence REAL,
                threat_sources TEXT,
                reasons TEXT
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def save_analysis_log_sqlite(url: str, analysis: Dict, user_id: int, db_path: str = THREAT_DB_PATH):
    """Persist URL analysis in SQLite for /stats command and audit trail."""
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO url_analysis (
                timestamp,
                user_id,
                url,
                risk_score,
                verdict,
                ai_label,
                ai_confidence,
                llm_label,
                llm_confidence,
                threat_sources,
                reasons
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now().isoformat(),
                user_id,
                url,
                int(analysis.get('risk_score', 0)),
                analysis.get('verdict', 'UNKNOWN'),
                analysis.get('ai_label'),
                analysis.get('ai_confidence'),
                analysis.get('llm_label'),
                analysis.get('llm_confidence'),
                ", ".join(analysis.get('threat_sources', [])),
                json.dumps(analysis.get('reasons', [])),
            )
        )
        conn.commit()
    finally:
        conn.close()


def get_user_stats(user_id: int, db_path: str = THREAT_DB_PATH) -> Dict:
    """Fetch usage statistics for a Telegram user from SQLite logs."""
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()

        cur.execute(
            "SELECT COUNT(*), MAX(timestamp), AVG(risk_score) FROM url_analysis WHERE user_id = ?",
            (user_id,)
        )
        total_count, last_ts, avg_risk = cur.fetchone()

        cur.execute(
            """
            SELECT verdict, COUNT(*) as c
            FROM url_analysis
            WHERE user_id = ?
            GROUP BY verdict
            ORDER BY c DESC
            LIMIT 1
            """,
            (user_id,)
        )
        top_row = cur.fetchone()
        common_verdict = top_row[0] if top_row else "N/A"

        return {
            'total_urls': int(total_count or 0),
            'last_analysis': last_ts or 'N/A',
            'average_risk': round(float(avg_risk or 0), 1),
            'most_common_verdict': common_verdict,
        }
    finally:
        conn.close()

def generate_safety_report(analysis: Dict) -> str:
    """Generate a detailed safety report with recommendations"""
    risk_level = analysis.get('risk_level', 'UNKNOWN')
    risk_score = analysis.get('risk_score', 0)
    
    report = f"🔒 **SECURITY ANALYSIS REPORT**\n\n"
    
    # Risk level with emoji
    risk_emojis = {
        'SAFE': '✅',
        'LOW_RISK': '⚠️',
        'MEDIUM_RISK': '🔶',
        'HIGH_RISK': '🔴',
        'CRITICAL': '🚨'
    }
    
    emoji = risk_emojis.get(risk_level, '❓')
    report += f"{emoji} **Risk Level: {risk_level}**\n"
    report += f"📊 **Risk Score: {risk_score}/100**\n\n"
    
    # Detailed recommendations based on risk level
    if risk_level == 'CRITICAL':
        report += "🚨 **IMMEDIATE ACTION REQUIRED:**\n"
        report += "• DO NOT click this link\n"
        report += "• Report as phishing to your email provider\n"
        report += "• Warn others about this URL\n"
    elif risk_level == 'HIGH_RISK':
        report += "⚠️ **HIGH CAUTION ADVISED:**\n"
        report += "• Avoid clicking this link\n"
        report += "• Verify the source independently\n"
        report += "• Use official websites instead\n"
    elif risk_level == 'MEDIUM_RISK':
        report += "🔶 **PROCEED WITH CAUTION:**\n"
        report += "• Double-check the URL spelling\n"
        report += "• Verify with the official source\n"
        report += "• Consider using official apps instead\n"
    elif risk_level == 'LOW_RISK':
        report += "💡 **MINOR CONCERNS DETECTED:**\n"
        report += "• URL appears mostly safe\n"
        report += "• Still verify the source if sensitive\n"
        report += "• Be cautious with personal information\n"
    else:
        report += "✅ **APPEARS SAFE:**\n"
        report += "• URL passed security checks\n"
        report += "• Still practice general web safety\n"
        report += "• Verify for sensitive transactions\n"
    
    return report

def save_analysis_log(url: str, analysis: Dict, user_id: int = None):
    """Save analysis results for monitoring and improvement"""
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'url': url,
        'user_id': user_id,
        'risk_score': analysis.get('risk_score', 0),
        'risk_level': analysis.get('risk_level', 'UNKNOWN'),
        'analysis_summary': {
            'ssl_score': analysis.get('ssl_info', {}).get('risk_score', 0),
            'whois_score': analysis.get('whois_info', {}).get('risk_score', 0),
            'dns_score': analysis.get('dns_info', {}).get('risk_score', 0),
            'structure_score': analysis.get('structure_info', {}).get('risk_score', 0),
            'brand_score': analysis.get('brand_info', {}).get('risk_score', 0)
        }
    }
    
    try:
        with open('analysis_logs.json', 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    except Exception as e:
        print(f"Failed to save log: {e}")

# Rate limiting for bot usage
class RateLimiter:
    def __init__(self, max_requests: int = 10, time_window: int = 60):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = {}
    
    def is_allowed(self, user_id: int) -> bool:
        """Check if user is within rate limits"""
        now = datetime.now()
        
        if user_id not in self.requests:
            self.requests[user_id] = []
        
        # Remove old requests outside time window
        self.requests[user_id] = [
            req_time for req_time in self.requests[user_id]
            if (now - req_time).seconds < self.time_window
        ]
        
        # Check if under limit
        if len(self.requests[user_id]) < self.max_requests:
            self.requests[user_id].append(now)
            return True
        
        return False

# Additional bot commands
async def help_command(update, context):
    """Enhanced help command"""
    help_text = """
🔒 **Phishing Detection Bot Help**

**Commands:**
/start - Initialize the bot
/help - Show this help message
/stats - Show your usage statistics
/about - About this bot

**How to use:**
1. Send any URL to get security analysis
2. Bot will analyze SSL, domain, DNS, and structure
3. You'll receive a detailed security report

**Features:**
🔐 SSL Certificate Validation
📋 Domain Age & Registration Analysis  
🌐 DNS Security Record Checks
🔍 URL Structure Analysis
🎯 Brand Impersonation Detection
📊 Risk Scoring (0-100)

**Security Tips:**
• Always verify URLs before clicking
• Look for https:// and valid certificates
• Be suspicious of urgent/threatening messages
• When in doubt, visit official websites directly

For support: Contact @yourusername
    """
    await update.message.reply_text(help_text)

async def stats_command(update, context):
    """Show user statistics"""
    user_id = update.effective_user.id
    stats = get_user_stats(user_id)

    stats_text = f"""
📊 **Your Statistics**

User ID: `{user_id}`
URLs Analyzed: {stats['total_urls']}
Last Analysis: {stats['last_analysis']}
Average Risk Score: {stats['average_risk']}
Most Common Verdict: {stats['most_common_verdict']}
    """
    await update.message.reply_text(stats_text)

async def about_command(update, context):
    """About the bot"""
    about_text = """
🤖 **Satark Vision Bot v2.0**

**Purpose:** Protect users from phishing attacks and malicious URLs

**Technology Stack:**
• Python 3.x
• python-telegram-bot library
• DNS resolution and SSL analysis
• WHOIS domain lookup
• Advanced pattern matching

**Security Features:**
✅ Real-time URL analysis
✅ Multi-factor risk assessment
✅ Brand impersonation detection
✅ SSL certificate validation
✅ Domain reputation checking

**Privacy:** 
• URLs are analyzed in real-time
• No permanent storage of personal data
• Analysis logs may be kept for improvement

**Disclaimer:**
This bot provides security analysis but cannot guarantee 100% accuracy. Always use your judgment and verify sources independently.

**Version:** Enhanced v2.0
**Last Updated:** September 2025
    """
    await update.message.reply_text(about_text)