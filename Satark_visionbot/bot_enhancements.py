# Enhanced Features for Telegram Phishing Detection Bot

import hashlib
import base64
from datetime import datetime
import json
import logging
from typing import Dict, List, Optional

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
    # In production, you'd query a database
    stats_text = f"""
📊 **Your Statistics**

User ID: `{user_id}`
URLs Analyzed: N/A (Feature coming soon)
Last Analysis: N/A
Most Common Risk Level: N/A

This feature will be enhanced in future updates!
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