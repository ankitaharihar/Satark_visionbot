# -*- coding: utf-8 -*-
"""
Enhanced Telegram Phishing Detection Bot (Reliable Version)
Focuses on reliable security checks without external API dependencies
"""

import telegram
from telegram.ext import Application, CommandHandler, MessageHandler, filters
import requests
import re
import asyncio
import sys
import os
import ssl
import socket
import whois
from datetime import datetime, timedelta
from urllib.parse import urlparse
import json
import time
import dns.resolver

# Set UTF-8 encoding for Windows compatibility
if sys.platform.startswith('win'):
    os.environ['PYTHONIOENCODING'] = 'utf-8'

# --- 1. CONFIGURATION ---
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get token from environment variable (SECURE)
TELEGRAM_TOKEN = os.getenv('TELEGRAM_TOKEN')

if not TELEGRAM_TOKEN:
    print("ERROR: TELEGRAM_TOKEN not found in environment variables!")
    print("Please create a .env file with your bot token.")
    exit(1)

# Risk scoring thresholds
RISK_THRESHOLDS = {
    'SAFE': 0,
    'LOW_RISK': 25,
    'MEDIUM_RISK': 50,
    'HIGH_RISK': 75,
    'CRITICAL': 100
}

# --- 2. ENHANCED SECURITY SCANNING FUNCTIONS ---

def extract_domain_from_url(url):
    """Extract domain from URL"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        # Remove www. prefix for consistency
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain
    except:
        return None

def check_ssl_certificate(domain):
    """Enhanced SSL certificate check"""
    ssl_info = {
        'has_ssl': False,
        'valid': False,
        'issuer': 'Unknown',
        'expires': None,
        'days_until_expiry': 0,
        'self_signed': False,
        'risk_score': 0
    }
    
    try:
        context = ssl.create_default_context()
        
        with socket.create_connection((domain, 443), timeout=15) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                ssl_info['has_ssl'] = True
                
                # Parse issuer
                issuer = cert.get('issuer', ())
                for item in issuer:
                    if isinstance(item, tuple) and len(item) >= 2:
                        if item[0] == 'organizationName':
                            ssl_info['issuer'] = item[1]
                            break
                
                # Check if self-signed
                subject = cert.get('subject', ())
                subject_cn = None
                for item in subject:
                    if isinstance(item, tuple) and len(item) >= 2:
                        if item[0] == 'commonName':
                            subject_cn = item[1]
                            break
                
                if ssl_info['issuer'] == subject_cn:
                    ssl_info['self_signed'] = True
                
                # Parse expiry date
                expiry_str = cert.get('notAfter')
                if expiry_str:
                    expiry_date = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                    ssl_info['expires'] = expiry_date
                    days_left = (expiry_date - datetime.now()).days
                    ssl_info['days_until_expiry'] = days_left
                    
                    # Risk scoring
                    if ssl_info['self_signed']:
                        ssl_info['risk_score'] = 40
                    elif days_left < 0:
                        ssl_info['risk_score'] = 60  # Expired
                    elif days_left < 30:
                        ssl_info['risk_score'] = 20  # Expiring soon
                    elif 'Let\'s Encrypt' in ssl_info['issuer']:
                        ssl_info['risk_score'] = 5   # Free SSL
                    else:
                        ssl_info['risk_score'] = 0
                        ssl_info['valid'] = True
                        
    except Exception as e:
        ssl_info['risk_score'] = 35  # No SSL
        print(f"SSL check failed for {domain}: {e}")
    
    return ssl_info

def check_whois_info(domain):
    """Enhanced WHOIS information check"""
    whois_info = {
        'creation_date': None,
        'expiration_date': None,
        'registrar': 'Unknown',
        'country': 'Unknown',
        'age_days': 0,
        'privacy_protected': False,
        'risk_score': 0
    }
    
    try:
        w = whois.whois(domain)
        
        # Handle creation date
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0] if creation_date else None
        
        if creation_date:
            whois_info['creation_date'] = creation_date
            age_days = (datetime.now() - creation_date).days
            whois_info['age_days'] = age_days
            
            # Risk scoring based on age  
            if age_days < 7:
                whois_info['risk_score'] = 50  # Very new
            elif age_days < 30:
                whois_info['risk_score'] = 35  # New domain
            elif age_days < 90:
                whois_info['risk_score'] = 20  # Young domain
            elif age_days < 365:
                whois_info['risk_score'] = 10  # Still young
            else:
                whois_info['risk_score'] = 0   # Established
        
        # Handle expiration date
        expiration_date = w.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0] if expiration_date else None
        whois_info['expiration_date'] = expiration_date
        
        # Get registrar and check for privacy
        registrar = str(w.registrar) if w.registrar else 'Unknown'
        whois_info['registrar'] = registrar
        
        privacy_keywords = ['privacy', 'protection', 'proxy', 'whoisguard', 'private']
        if any(keyword in registrar.lower() for keyword in privacy_keywords):
            whois_info['privacy_protected'] = True
            whois_info['risk_score'] += 15
        
        # Get country
        whois_info['country'] = str(w.country) if w.country else 'Unknown'
        
    except Exception as e:
        whois_info['risk_score'] = 20
        print(f"WHOIS check failed for {domain}: {e}")
    
    return whois_info

def check_dns_records(domain):
    """Check DNS records for security indicators"""
    dns_info = {
        'has_mx': False,
        'has_spf': False,
        'has_dmarc': False,
        'has_caa': False,
        'mx_count': 0,
        'risk_score': 0
    }
    
    try:
        # Check MX records
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            dns_info['has_mx'] = True
            dns_info['mx_count'] = len(mx_records)
        except:
            dns_info['risk_score'] += 10  # No email setup
        
        # Check SPF records
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            for record in txt_records:
                record_str = str(record).lower()
                if 'v=spf1' in record_str:
                    dns_info['has_spf'] = True
                    break
        except:
            dns_info['risk_score'] += 5
        
        # Check DMARC
        try:
            dmarc_records = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            dns_info['has_dmarc'] = len(dmarc_records) > 0
        except:
            dns_info['risk_score'] += 5
        
        # Check CAA records
        try:
            caa_records = dns.resolver.resolve(domain, 'CAA')
            dns_info['has_caa'] = len(caa_records) > 0
        except:
            dns_info['risk_score'] += 3
            
    except Exception as e:
        dns_info['risk_score'] = 15
        print(f"DNS check failed for {domain}: {e}")
    
    return dns_info

def check_url_structure(url):
    """Analyze URL structure for suspicious patterns"""
    structure_info = {
        'suspicious_tld': False,
        'long_subdomain': False,
        'suspicious_path': False,
        'ip_address': False,
        'url_shortener': False,
        'homograph_attack': False,
        'risk_score': 0
    }
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.biz', '.info', '.click', 
                          '.download', '.zip', '.loan', '.win', '.bid']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            structure_info['suspicious_tld'] = True
            structure_info['risk_score'] += 25
        
        # Check for long subdomains (potential typosquatting)
        if domain.count('.') > 3:
            structure_info['long_subdomain'] = True
            structure_info['risk_score'] += 15
        
        # Check for suspicious path patterns
        suspicious_paths = ['login', 'signin', 'verify', 'update', 'secure', 
                           'account', 'suspended', 'limited', 'confirm']
        if any(pattern in path for pattern in suspicious_paths):
            structure_info['suspicious_path'] = True
            structure_info['risk_score'] += 10
        
        # Check if using IP address instead of domain
        import ipaddress
        try:
            ipaddress.ip_address(domain.split(':')[0])
            structure_info['ip_address'] = True
            structure_info['risk_score'] += 30
        except:
            pass
        
        # Check for URL shorteners
        shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 
                     'short.link', 'tiny.cc', 'is.gd', 'buff.ly']
        if any(shortener in domain for shortener in shorteners):
            structure_info['url_shortener'] = True
            structure_info['risk_score'] += 20
        
        # Basic homograph attack detection (mixed scripts)
        if any(ord(char) > 127 for char in domain):
            structure_info['homograph_attack'] = True
            structure_info['risk_score'] += 35
            
    except Exception as e:
        structure_info['risk_score'] = 10
        print(f"URL structure check failed: {e}")
    
    return structure_info

def check_brand_impersonation(url):
    """Check for brand impersonation attempts"""
    brand_info = {
        'impersonated_brands': [],
        'suspicious_keywords': [],
        'risk_score': 0
    }
    
    # Popular brands often impersonated
    brands = [
        'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
        'instagram', 'twitter', 'netflix', 'spotify', 'ebay', 'alibaba',
        'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'hsbc',
        'visa', 'mastercard', 'americanexpress', 'discover'
    ]
    
    # Suspicious keywords
    suspicious_words = [
        'secure', 'verify', 'update', 'confirm', 'suspended', 'limited',
        'restore', 'urgent', 'immediate', 'expire', 'temporary', 'activate',
        'validate', 'alert', 'warning', 'notice', 'action', 'required'
    ]
    
    url_lower = url.lower()
    domain = extract_domain_from_url(url)
    
    # Check for brand impersonation
    for brand in brands:
        if brand in url_lower and brand not in domain:
            brand_info['impersonated_brands'].append(brand)
    
    # Check for suspicious keywords  
    for word in suspicious_words:
        if word in url_lower:
            brand_info['suspicious_keywords'].append(word)
    
    # Calculate risk score
    brand_info['risk_score'] = (len(brand_info['impersonated_brands']) * 20) + \
                              (len(brand_info['suspicious_keywords']) * 3)
    
    return brand_info

def calculate_overall_risk(ssl_info, whois_info, dns_info, structure_info, brand_info):
    """Calculate comprehensive risk score"""
    total_score = (
        ssl_info['risk_score'] +
        whois_info['risk_score'] +
        dns_info['risk_score'] +
        structure_info['risk_score'] +
        brand_info['risk_score']
    )
    
    # Cap at 100
    total_score = min(total_score, 100)
    
    # Determine risk level
    if total_score >= RISK_THRESHOLDS['CRITICAL']:
        risk_level = 'CRITICAL'
    elif total_score >= RISK_THRESHOLDS['HIGH_RISK']:
        risk_level = 'HIGH_RISK'
    elif total_score >= RISK_THRESHOLDS['MEDIUM_RISK']:
        risk_level = 'MEDIUM_RISK'
    elif total_score >= RISK_THRESHOLDS['LOW_RISK']:
        risk_level = 'LOW_RISK'
    else:
        risk_level = 'SAFE'
    
    return total_score, risk_level

def enhanced_phishing_check(url):
    """Comprehensive phishing analysis with reliable checks"""
    print(f"Analyzing: {url}")
    
    domain = extract_domain_from_url(url)
    if not domain:
        return {
            'url': url,
            'risk_level': 'HIGH_RISK',
            'risk_score': 80,
            'error': 'Invalid URL format'
        }
    
    # Perform all security checks
    ssl_info = check_ssl_certificate(domain)
    whois_info = check_whois_info(domain)
    dns_info = check_dns_records(domain)
    structure_info = check_url_structure(url)
    brand_info = check_brand_impersonation(url)
    
    # Calculate overall risk
    risk_score, risk_level = calculate_overall_risk(
        ssl_info, whois_info, dns_info, structure_info, brand_info
    )
    
    return {
        'url': url,
        'domain': domain,
        'risk_score': risk_score,
        'risk_level': risk_level,
        'ssl_info': ssl_info,
        'whois_info': whois_info,
        'dns_info': dns_info,
        'structure_info': structure_info,
        'brand_info': brand_info
    }

def format_enhanced_report(analysis):
    """Format comprehensive analysis report"""
    if 'error' in analysis:
        return f"[ERROR] {analysis['error']}"
    
    risk_level = analysis['risk_level']
    risk_score = analysis['risk_score']
    domain = analysis['domain']
    
    # Risk level indicators
    risk_icons = {
        'SAFE': '[SAFE]',
        'LOW_RISK': '[LOW RISK]',
        'MEDIUM_RISK': '[MEDIUM RISK]',
        'HIGH_RISK': '[HIGH RISK]',
        'CRITICAL': '[CRITICAL THREAT]'
    }
    
    report = f"{risk_icons[risk_level]} **{risk_level}**\n"
    report += f"**Risk Score: {risk_score}/100**\n\n"
    report += f"URL: `{analysis['url']}`\n"
    report += f"Domain: `{domain}`\n\n"
    
    # SSL Analysis
    ssl = analysis['ssl_info']
    report += "**SSL Certificate Analysis:**\n"
    if ssl['has_ssl']:
        status = "Valid" if ssl['valid'] else "Present but Issues"
        report += f"- Status: {status}\n"
        report += f"- Issuer: {ssl['issuer']}\n"
        if ssl['self_signed']:
            report += "- WARNING: Self-signed certificate\n"
        if ssl['expires']:
            report += f"- Expires: {ssl['expires'].strftime('%Y-%m-%d')}\n"
    else:
        report += "- Status: No SSL Certificate (HIGH RISK)\n"
    
    # Domain Analysis
    whois = analysis['whois_info']
    report += "\n**Domain Analysis:**\n"
    if whois['creation_date']:
        age_years = whois['age_days'] // 365
        report += f"- Age: {whois['age_days']} days ({age_years} years)\n"
        report += f"- Created: {whois['creation_date'].strftime('%Y-%m-%d')}\n"
    report += f"- Registrar: {whois['registrar']}\n"
    if whois['privacy_protected']:
        report += "- Privacy Protected: Yes (slightly suspicious)\n"
    
    # DNS Security
    dns = analysis['dns_info']
    report += "\n**DNS Security:**\n"
    report += f"- Mail Records (MX): {'Present' if dns['has_mx'] else 'Missing'}\n"
    report += f"- SPF Record: {'Present' if dns['has_spf'] else 'Missing'}\n"
    report += f"- DMARC: {'Present' if dns['has_dmarc'] else 'Missing'}\n"
    
    # URL Structure Analysis
    structure = analysis['structure_info']
    if structure['risk_score'] > 0:
        report += "\n**URL Structure Issues:**\n"
        if structure['suspicious_tld']:
            report += "- Suspicious TLD detected\n"
        if structure['long_subdomain']:
            report += "- Complex subdomain structure\n"
        if structure['ip_address']:
            report += "- Uses IP address instead of domain\n"
        if structure['url_shortener']:
            report += "- URL shortener detected\n"
        if structure['homograph_attack']:
            report += "- Potential homograph attack\n"
    
    # Brand Impersonation
    brand = analysis['brand_info']
    if brand['impersonated_brands']:
        report += "\n**Brand Impersonation Detected:**\n"
        report += f"- Brands: {', '.join(brand['impersonated_brands'])}\n"
    
    if brand['suspicious_keywords']:
        report += f"\n**Suspicious Keywords:** {len(brand['suspicious_keywords'])} found\n"
    
    # Final Recommendation
    report += "\n**RECOMMENDATION:**\n"
    if risk_level == 'CRITICAL':
        report += "🚨 EXTREME DANGER - DO NOT CLICK! Very high probability of phishing/malware."
    elif risk_level == 'HIGH_RISK':
        report += "⚠️ HIGH RISK - Avoid clicking. Multiple red flags detected."
    elif risk_level == 'MEDIUM_RISK':
        report += "⚡ MEDIUM RISK - Exercise extreme caution. Verify source independently."
    elif risk_level == 'LOW_RISK':
        report += "💡 LOW RISK - Some concerns detected. Proceed with caution."
    else:
        report += "✅ APPEARS SAFE - But always verify the source and be cautious."
    
    return report

# --- 3. TELEGRAM HANDLERS ---

async def start_command(update: telegram.Update, context: telegram.ext.ContextTypes.DEFAULT_TYPE):
    """Enhanced start command"""
    await update.message.reply_text(
        "🔒 **Enhanced Phishing Detection Bot** 🔒\n\n"
        "I perform comprehensive security analysis:\n\n"
        "🔐 **SSL Certificate Validation**\n"
        "📋 **WHOIS Domain Analysis**\n"
        "🌐 **DNS Security Records**\n"
        "🔍 **URL Structure Analysis**\n"
        "🎯 **Brand Impersonation Detection**\n"
        "📊 **Risk Scoring System**\n\n"
        "Send me any URL for detailed security analysis!"
    )

async def analyze_url_message(update: telegram.Update, context: telegram.ext.ContextTypes.DEFAULT_TYPE):
    """Enhanced URL analysis handler"""
    text = update.message.text
    urls = re.findall(r'(https?://[^\s]+)', text)
    
    if not urls:
        await update.message.reply_text(
            "Please send a valid URL starting with http:// or https://"
        )
        return
    
    await update.message.reply_text(
        "🔍 Performing comprehensive security analysis...\n"
        "This may take 15-30 seconds."
    )
    
    for url in urls:
        try:
            analysis = enhanced_phishing_check(url)
            report = format_enhanced_report(analysis)
            
            # Split long reports if needed
            if len(report) > 4000:
                parts = [report[i:i+4000] for i in range(0, len(report), 4000)]
                for part in parts:
                    await update.message.reply_text(part)
            else:
                await update.message.reply_text(report)
                
        except Exception as e:
            await update.message.reply_text(f"Analysis error for {url}: {str(e)}")

# --- 4. MAIN FUNCTION ---

async def error_handler(update: telegram.Update, context: telegram.ext.ContextTypes.DEFAULT_TYPE):
    """Handle errors that occur during bot operation"""
    import logging
    
    # Log the error
    logging.error(f"Exception while handling update: {context.error}")
    
    # Send a message to the user if possible
    if update and update.effective_message:
        try:
            await update.effective_message.reply_text(
                "🔧 Sorry, I encountered an error while processing your request. "
                "Please try again in a moment."
            )
        except Exception:
            pass  # If we can't send a message, just log it

def main():
    """Run the enhanced phishing detection bot"""
    import logging
    
    # Set up logging
    logging.basicConfig(
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        level=logging.INFO
    )
    logger = logging.getLogger(__name__)
    
    print("🚀 Starting Enhanced Phishing Detection Bot...")
    
    try:
        application = Application.builder().token(TELEGRAM_TOKEN).build()
        
        # Add handlers
        application.add_handler(CommandHandler("start", start_command))
        application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, analyze_url_message))
        
        # Add error handler
        application.add_error_handler(error_handler)
        
        print("✅ Enhanced bot running with comprehensive security analysis...")
        print(f"🔗 Bot token configured: {TELEGRAM_TOKEN[:10]}...")
        print("📱 Your bot is ready! Start a conversation on Telegram.")
        print("⏹️  Press Ctrl+C to stop the bot")
        
        # Start polling with error handling
        application.run_polling(
            poll_interval=3,
            timeout=10,
            bootstrap_retries=3
        )
        
    except Exception as e:
        logger.error(f"Failed to start bot: {e}")
        print(f"❌ Error starting bot: {e}")
        print("💡 Make sure your token is valid and no other bot instance is running")

if __name__ == '__main__':
    main()