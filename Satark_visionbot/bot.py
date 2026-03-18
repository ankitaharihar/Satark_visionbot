# -*- coding: utf-8 -*-
"""
Telegram Phishing Detection Bot
Explainable, fast, rule-based detection with enhancements
"""
import os
import re
import sys
import telegram
from telegram.ext import Application, CommandHandler, MessageHandler, filters
from dotenv import load_dotenv
from ai_model.phishing_detector import classify_url
from bot_enhancements import (
    setup_logging,
    check_url_redirects,
    check_malicious_patterns,
    check_blacklists,
    save_analysis_log,
    RateLimiter,
    help_command,
    stats_command,
    about_command
)

# ------------------ ENV SETUP ------------------
load_dotenv()
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
if not TELEGRAM_TOKEN:
    print("❌ TELEGRAM_TOKEN not found in environment variables")
    sys.exit(1)

# ------------------ SETUP ------------------
logger = setup_logging()
rate_limiter = RateLimiter(max_requests=10, time_window=60)

# ------------------ HANDLERS ------------------
async def start_command(update: telegram.Update, context):
    await update.message.reply_text(
        "🔒 *Phishing Detection Bot*\n\n"
        "I analyze URLs and tell you:\n"
        "• Whether it is phishing or safe\n"
        "• Risk score (0–100)\n"
        "• SSL, Domain, DNS analysis\n"
        "• Clear reasons for the decision\n\n"
        "📩 Send any URL to begin.\n\n"
        "Use /help for more commands.",
        parse_mode="Markdown"
    )

async def analyze_url_message(update: telegram.Update, context):
    user_id = update.effective_user.id
    text = update.message.text

    if not rate_limiter.is_allowed(user_id):
        await update.message.reply_text(
            "⚠️ Rate limit exceeded. Please wait a minute before sending more URLs."
        )
        return

    urls = re.findall(r'(https?://[^\s]+)', text)
    if not urls:
        await update.message.reply_text(
            "❌ Please send a valid URL starting with http:// or https://"
        )
        return

    for url in urls:
        try:
            await update.message.reply_text("🔍 Analyzing URL... This may take 15-30 seconds.")

            result = classify_url(url)
            redirect_info = check_url_redirects(url)
            pattern_info = check_malicious_patterns(url)

            domain_match = re.search(r'https?://([^/]+)', url)
            domain = domain_match.group(1) if domain_match else url
            blacklist_info = check_blacklists(domain)

            total_risk = result['risk_score']
            total_risk += redirect_info.get('risk_score', 0)
            total_risk += min(pattern_info.get('risk_score', 0), 20)
            total_risk += blacklist_info.get('risk_score', 0)
            total_risk = min(total_risk, 100)

            if total_risk >= 70 or blacklist_info['is_blacklisted']:
                verdict = "🚨 PHISHING"
                risk_level = "CRITICAL" if total_risk >= 85 else "HIGH_RISK"
            elif total_risk >= 40:
                verdict = "⚠️ SUSPICIOUS"
                risk_level = "MEDIUM_RISK"
            else:
                verdict = "✅ SAFE"
                risk_level = "SAFE" if total_risk < 20 else "LOW_RISK"

            reply = f"{verdict}\n"
            reply += f"📊 *Risk Score: {total_risk}/100*\n\n"
            reply += f"🔗 URL: `{url}`\n"
            reply += f"🌐 Domain: `{domain}`\n\n"

            if result["reasons"]:
                reply += "*🔍 Detection Reasons:*\n"
                for r in result["reasons"]:
                    reply += f"• {r}\n"
                reply += "\n"

            if redirect_info['redirect_count'] > 0:
                reply += f"*🔄 Redirects:* {redirect_info['redirect_count']} redirect(s) detected\n"
                if redirect_info['suspicious_redirects']:
                    reply += "• ⚠️ Suspicious redirect chain detected\n"
                reply += "\n"

            if pattern_info['phishing_keywords']:
                reply += "*🎯 Phishing Keywords Found:*\n"
                for kw in pattern_info['phishing_keywords'][:5]:
                    reply += f"• `{kw}`\n"
                reply += "\n"

            if blacklist_info['is_blacklisted']:
                reply += "*🚫 BLACKLISTED DOMAIN DETECTED*\n\n"

            if risk_level in ["CRITICAL", "HIGH_RISK"]:
                reply += "🚫 *RECOMMENDATION: DO NOT visit this URL!*"
            elif risk_level == "MEDIUM_RISK":
                reply += "⚠️ *RECOMMENDATION: Proceed with caution. Verify the source.*"
            else:
                reply += "✅ *RECOMMENDATION: APPEARS SAFE - But always verify the source.*"

            await update.message.reply_text(reply, parse_mode="Markdown")
            save_analysis_log(url, {'risk_score': total_risk, 'risk_level': risk_level}, user_id)
            logger.info(f"Analyzed URL: {url} | Risk: {total_risk} | Level: {risk_level}")

        except Exception as e:
            logger.error(f"Error analyzing {url}: {e}")
            await update.message.reply_text(f"❌ Error analyzing URL:\n{str(e)}")

# ------------------ ERROR HANDLER ------------------
async def error_handler(update, context):
    logger.error(f"Error: {context.error}")
    if update and update.effective_message:
        await update.effective_message.reply_text(
            "⚠️ Something went wrong. Please try again."
        )

# ------------------ MAIN ------------------
def main():
    print("🚀 Starting Phishing Detection Bot...")
    application = Application.builder().token(TELEGRAM_TOKEN).build()

    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("stats", stats_command))
    application.add_handler(CommandHandler("about", about_command))
    application.add_handler(
        MessageHandler(filters.TEXT & ~filters.COMMAND, analyze_url_message)
    )
    application.add_error_handler(error_handler)
    print("✅ Bot is running")
    application.run_polling()

if __name__ == "__main__":
    main()