# -*- coding: utf-8 -*-
"""
Telegram Phishing Detection Bot
Explainable, fast, rule-based detection
"""

import os
import re
import sys
import telegram
from telegram.ext import Application, CommandHandler, MessageHandler, filters
from dotenv import load_dotenv
from urllib.parse import urlparse

from ai_model.phishing_detector import classify_url
from bot_enhancements import (
    check_threat_intel,
    init_analysis_db,
    save_analysis_log_sqlite,
    get_user_stats,
)

# ------------------ ENV SETUP ------------------

load_dotenv()

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")

if not TELEGRAM_TOKEN:
    print("❌ TELEGRAM_TOKEN not found in environment variables")
    sys.exit(1)

# ------------------ HANDLERS ------------------

async def start_command(update: telegram.Update, context):
    await update.message.reply_text(
        "🔒 *Phishing Detection Bot*\n\n"
        "I analyze URLs and tell you:\n"
        "• Whether it is phishing or safe\n"
        "• Risk score (0–100)\n"
        "• AI model confidence\n"
        "• Threat intelligence signals\n"
        "• Clear reasons for the decision\n\n"
        "📩 Send any URL to begin.\n"
        "📊 Use /stats to view your usage analytics.",
        parse_mode="Markdown"
    )


async def stats_command(update: telegram.Update, context):
    user_id = update.effective_user.id
    stats = get_user_stats(user_id)
    stats_text = (
        "📊 *Your Statistics*\n\n"
        f"User ID: `{user_id}`\n"
        f"URLs Analyzed: {stats['total_urls']}\n"
        f"Last Analysis: {stats['last_analysis']}\n"
        f"Average Risk Score: {stats['average_risk']}\n"
        f"Most Common Verdict: {stats['most_common_verdict']}"
    )
    await update.message.reply_text(stats_text, parse_mode="Markdown")

async def analyze_url_message(update: telegram.Update, context):
    user_id = update.effective_user.id
    text = update.message.text
    urls = re.findall(r'(https?://[^\s]+)', text)

    if not urls:
        await update.message.reply_text(
            "❌ Please send a valid URL starting with http:// or https://"
        )
        return

    for url in urls:
        try:
            result = classify_url(url)
            domain = urlparse(url).netloc.lower().replace("www.", "")

            threat_intel = check_threat_intel(url, domain)
            final_score = min(100, result['risk_score'] + threat_intel['risk_score'])

            if threat_intel['is_malicious'] and result['verdict'] != 'PHISHING':
                final_verdict = 'PHISHING'
            elif final_score >= 70:
                final_verdict = 'PHISHING'
            elif final_score >= 40:
                final_verdict = 'SUSPICIOUS'
            else:
                final_verdict = 'SAFE'

            ai_label = result.get('ai_label') or 'N/A'
            ai_conf = result.get('ai_confidence')
            llm_label = result.get('llm_label') or 'N/A'
            llm_conf = result.get('llm_confidence')

            ai_conf_text = f"{ai_conf}%" if isinstance(ai_conf, (int, float)) else "N/A"
            llm_conf_text = f"{llm_conf}%" if isinstance(llm_conf, (int, float)) else "N/A"

            verdict_emoji = '🚨' if final_verdict == 'PHISHING' else '⚠️' if final_verdict == 'SUSPICIOUS' else '✅'

            reply = (
                f"{verdict_emoji} *{final_verdict}*\n"
                f"🔐 Risk Score: {final_score}%\n"
                f"🌐 Domain: `{domain}`\n\n"
                "*AI Models:*\n"
                f"• Model 1 (BERT): {ai_label} ({ai_conf_text})\n"
                f"• Model 2 (Zero-shot): {llm_label} ({llm_conf_text})\n\n"
                "*Threat Intelligence:*\n"
                f"• Malicious: {'Yes' if threat_intel['is_malicious'] else 'No'}\n"
                f"• Sources: {', '.join(threat_intel['sources']) if threat_intel['sources'] else 'None'}\n"
                f"• Intel Score: +{threat_intel['risk_score']}\n\n"
                "*Reasons:*\n"
            )

            if result["reasons"]:
                for r in result["reasons"]:
                    reply += f"• {r}\n"
            else:
                reply += "• No suspicious patterns detected\n"

            if threat_intel['details']:
                reply += "\n*Intel Details:*\n"
                for detail in threat_intel['details'][:3]:
                    reply += f"• {detail}\n"

            if final_verdict == 'PHISHING':
                reply += "\n🚫 *Recommendation:* Do not open this link."
            elif final_verdict == 'SUSPICIOUS':
                reply += "\n⚠️ *Recommendation:* Open only after source verification."
            else:
                reply += "\n✅ *Recommendation:* Appears safe, but always verify source."

            await update.message.reply_text(reply, parse_mode="Markdown")

            save_analysis_log_sqlite(
                url=url,
                analysis={
                    'risk_score': final_score,
                    'verdict': final_verdict,
                    'ai_label': result.get('ai_label'),
                    'ai_confidence': result.get('ai_confidence'),
                    'llm_label': result.get('llm_label'),
                    'llm_confidence': result.get('llm_confidence'),
                    'threat_sources': threat_intel.get('sources', []),
                    'reasons': result.get('reasons', []),
                },
                user_id=user_id,
            )

        except Exception as e:
            await update.message.reply_text(
                f"❌ Error analyzing URL:\n{str(e)}"
            )

# ------------------ ERROR HANDLER ------------------

async def error_handler(update, context):
    if update and update.effective_message:
        await update.effective_message.reply_text(
            "⚠️ Something went wrong. Please try again."
        )

# ------------------ MAIN ------------------

def main():
    print("🚀 Starting Phishing Detection Bot...")

    init_analysis_db()

    application = Application.builder().token(TELEGRAM_TOKEN).build()

    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("stats", stats_command))
    application.add_handler(
        MessageHandler(filters.TEXT & ~filters.COMMAND, analyze_url_message)
    )
    application.add_error_handler(error_handler)

    print("✅ Bot is running")
    application.run_polling()

if __name__ == "__main__":
    main()
