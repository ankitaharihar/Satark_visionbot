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

from ai_model.phishing_detector import classify_url

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
        "• Clear reasons for the decision\n\n"
        "📩 Send any URL to begin.",
        parse_mode="Markdown"
    )

async def analyze_url_message(update: telegram.Update, context):
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

            reply = f"""
🚨 *{result['verdict']}*
🔐 Risk Score: {result['risk_score']}%

*Reasons:*
"""

            if result["reasons"]:
                for r in result["reasons"]:
                    reply += f"• {r}\n"
            else:
                reply += "• No suspicious patterns detected\n"

            await update.message.reply_text(reply, parse_mode="Markdown")

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

    application = Application.builder().token(TELEGRAM_TOKEN).build()

    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(
        MessageHandler(filters.TEXT & ~filters.COMMAND, analyze_url_message)
    )
    application.add_error_handler(error_handler)

    print("✅ Bot is running")
    application.run_polling()

if __name__ == "__main__":
    main()
