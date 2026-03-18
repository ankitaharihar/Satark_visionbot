# Satark Vision Bot

Telegram bot for phishing URL detection with explainable, rule-based scoring.

## Overview

Satark Vision Bot analyzes URLs sent in Telegram chats and returns:

- A verdict: SAFE, SUSPICIOUS, or PHISHING
- A risk score from 0 to 100
- Human-readable reasons for the decision

The detector is lightweight and fast, built around URL heuristics plus domain-age checks from WHOIS.

## Current Features

- URL length risk check
- IP address detection inside URLs
- Suspicious keyword detection in URLs
- URL shortener detection
- WHOIS-based domain age scoring
- Explainable risk output (reasons list)
- Telegram bot command and message handling

## How Scoring Works

The core logic is in `ai_model/phishing_detector.py`.

### URL Heuristics

- URL longer than 75 chars: +15
- URL uses IP address instead of domain: +25
- Each suspicious keyword match: +10
- URL shortener domain match: +20

### WHOIS Scoring

- Domain age < 7 days: +40
- Domain age < 30 days: +30
- Domain age < 90 days: +20
- Creation date missing: +20
- WHOIS lookup failure: +15

### Verdict Thresholds

- Score >= 70: PHISHING
- Score >= 40 and < 70: SUSPICIOUS
- Score < 40: SAFE

Final score is capped at 100.

## Project Layout

From workspace root:

```text
ai_model/
  phishing_detector.py
  whois_checker.py
Satark_visionbot/
  bot.py
  bot_enhancements.py
  config.py
  requirements.txt
  README.md
test_detector.py
```

## Requirements

- Python 3.8+
- Telegram bot token from BotFather

## Installation

Run from workspace root:

```bash
python -m venv .venv
```

Activate environment:

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Linux/macOS:

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r Satark_visionbot/requirements.txt
```

## Configuration

Create `Satark_visionbot/.env` with:

```env
TELEGRAM_TOKEN=your_bot_token_here
```

## Run The Bot

From workspace root:

```bash
python Satark_visionbot/bot.py
```

## Telegram Usage

- Use `/start` for the welcome/help message
- Send any message containing one or more `http://` or `https://` URLs
- Bot replies with verdict, risk score, and reasons per URL

## Example Output

```text
PHISHING
Risk Score: 85%

Reasons:
- URL is unusually long
- Suspicious keyword found: 'login'
- Domain registered less than 30 days ago
```

## Local Detector Test

Quick test without Telegram:

```bash
python test_detector.py
```

## Optional/Experimental Modules

- `Satark_visionbot/bot_enhancements.py` contains additional helper functions
  (logging, redirect checks, extended reports, extra commands) that are not
  wired into `Satark_visionbot/bot.py` by default.
- `Satark_visionbot/config.py` includes an optional configuration class.
- `Satark_visionbot/SECURITY_FEATURES.md` describes an extended feature set and
  roadmap concepts.

## Troubleshooting

- `TELEGRAM_TOKEN not found`: verify `Satark_visionbot/.env` exists and has
  a valid token.
- `ModuleNotFoundError: ai_model`: run the bot from workspace root using
  `python Satark_visionbot/bot.py`.
- WHOIS failures can happen due to network/registrar lookup limits; detector
  will still return a scored result.

## Security Note

This bot provides heuristic analysis and does not guarantee perfect detection.
Always verify sensitive links through official channels.

## License

MIT License. See `Satark_visionbot/LICENSE`.
