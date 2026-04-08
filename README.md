# 🔒 Satark Vision Bot - Advanced Telegram Phishing Detection

> A comprehensive Telegram bot for real-time phishing URL detection and security analysis

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Telegram](https://img.shields.io/badge/Telegram-Bot-blue.svg)](https://telegram.org)

## 🎯 **Project Overview**

Satark Vision Bot is an advanced Telegram bot designed to protect users from phishing attacks by analyzing URLs in real-time. It performs comprehensive security checks including SSL certificate validation, domain analysis, DNS security records verification, and brand impersonation detection.

## ✨ **Key Features**

### 🔐 **Multi-Layer Security Analysis**

- **SSL Certificate Validation** - Checks certificate validity, expiration, and issuer
- **WHOIS Domain Analysis** - Analyzes domain age, registrar, and privacy settings
- **DNS Security Records** - Verifies MX, SPF, DMARC, and CAA records
- **URL Structure Analysis** - Detects suspicious patterns and malicious indicators
- **Brand Impersonation Detection** - Identifies fake websites mimicking popular brands

### 📊 **Advanced Risk Assessment**

- **Risk Scoring System** (0-100) with detailed explanations
- **Five Risk Levels**: Safe, Low Risk, Medium Risk, High Risk, Critical
- **Comprehensive Reports** with actionable recommendations
- **Real-time Analysis** with fast response times

### 🛡️ **Security Features**

- **Rate Limiting** to prevent abuse
- **Logging System** for monitoring and analysis
- **Environment Variable Support** for secure configuration
- **No External API Dependencies** for core functionality (optional APIs supported)

## 🚀 **Quick Start**

### **Prerequisites**

- Python 3.8 or higher
- Telegram Bot Token (from @BotFather)
- Windows/Linux/macOS

### **Installation**

1. **Clone the repository:**

```bash
git clone https://github.com/Adownloader17/Satark_visionbot.git
cd Satark_visionbot
```

2. **Set up virtual environment:**

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux/macOS
source .venv/bin/activate
```

3. **Install dependencies:**

```bash
pip install -r requirements.txt
```

4. **Configure environment variables:**

```bash
# Copy template and edit
cp .env.template .env
# Edit .env with your bot token
```

5. **Run the bot:**

```bash
python bot/bot.py
```

## 🔧 **Configuration**

### **Environment Variables**

Create a `.env` file with your configuration:

```env
TELEGRAM_TOKEN=your_bot_token_here
MAX_REQUESTS_PER_MINUTE=10
LOG_LEVEL=INFO
```

### **Bot Commands**

- `/start` - Initialize the bot
- `/help` - Show help information
- `/stats` - Display usage statistics
- `/about` - About the bot

## 📱 **Usage**

1. **Start a conversation** with your bot on Telegram
2. **Send any URL** to get security analysis
3. **Receive detailed report** with risk assessment and recommendations

## 🌐 **Web App + Browser Extension**

You can now use the same detection engine in a local web app and a Chrome extension.

### **Run Web App/API**

```bash
# from project root
python web/app.py
```

Open in browser:

```text
http://127.0.0.1:8000
```

### **API Endpoint**

```text
POST /api/analyze
Content-Type: application/json
{
	"url": "https://example.com"
}
```

### **Load Chrome Extension**

1. Open `chrome://extensions`
2. Turn on **Developer mode**
3. Click **Load unpacked**
4. Select `extension` folder
5. Keep `python web/app.py` running, then use the extension popup

### **Example Analysis Output:**

```
🔒 SECURITY ANALYSIS REPORT

🔴 Risk Level: HIGH_RISK
📊 Risk Score: 85/100

URL: https://suspicious-site.com

⚠️ HIGH CAUTION ADVISED:
• Avoid clicking this link
• Verify the source independently
• Use official websites instead

SSL Certificate Analysis:
- Status: Self-signed certificate
- WARNING: Untrusted issuer

Domain Analysis:
- Age: 3 days (Very new domain)
- Registrar: Privacy Protected

Brand Impersonation Detected:
- Brands: paypal, microsoft
```

## 🧪 **Testing**

Test the bot with various URLs:

```bash
# Safe URL
https://google.com

# Suspicious patterns
https://paypal-security-update.suspicious-domain.tk/login

# IP-based URL
https://192.168.1.1/secure/update
```

## 📊 **Risk Assessment Criteria**

### **Risk Factors Analyzed:**

- Domain age and registration details
- SSL certificate validity and issuer
- DNS security record presence
- URL structure and patterns
- Brand impersonation indicators
- Suspicious keywords and TLDs

### **Risk Levels:**

- **✅ SAFE (0-24)**: URL passed all security checks
- **💡 LOW_RISK (25-49)**: Minor concerns detected
- **🔶 MEDIUM_RISK (50-74)**: Several risk factors present
- **🔴 HIGH_RISK (75-99)**: Multiple red flags detected
- **🚨 CRITICAL (100)**: Extreme danger - likely phishing

## 🔒 **Security & Privacy**

- **No URL Storage**: URLs are analyzed in real-time and not permanently stored
- **Privacy Protection**: User data is handled according to privacy best practices
- **Rate Limiting**: Prevents abuse and ensures fair usage
- **Secure Configuration**: Environment variables for sensitive data

## 🛠️ **Development**

### **Project Structure**

```
Satark_visionbot/
├── bot/
│   ├── bot.py            # Telegram bot entrypoint
│   └── config.py         # Bot-specific config
├── web/
│   ├── app.py            # Flask API + web UI entrypoint
│   ├── templates/        # Web templates
│   └── static/           # Web static assets
├── extension/            # Chrome extension files
├── common/
│   ├── bot_enhancements.py
│   └── ai_model/         # Shared AI detection modules
├── requirements.txt
└── README.md
```

### **Adding New Features**

1. Create shared detection helpers in `common/bot_enhancements.py`
2. Update analysis pipeline in `bot/bot.py` and/or `web/app.py`
3. Add tests for new functionality
4. Update documentation

## 📈 **Performance**

- **Response Time**: < 5 seconds for most URLs
- **Accuracy**: High precision with low false positives
- **Throughput**: Handles multiple concurrent analyses
- **Resource Usage**: Lightweight with minimal dependencies

## 🤝 **Contributing**

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes and test thoroughly
4. Submit a pull request with detailed description

### **Contribution Guidelines**

- Follow PEP 8 coding standards
- Add tests for new features
- Update documentation
- Ensure backward compatibility

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 **Acknowledgments**

- **python-telegram-bot** library for Telegram integration
- **python-whois** for domain analysis
- **dnspython** for DNS lookups
- **cryptography** for SSL analysis

## 📞 **Support**

- **Issues**: [GitHub Issues](https://github.com/Adownloader17/Satark_visionbot/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Adownloader17/Satark_visionbot/discussions)
- **Email**: [Your email here]

## 🔮 **Roadmap**

- [ ] Machine Learning integration for better detection
- [ ] Web dashboard for analytics
- [ ] Multi-language support
- [ ] Integration with threat intelligence feeds
- [ ] Mobile app companion
- [ ] Enterprise features

---

**⚠️ Disclaimer**: This bot provides security analysis as a helpful tool but cannot guarantee 100% accuracy. Always use your judgment and verify sources independently for sensitive transactions.
Detect Phishing URLs on telegram - @Satark_visionbot
