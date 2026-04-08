# Enhanced bot configuration with environment variables
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Enhanced configuration
class BotConfig:
    def __init__(self):
        # Get token from environment variable (more secure)
        self.TELEGRAM_TOKEN = os.getenv('TELEGRAM_TOKEN', '7776856290:AAGc54x230eAigcP-8Y8VvTy7YE_cNA7lqw')
        
        # Rate limiting settings
        self.MAX_REQUESTS_PER_MINUTE = 10
        self.MAX_REQUESTS_PER_HOUR = 50
        
        # Analysis settings
        self.MAX_REDIRECTS = 5
        self.REQUEST_TIMEOUT = 15
        self.MAX_URL_LENGTH = 2048
        
        # Logging settings
        self.LOG_FILE = 'phishing_bot.log'
        self.ANALYSIS_LOG_FILE = 'analysis_logs.json'
        
        # Security settings
        self.ENABLE_BLACKLIST_CHECK = True
        self.ENABLE_REDIRECT_ANALYSIS = True
        self.ENABLE_ADVANCED_PATTERNS = True

# Database schema for tracking (SQLite example)
CREATE_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS url_analysis (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    url TEXT,
    risk_score INTEGER,
    risk_level TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    analysis_data TEXT
);

CREATE TABLE IF NOT EXISTS user_stats (
    user_id INTEGER PRIMARY KEY,
    total_analyses INTEGER DEFAULT 0,
    last_analysis DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS blacklist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT UNIQUE,
    reason TEXT,
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
"""