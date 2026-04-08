import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
	sys.path.insert(0, str(ROOT_DIR))

from common.ai_model.phishing_detector import classify_url

url = "http://secure-login-update.com/verify"
result = classify_url(url)

print(result)
