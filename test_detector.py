from ai_model.phishing_detector import classify_url

url = "http://secure-login-update.com/verify"
result = classify_url(url)

print(result)
