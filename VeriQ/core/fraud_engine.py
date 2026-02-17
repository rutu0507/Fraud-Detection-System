import re
from urllib.parse import urlparse

SUSPICIOUS_WORDS = [
    "login", "verify", "bank", "secure", "update",
    "account", "free", "click", "urgent", "password",
    "confirm", "limited", "winner", "offer"
]

SUSPICIOUS_DOMAINS = [
    ".xyz", ".tk", ".ru", ".top", ".info"
]

def contains_ip(url):
    return re.search(r"(http[s]?://)?(\d{1,3}\.){3}\d{1,3}", url)

def analyze_input(url=None, text=None, filename=None):

    risk_score = 0
    reasons = []

    # ---------------- URL CHECK ----------------
    if url:
        parsed = urlparse(url)

        # Length check
        if len(url) > 75:
            risk_score += 15
            reasons.append("URL is unusually long")

        # IP address in URL
        if contains_ip(url):
            risk_score += 25
            reasons.append("URL contains IP address")

        # Suspicious domain
        for domain in SUSPICIOUS_DOMAINS:
            if domain in url:
                risk_score += 20
                reasons.append(f"Suspicious domain detected ({domain})")

        # Too many special characters
        special_chars = len(re.findall(r"[^\w]", url))
        if special_chars > 10:
            risk_score += 10
            reasons.append("Too many special characters in URL")

        # Suspicious keywords
        for word in SUSPICIOUS_WORDS:
            if word in url.lower():
                risk_score += 8
                reasons.append(f"Suspicious keyword detected: {word}")

    # ---------------- TEXT CHECK ----------------
    if text:
        text_lower = text.lower()

        for word in SUSPICIOUS_WORDS:
            if word in text_lower:
                risk_score += 10
                reasons.append(f"Suspicious word in text: {word}")

        if "http" in text_lower:
            risk_score += 10
            reasons.append("Text contains external link")

    # ---------------- FILE CHECK ----------------
    if filename:
        if filename.endswith((".exe", ".bat", ".scr")):
            risk_score += 40
            reasons.append("Executable file detected")

    # ---------------- FINAL DECISION ----------------
    if risk_score >= 60:
        status = "FRAUDULENT"
    elif risk_score >= 30:
        status = "SUSPICIOUS"
    else:
        status = "LEGITIMATE"

    confidence = min(95, 50 + risk_score // 2)

    return {
        "status": status,
        "risk_score": risk_score,
        "confidence": confidence,
        "reasons": reasons if reasons else ["No major threats detected"]
    }