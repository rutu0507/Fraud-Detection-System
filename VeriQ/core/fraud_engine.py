import re
from urllib.parse import urlparse

SUSPICIOUS_WORDS = [
    "login", "verify", "bank", "secure", "update",
    "account", "free", "click", "urgent", "password",
    "confirm", "limited", "winner", "offer"
]

SUSPICIOUS_DOMAINS = [
    ".xyz", ".tk", ".ru", ".top", ".info", ".to"
]

PIRACY_KEYWORDS = [
    "watch", "movies", "stream", "download", "free"
]

def contains_ip(url):
    return re.search(r"(http[s]?://)?(\d{1,3}\.){3}\d{1,3}", url)

def analyze_input(url=None, text=None, filename=None):

    risk_score = 0
    reasons = []

    # ---------------- URL CHECK ----------------
    if url:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        # Length check
        if len(url) > 75:
            risk_score += 15
            reasons.append("URL is unusually long")

        # IP address in URL
        if contains_ip(url):
            risk_score += 25
            reasons.append("URL contains IP address")

        # Suspicious domain
        for d in SUSPICIOUS_DOMAINS:
            if domain.endswith(d):
                risk_score += 20
                reasons.append(f"Suspicious domain detected ({d})")

        # Suspicious numbered subdomain (ww17, ww3, etc.)
        if re.search(r"ww\d+\.", domain):
            risk_score += 25
            reasons.append("Suspicious numbered subdomain detected")

        # Too many special characters
        special_chars = len(re.findall(r"[^\w]", url))
        if special_chars > 10:
            risk_score += 10
            reasons.append("Too many special characters in URL")

        # Suspicious keywords
        for word in SUSPICIOUS_WORDS:
            if word in url.lower():
                risk_score += 10
                reasons.append(f"Suspicious keyword detected: {word}")

        # Piracy / risky content keywords
        for word in PIRACY_KEYWORDS:
            if word in url.lower():
                risk_score += 12
                reasons.append(f"High-risk content keyword: {word}")

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
    if risk_score >= 70:
        status = "FRAUDULENT"
    elif risk_score >= 35:
        status = "SUSPICIOUS"
    else:
        status = "LEGITIMATE"

    confidence = min(98, 40 + risk_score)

    return {
        "status": status,
        "risk_score": risk_score,
        "confidence": confidence,
        "reasons": reasons if reasons else ["No major threats detected"]
    }