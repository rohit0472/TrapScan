import os
from urllib.parse import urlparse

BLACKLIST_FILE = "data/blacklist.txt"

SUSPICIOUS_KEYWORDS = [
    "login","secure","signin","bank","verify","confirm","account","update",
    "free","gift","otp","reset","checkout","phish","malware","click"
]

def normalize_domain(domain):
    domain = domain.lower().strip()
    if domain.startswith("www."):
        domain = domain[4:]
    return domain

def load_blacklist():
    if not os.path.exists(BLACKLIST_FILE):
        return set()
    with open(BLACKLIST_FILE, "r") as f:
        return {normalize_domain(line.strip()) for line in f if line.strip()}

BLACKLIST = load_blacklist()

def update_blacklist(domain):
    domain_norm = normalize_domain(domain)
    if domain_norm not in BLACKLIST:
        with open(BLACKLIST_FILE, "a") as f:
            f.write(domain_norm + "\n")
        BLACKLIST.add(domain_norm)

def extract_domain_from_url(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    domain = parsed.netloc
    return normalize_domain(domain)

def extract_domain_from_email(email):
    if "@" not in email:
        return None
    domain = email.split("@")[1]
    return normalize_domain(domain)

def analyze(input_value, input_type="url"):
    if input_type == "url":
        domain = extract_domain_from_url(input_value)
    elif input_type == "email":
        domain = extract_domain_from_email(input_value)
        if domain is None:
            return "Invalid", "Error", "Not a valid email"
    else:
        return "Invalid", "Error", "Unknown input type"

    if domain in BLACKLIST or f"www.{domain}" in BLACKLIST:
        return "Malicious", "Blacklist", f"Domain {domain} found in blacklist"

    for kw in SUSPICIOUS_KEYWORDS:
        if kw in domain or kw in input_value.lower():
            if kw in ["phish", "malware"]:
                update_blacklist(domain)
                return "Malicious", "Heuristic", f"Domain {domain} flagged and added to blacklist"
            return "Suspicious", "Heuristic", f"Keyword '{kw}' found"

    return "Safe", "Heuristic", "No suspicious indicators"
