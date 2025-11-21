import re

def check_phishing(url):
    score = 0
    reasons = []

    # 1. Check HTTPS
    if not url.startswith("https://"):
        score += 1
        reasons.append("No HTTPS (unsecured website)")

    # 2. Check for IP instead of domain
    ip_pattern = r"(https?:\/\/)?(\d{1,3}\.){3}\d{1,3}"
    if re.match(ip_pattern, url):
        score += 2
        reasons.append("URL uses an IP address instead of domain")

    # 3. Check for too many hyphens
    if url.count("-") >= 3:
        score += 1
        reasons.append("Too many '-' characters")

    # 4. Check for suspicious length
    if len(url) > 75:
        score += 1
        reasons.append("URL is unusually long")

    # 5. Check for '@' (used in phishing redirects)
    if "@" in url:
        score += 2
        reasons.append("URL contains '@' which is commonly used in phishing")

    # 6. Check number of subdomains
    domain_parts = url.split(".")
    if len(domain_parts) > 4:
        score += 1
        reasons.append("Too many subdomains")

    # Final detection
    if score <= 1:
        result = "SAFE"
    elif score <= 3:
        result = "SUSPICIOUS"
    else:
        result = "PHISHING"

    return result, reasons


# ----------- MAIN PROGRAM -----------
url = input("Enter a URL to check: ")

result, reasons = check_phishing(url)

print("\n🔍 URL Analysis Result:", result)
print("\nReasons:")
for r in reasons:
    print("-", r)
