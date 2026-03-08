import re

SECRET_PATTERNS = {
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Generic Token": r"Bearer\s+[A-Za-z0-9\-._~+/]+=*"
}

def detect_secrets(strings):
    findings = []

    for s in strings:
        for name, pattern in SECRET_PATTERNS.items():
            if re.search(pattern, s):
                findings.append({"type": name, "value": s})

    return findings
