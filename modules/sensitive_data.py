"""
sensitive_data.py - sensitive data detection in jwt payloads

scans the decoded jwt payload for sensitive data that shouldn't
be sitting in an unencrypted token.
 
checks for:
    - email addresses
    - phone numbers
    - API keys and secrets
    - bearer tokens
    - passwords in claim names
    - credit card numbers
    - private key material
 
Author: Patrick Earley
Module: CMP320 Advanced Ethical Hacking
"""
 
import re
import json
 
 
# regex patterns for sensitive data detection
PATTERNS = [
    (
        'Email address',
        'MEDIUM',
        re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
    ),
    (
        'Phone number',
        'LOW',
        # must contain non-digit characters (spaces, dashes, brackets)
        # to avoid matching plain numeric timestamps
        re.compile(r'\+?\d[\d]{0,3}[\s\-().]+[\d\s\-().]{5,}\d')
    ),
    (
        'API key (generic)',
        'HIGH',
        # match the full prefix-key pattern including the value after the separator
        re.compile(r'(?i)(sk|pk|api|key|secret|token)[-_][a-zA-Z0-9]{16,}')
    ),
    (
        'Bearer token',
        'HIGH',
        re.compile(r'(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*')
    ),
    (
        'AWS access key',
        'HIGH',
        re.compile(r'AKIA[0-9A-Z]{16}')
    ),
    (
        'Private key material',
        'CRITICAL',
        re.compile(r'-----BEGIN (RSA |EC )?PRIVATE KEY-----')
    ),
    (
        'Credit card number',
        'HIGH',
        re.compile(r'\b(?:\d[ \-]?){13,16}\b')
    ),
]
 
# claim names that suggest sensitive data regardless of value
SENSITIVE_CLAIM_NAMES = {
    'password', 'passwd', 'pwd', 'secret', 'private_key', 'privatekey',
    'api_key', 'apikey', 'api_secret', 'apisecret', 'token', 'access_token',
    'refresh_token', 'client_secret', 'ssn', 'credit_card', 'card_number',
    'cvv', 'pin'
}
 
 
def analyse(decoded):
    """
    Scan the JWT payload for sensitive data.

    In arg of the output from decoder.decode() and returns a list of
    finding dicts with severity, title, and description
    """
    payload = decoded['payload']
    findings = []
 
    # flatten payload to a single string for pattern matching
    payload_str = json.dumps(payload)
 
    # run each regex pattern against the full payload string
    for label, severity, pattern in PATTERNS:
        matches = [m.group(0) for m in pattern.finditer(payload_str)]
        if matches:
            unique = list(dict.fromkeys(matches))
            findings.append({
                'severity': severity,
                'title': f"Sensitive data detected: {label}",
                'description': (
                    f"{len(unique)} instance(s) of {label.lower()} pattern found "
                    f"in the payload. JWT payloads are not encrypted and can be "
                    f"read by anyone who obtains the token. "
                    f"Found: {', '.join(str(m)[:40] for m in unique[:3])}"
                )
            
            })
    # check claim names for obviously sensitive field names
    for claim_name in payload.keys():
        if claim_name.lower() in SENSITIVE_CLAIM_NAMES:
            findings.append({
                'severity': 'HIGH',
                'title': f"Sensitive claim name: '{claim_name}'",
                'description': (
                    f"The payload contains a claim named '{claim_name}', which "
                    f"suggests sensitive data may be stored directly in the token. "
                    f"Sensitive values should never be placed in an unencrypted JWT payload."
                )
            })
 
    if not findings:
        findings.append({
            'severity': 'INFO',
            'title': "No sensitive data detected",
            'description': "No obvious sensitive data patterns were found in the payload."
        })
 
    return findings