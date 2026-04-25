"""
claim_analyser.py - jwt claims validation and anomaly detection
checks for
    - Missing critical claims (exp, iss, aud, iat, nbf)
    - Expired tokens (exp in the past)
    - Not-yet-valid tokens (nbf in the future)
    - Overly long expiry windows (over 24 hours)
    - Missing or generic issuer/audience values

Author: Patrick Earley
Module: CMP320 Advanced Ethical Hacking
"""

import time


# how long is too long for a token lifetime (a day)
MAX_LIFETIME_SECONDS = 86400

# claims we consider critical to have present
CRITICAL_CLAIMS = ['exp', 'iss', 'aud', 'iat']

# optional but recommended
RECOMMENDED_CLAIMS = ['nbf']

# issuers/audiences that suggest a placeholder was never changed
SUSPICIOUS_VALUES = {'test', 'example', 'localhost', 'dev', 'development',
                     'staging', 'changeme', 'your-app', 'myapp', 'app'}


def analyse(decoded):
    # analyse the claims in a decoded jwt for security issues.
    payload = decoded['payload']
    findings = []
    now = int(time.time())

    # missing critical claims

    for claim in CRITICAL_CLAIMS:
        if claim not in payload:
            findings.append({
                'severity': 'MEDIUM',
                'title': f"missing claim: '{claim}'",
                'description': (
                    f"the '{claim}' claim is absent from the payload. "
                    f"rfc 7519 strongly recommends this claim be present "
                    f"to prevent token misuse."
                )
            })

    for claim in RECOMMENDED_CLAIMS:
        if claim not in payload:
            findings.append({
                'severity': 'LOW',
                'title': f"missing recommended claim: '{claim}'",
                'description': (
                    f"the '{claim}' claim is absent. while not mandatory, "
                    f"its absence reduces the precision of token validity checks."
                )
            })

    # expiry checks

    if 'exp' in payload:
        exp = payload['exp']

        # check exp is actually an integer
        if not isinstance(exp, (int, float)):
            findings.append({
                'severity': 'MEDIUM',
                'title': "invalid 'exp' claim type",
                'description': (
                    f"the 'exp' claim should be a numeric timestamp, "
                    f"but got {type(exp).__name__}."
                )
            })
        else:
            # token is expired
            if exp < now:
                overdue_by = now - exp
                findings.append({
                    'severity': 'MEDIUM',
                    'title': "token is expired",
                    'description': (
                        f"the token expired {_format_duration(overdue_by)} ago "
                        f"(exp: {exp}, now: {now}). if a server is accepting "
                        f"this token, expiry validation is not being enforced."
                    )
                })

            # check for excessively long lifetime
            if 'iat' in payload and isinstance(payload['iat'], (int, float)):
                lifetime = exp - payload['iat']
                if lifetime > MAX_LIFETIME_SECONDS:
                    findings.append({
                        'severity': 'LOW',
                        'title': "excessively long token lifetime",
                        'description': (
                            f"token lifetime is {_format_duration(lifetime)}, "
                            f"which exceeds the recommended maximum of 24 hours. "
                            f"long-lived tokens increase the window of opportunity "
                            f"for an attacker if a token is compromised."
                        )
                    })

    # not-before check

    if 'nbf' in payload:
        nbf = payload['nbf']
        if isinstance(nbf, (int, float)) and nbf > now:
            findings.append({
                'severity': 'LOW',
                'title': "token not yet valid (nbf in the future)",
                'description': (
                    f"the 'nbf' (not before) claim is set to a future time "
                    f"({nbf}). the token should not be accepted yet."
                )
            })

    # issuer checks

    if 'iss' in payload:
        iss = str(payload['iss']).lower().strip()
        if iss in SUSPICIOUS_VALUES or not iss:
            findings.append({
                'severity': 'LOW',
                'title': "suspicious or generic issuer value",
                'description': (
                    f"the 'iss' claim is set to '{payload['iss']}', which "
                    f"looks like a placeholder or default value. this suggests "
                    f"the issuer field may not be properly validated."
                )
            })

    # audience checks

    if 'aud' in payload:
        aud = payload['aud']
        # aud can be a string or a list of strings per RFC 7519
        aud_values = [aud] if isinstance(aud, str) else aud
        for val in aud_values:
            if str(val).lower().strip() in SUSPICIOUS_VALUES or not str(val).strip():
                findings.append({
                    'severity': 'LOW',
                    'title': "suspicious or generic audience value",
                    'description': (
                        f"the 'aud' claim contains '{val}', which looks like "
                        f"a placeholder. proper audience validation restricts "
                        f"which services can accept this token."
                    )
                })
                break

    # no issues found

    if not findings:
        findings.append({
            'severity': 'INFO',
            'title': "claims appear valid",
            'description': "no claim-related issues were detected."
        })

    return findings


# helper
# god help me

def _format_duration(seconds):
    """Convert a number of seconds into a readable string like '2 hours 30 minutes'."""
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds} seconds"
    elif seconds < 3600:
        minutes = seconds // 60
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    elif seconds < 86400:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        if minutes:
            return f"{hours} hour{'s' if hours != 1 else ''} {minutes} minute{'s' if minutes != 1 else ''}"
        return f"{hours} hour{'s' if hours != 1 else ''}"
    else:
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        if hours:
            return f"{days} day{'s' if days != 1 else ''} {hours} hour{'s' if hours != 1 else ''}"
        return f"{days} day{'s' if days != 1 else ''}"