"""
kid_injection.py - kid header parameter injection detection

if the kid value is used unsanitised in a file path lookup or
database query, an attacker can manipulate it to:
    - path traversal: point to a known file (e.g. /dev/null) to
      use an empty or predictable signing key
    - sql injection: manipulate the key lookup query
    - command injection: execute arbitrary commands if the kid
      is passed to a shell

Author: Patrick Earley
Module: CMP320 Advanced Ethical Hacking
"""

import re


# patterns that suggest path traversal in the kid value
PATH_TRAVERSAL_PATTERNS = [
    re.compile(r'\.\./'),           # unix traversal
    re.compile(r'\.\.\\'),          # windows traversal
    re.compile(r'%2e%2e', re.I),    # url-encoded traversal
    re.compile(r'/etc/'),           # common unix target
    re.compile(r'/dev/null'),       # null file trick
    re.compile(r'/proc/'),          # proc filesystem
    re.compile(r'C:\\', re.I),      # windows absolute path
]

# patterns that suggest sql injection in the kid value
SQL_INJECTION_PATTERNS = [
    re.compile(r"'\s*(or|and)\s*'?\d", re.I),   # ' or '1
    re.compile(r"--\s*$"),                        # sql comment
    re.compile(r';\s*(drop|select|insert)', re.I), # stacked queries
    re.compile(r"union\s+select", re.I),          # union attack
    re.compile(r"'\s*=\s*'"),                     # tautology
    re.compile(r"/\*.*\*/"),                      # inline comment
]

# patterns that suggest command injection in the kid value
COMMAND_INJECTION_PATTERNS = [
    re.compile(r'[|;&`$]'),         # shell metacharacters
    re.compile(r'\$\('),            # command substitution
    re.compile(r'`[^`]+`'),         # backtick execution
]


def analyse(decoded):
    """
    analyse the kid header parameter for injection attack patterns.

    arg in is the output of decoder.decode(). returns a list of
    finding dicts with severity, title, and description.
    """
    findings = []
    header = decoded['header']

    # no kid parameter at all - nothing to check
    if 'kid' not in header:
        findings.append({
            'severity': 'INFO',
            'title': "No kid parameter present",
            'description': "The header does not contain a 'kid' parameter."
        })
        return findings

    kid = str(header['kid'])

    # path traversal checks
    traversal_hits = [
        p.pattern for p in PATH_TRAVERSAL_PATTERNS if p.search(kid)
    ]
    if traversal_hits:
        findings.append({
            'severity': 'HIGH',
            'title': "Path traversal pattern in kid parameter",
            'description': (
                f"The kid value '{kid}' contains path traversal sequences. "
                f"If the server uses this value to locate a key file without "
                f"sanitisation, an attacker may be able to point it to an "
                f"arbitrary file (e.g. /dev/null gives an empty key, making "
                f"an empty-string HMAC trivially valid). "
                f"Matched patterns: {', '.join(traversal_hits)}"
            ),
            'kid': kid
        })

    # sql injection checks
    sql_hits = [
        p.pattern for p in SQL_INJECTION_PATTERNS if p.search(kid)
    ]
    if sql_hits:
        findings.append({
            'severity': 'HIGH',
            'title': "SQL injection pattern in kid parameter",
            'description': (
                f"The kid value '{kid}' contains patterns consistent with "
                f"SQL injection. If the server uses this value unsanitised "
                f"in a database query to look up signing keys, an attacker "
                f"may be able to manipulate the query result. "
                f"Matched patterns: {', '.join(sql_hits)}"
            ),
            'kid': kid
        })

    # command injection checks
    cmd_hits = [
        p.pattern for p in COMMAND_INJECTION_PATTERNS if p.search(kid)
    ]
    if cmd_hits:
        findings.append({
            'severity': 'CRITICAL',
            'title': "Command injection pattern in kid parameter",
            'description': (
                f"The kid value '{kid}' contains shell metacharacters or "
                f"command substitution syntax. If the server passes this value "
                f"to a shell command without sanitisation, arbitrary command "
                f"execution may be possible. "
                f"Matched patterns: {', '.join(cmd_hits)}"
            ),
            'kid': kid
        })

    # kid present but no suspicious patterns
    if not any([traversal_hits, sql_hits, cmd_hits]):
        findings.append({
            'severity': 'INFO',
            'title': f"kid parameter present: '{kid}'",
            'description': (
                f"The header contains a kid parameter with value '{kid}'. "
                f"No injection patterns were detected, but ensure the server "
                f"validates this value against a strict allowlist."
            ),
            'kid': kid
        })

    return findings