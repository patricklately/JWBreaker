"""
entropy.py - Shannon entropy scoring for recovered HMAC secrets

once brute_force.py recovers a secret, this module scores its
cryptographic strength using Shannon entropy.

Ratings:
    CRITICAL  < 2.0 bits  - trivially weak (e.g. 'aaa', '111')
    HIGH      < 3.0 bits  - very weak (e.g. 'secret', 'password')  
    MEDIUM    < 3.5 bits  - weak (simple words with substitutions)
    LOW       < 4.0 bits  - moderate (mixed case, some symbols)
    INFO      >= 4.0 bits - reasonable entropy, but still cracked

Author: Patrick Earley
Module: CMP320 Advanced Ethical Hacking
"""

import math
from collections import Counter


def _shannon_entropy(secret):
    """
    calculate the Shannon entropy of a string in bits per character.

    entropy = -sum(p(x) * log2(p(x))) for each unique character x,
    where p(x) is the probability of that character appearing.
    """
    if not secret:
        return 0.0

    counts = Counter(secret)
    length = len(secret)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def _rate(entropy, secret_length):
    """
    assign a severity rating based on entropy and secret length.

    entropy alone isn't enough as a very short secret can have high
    entropy per character but still be weak overall, so we also
    penalise short secrets.
    """
    # very short secrets are always at least high severity
    if secret_length < 8:
        if entropy < 3.0:
            return 'CRITICAL', "extremely short and low-entropy secret"
        return 'HIGH', "very short secret - easy to brute-force regardless of entropy"

    if entropy < 2.0:
        return 'CRITICAL', "trivially weak - near-zero entropy (e.g. repeated characters)"
    elif entropy < 3.0:
        return 'HIGH', "very weak - low entropy, likely a common word or pattern"
    elif entropy < 3.5:
        return 'MEDIUM', "weak - below recommended entropy for a signing secret"
    elif entropy < 4.0:
        return 'LOW', "moderate entropy, but still recovered from a wordlist"
    else:
        return 'INFO', "reasonable entropy per character, but the secret was still cracked"


def analyse(cracked_secret):
    """
    score the entropy of a recovered HMAC secret.

    arg in is the cracked secret string from brute_force.analyse().
    returns a list containing a single finding dict with the entropy
    score, strength rating, and recommendations.
    """
    if cracked_secret is None:
        return [{
            'severity': 'INFO',
            'title': "entropy analysis skipped",
            'description': "no cracked secret was provided to analyse."
        }]

    # blank secret is a special case
    if cracked_secret == '':
        return [{
            'severity': 'CRITICAL',
            'title': "secret is blank - zero entropy",
            'description': (
                "the signing secret is an empty string, which has zero entropy. "
                "this is the weakest possible secret."
            ),
            'entropy': 0.0,
            'length': 0
        }]

    entropy = _shannon_entropy(cracked_secret)
    severity, rating = _rate(entropy, len(cracked_secret))

    return [{
        'severity': severity,
        'title': f"entropy analysis: {rating}",
        'description': (
            f"the recovered secret '{cracked_secret}' has a Shannon entropy "
            f"of {entropy:.2f} bits/character over {len(cracked_secret)} "
            f"character(s). {rating}. "
            f"rfc 7518 requires hmac keys to be at least as long as the hash "
            f"output (32 bytes for hs256). A strong secret should be randomly "
            f"generated and at least 32 characters long."
        ),
        'entropy': round(entropy, 4),
        'length': len(cracked_secret)
    }]