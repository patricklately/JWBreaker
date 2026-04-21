"""
decoder.py - for JWT decoding and structural validation

JWTs are made of three Base64URL-encoded segments separated by
full stops: <header>.<payload>.<signature>

The header and payload are JSON objects. The signature is raw bytes.

Author: Patrick Earley
Module: CMP320 Advanced Ethical Hacking
"""

import base64
import json


# custom exceptions

class JWTDecodeError(Exception):
    """Raised when a JWT cannot be decoded due to structural or
    formatting issues. Provides a human-readable message suitable
    for display in the CLI and report output."""
    pass


# internal helpers

def _pad(b64_string):
    """
    Requires padding with '=' characters to make the length a 
    multiple of 4. JWT drops this padding so here we must restore
    it before decoding.

    In goes a Base64URL-encoded string without padding, 
    and out comes the same string with the correct padding restored.
    """
    # Calculate how many padding characters are needed
    padding_needed = 4 - len(b64_string) % 4
    if padding_needed != 4:
        b64_string += '=' * padding_needed
    return b64_string


def _decode_b64url(b64_string, label):
    """
    Handles both standard Base64 and URL-safe Base64 which replaces
    '+' with '-' and '/' with '_'.

    Arguments in are the Base64URL segment to decode, and a
    human-readable label for error messages, and out is the
    decoded raw bytes. Raises JWTDecodeError if the segment cannot
    be Base64 decoded.
    """
    try:
        return base64.urlsafe_b64decode(_pad(b64_string))
    except Exception as e:
        raise JWTDecodeError(
            f"Failed to Base64URL-decode the {label} segment: {e}"
        )


def _parse_json(raw_bytes, label):
    """
    Parse raw bytes as a UTF-8 JSON object.

    In args are the decoded bytes and a readable label, out is the
    parsed JSON object. Raises JWTDecodeError if the bytes cannot
    be decoded as UTF-8 or parsed as valid JSON
    """
    try:
        return json.loads(raw_bytes.decode('utf-8'))
    except UnicodeDecodeError:
        raise JWTDecodeError(
            f"The {label} segment is not valid UTF-8."
        )
    except json.JSONDecodeError as e:
        raise JWTDecodeError(
            f"The {label} segment is not valid JSON: {e}"
        )


# public interface

def decode(token):
    """
    Decode and validate a raw JWT string.

    Splits the token into its three segments, Base64URL-decodes each,
    and parses the header and payload as JSON. Returns a structured
    dictionary containing all decoded components alongside metadata
    useful for downstream attack and analysis modules.

    Arg in is the raw JWT string to decode 

    Args out is a dictionary with the following keys: raw (the
    original token string), header (the decoded JOSE header), 
    payload (the decoded claims payload), signature_b64 (the raw
    Base64URL-encoded signature segment), signature_bytes,
    algorithm (the signing algorithm declared in the header), 
    token_type, signing_input (the raw 
    '<header_b64>.<payload_b64>' string used as the signing 
    input), and is_alg_none (true if the declared algorithm is
    none).

    Raises JWTDecodeError is the token is malformed, not a string,
    empty, wrong amount of segments, or has invalid Base64 or JSON
    """
    # Input validation
    if not isinstance(token, str):
        raise JWTDecodeError(
            f"Expected a string token, got {type(token).__name__}."
        )

    token = token.strip()

    if not token:
        raise JWTDecodeError("Token is empty.")

    # Split into segments
    parts = token.split('.')

    if len(parts) != 3:
        raise JWTDecodeError(
            f"A JWT must have exactly 3 segments separated by full stops, or '.', "
            f"but {len(parts)} segment(s) were found. "
            f"This probably isn't a JWT."
        )

    header_b64, payload_b64, signature_b64 = parts

    # Decode header and payload
    header_bytes  = _decode_b64url(header_b64,  'header')
    payload_bytes = _decode_b64url(payload_b64, 'payload')

    header  = _parse_json(header_bytes,  'header')
    payload = _parse_json(payload_bytes, 'payload')

    # Validate header fields
    if 'alg' not in header:
        raise JWTDecodeError(
            "The JWT header is missing the required 'alg' field."
        )

    # Decode signature
    if signature_b64 == '':
        signature_bytes = b''
    else:
        signature_bytes = _decode_b64url(signature_b64, 'signature')

    # Extract metadata
    algorithm   = str(header.get('alg', '')).upper()
    token_type  = str(header.get('typ', 'UNKNOWN')).upper()
    is_alg_none = algorithm == 'NONE'

    signing_input = f"{header_b64}.{payload_b64}"

    # Return structured result
    return {
        'raw':            token,
        'header':         header,
        'payload':        payload,
        'signature_b64':  signature_b64,
        'signature_bytes': signature_bytes,
        'algorithm':      algorithm,
        'token_type':     token_type,
        'signing_input':  signing_input,
        'is_alg_none':    is_alg_none,
    }


def pretty_print(decoded):
    """
    Print a human-readable summary of a decoded JWT to stdout.

    Supposed to be used for use with the --verbose flag in the CLI. 
    Displays the header and payload as indented JSON, the algorithm, 
    token type, and whether the signature is present.

    Argument is the output of decode()
    """
    print("\n── JWT Decoded ─────────────────────────────────────────")
    print(f"  Algorithm  : {decoded['algorithm']}")
    print(f"  Token Type : {decoded['token_type']}")
    print(f"  Signature  : {'(empty — alg:none)' if decoded['is_alg_none'] else '(present)'}")

    print("\n  Header:")
    for line in json.dumps(decoded['header'], indent=4).splitlines():
        print(f"    {line}")

    print("\n  Payload:")
    for line in json.dumps(decoded['payload'], indent=4).splitlines():
        print(f"    {line}")

    print("────────────────────────────────────────────────────────\n")