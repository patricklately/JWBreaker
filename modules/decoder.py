"""
decoder.py - for jwt decoding and structural validation

jwts are made of three base64url-encoded segments separated by
full stops: <header>.<payload>.<signature>

the header and payload are json objects. the signature is raw bytes.

Author: Patrick Earley
Module: CMP320 Advanced Ethical Hacking
"""

import base64
import json


# custom exceptions

class JWTDecodeError(Exception):
    """raised when a JWT cannot be decoded due to structural or
    formatting issues. provides a human-readable message suitable
    for display in the CLI and report output."""
    pass


# internal helpers

def _pad(b64_string):
    """
    requires padding with '=' characters to make the length a 
    multiple of 4. JWT drops this padding so here we must restore
    it before decoding.

    in goes a Base64URL-encoded string without padding, 
    and out comes the same string with the correct padding restored.
    """
    # calculate how many padding characters are needed
    padding_needed = 4 - len(b64_string) % 4
    if padding_needed != 4:
        b64_string += '=' * padding_needed
    return b64_string


def _decode_b64url(b64_string, label):
    """
    handles both standard base64 and url-safe base64 which replaces
    '+' with '-' and '/' with '_'.

    arguments in are the Base64URL segment to decode, and a
    human-readable label for error messages, and out is the
    decoded raw bytes. Raises jwtdecodeerror if the segment cannot
    be base64 decoded.
    """
    try:
        return base64.urlsafe_b64decode(_pad(b64_string))
    except Exception as e:
        raise JWTDecodeError(
            f"failed to base64url-decode the {label} segment: {e}"
        )


def _parse_json(raw_bytes, label):
    """
    parse raw bytes as a utf-8 json object.

    in args are the decoded bytes and a readable label, out is the
    parsed json object. Raises jwtdecodererror if the bytes cannot
    be decoded as utf-8 or parsed as valid json
    """
    try:
        return json.loads(raw_bytes.decode('utf-8'))
    except UnicodeDecodeError:
        raise JWTDecodeError(
            f"the {label} segment is not valid utf-8."
        )
    except json.JSONDecodeError as e:
        raise JWTDecodeError(
            f"the {label} segment is not valid json: {e}"
        )


# public interface

def decode(token):
    """
    decode and validate a raw JWT string.

    splits the token into its three segments, base64url-decodes each,
    and parses the header and payload as json.

    arg in is the raw JWT string to decode 

    args out is a dictionary with the following keys: raw (the
    original token string), header (the decoded jose header), 
    payload (the decoded claims payload), signature_b64 (the raw
    base64url-encoded signature segment), signature_bytes,
    algorithm (the signing algorithm declared in the header), 
    token_type, signing_input (the raw 
    '<header_b64>.<payload_b64>' string used as the signing 
    input), and is_alg_none (true if the declared algorithm is
    none).

    raises jwtdecodeerror is the token is malformed, not a string,
    empty, wrong amount of segments, or has invalid base64 or json
    """
    # input validation
    if not isinstance(token, str):
        raise JWTDecodeError(
            f"expected a string token, got {type(token).__name__}."
        )

    token = token.strip()

    if not token:
        raise JWTDecodeError("token is empty.")

    # split into segments
    parts = token.split('.')

    if len(parts) != 3:
        raise JWTDecodeError(
            f"a jwt must have exactly 3 segments separated by full stops, or '.', "
            f"but {len(parts)} segment(s) were found. "
            f"this probably isn't a jwt."
        )

    header_b64, payload_b64, signature_b64 = parts

    # decode header and payload
    header_bytes  = _decode_b64url(header_b64,  'header')
    payload_bytes = _decode_b64url(payload_b64, 'payload')

    header  = _parse_json(header_bytes,  'header')
    payload = _parse_json(payload_bytes, 'payload')

    # validate header fields
    if 'alg' not in header:
        raise JWTDecodeError(
            "the jwt header is missing the required 'alg' field."
        )

    # decode signature
    if signature_b64 == '':
        signature_bytes = b''
    else:
        signature_bytes = _decode_b64url(signature_b64, 'signature')

    # Extract metadata
    algorithm   = str(header.get('alg', '')).upper()
    token_type  = str(header.get('typ', 'UNKNOWN')).upper()
    is_alg_none = algorithm == 'NONE'

    signing_input = f"{header_b64}.{payload_b64}"

    # return structured result
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
    print a human-readable summary of a decoded JWT to stdout.

    supposed to be used for use with the --verbose flag in the CLI. 
    displays the header and payload as indented json, the algorithm, 
    token type, and whether the signature is present.

    argument is the output of decode()
    """
    print("\n=== jwt Decoded =========================================")
    print(f"  algorithm  : {decoded['algorithm']}")
    print(f"  token Type : {decoded['token_type']}")
    print(f"  signature  : {'(empty - alg:none)' if decoded['is_alg_none'] else '(present)'}")

    print("\n  header:")
    for line in json.dumps(decoded['header'], indent=4).splitlines():
        print(f"    {line}")

    print("\n  payload:")
    for line in json.dumps(decoded['payload'], indent=4).splitlines():
        print(f"    {line}")

    print("========================================================\n")