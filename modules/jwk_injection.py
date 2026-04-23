"""
jwk_injection.py - jwk header injection detection

detects the presence of attacker-controlled key material embedded
directly in the JWT header (CVE-2018-0114).

two related attack vectors are checked:
    - jwk: an attacker embeds their own public key directly in the
      header. vulnerable servers use this key to verify the signature
      instead of their own trusted key, accepting any token the
      attacker signs with the matching private key.

    - jku: the header contains a URL pointing to a jwk set. a 
      vulnerable server fetches keys from this URL, which an attacker
      can point to a server they control.

Author: Patrick Earley
Module: CMP320 Advanced Ethical Hacking
"""


def analyse(decoded):
    """
    check the JWT header for JWK injection attack vectors.

    arg in is the output of decoder.decode(). returns a list of
    finding dicts with severity, title, and description.
    """
    findings = []
    header = decoded['header']

    # jwk header parameter - embedded public key
    if 'jwk' in header:
        jwk = header['jwk']

        # check it looks like an actual key object
        if isinstance(jwk, dict):
            kty = jwk.get('kty', 'unknown')
            findings.append({
                'severity': 'CRITICAL',
                'title': "JWK header injection detected (CVE-2018-0114)",
                'description': (
                    f"The JWT header contains an embedded JWK public key "
                    f"(kty: {kty}). Vulnerable implementations verify the "
                    f"token signature using this attacker-supplied key instead "
                    f"of the server's trusted key. An attacker can generate "
                    f"their own RSA key pair, embed the public key in the header, "
                    f"sign the token with their private key, and the server will "
                    f"accept it as valid. This allows complete authentication bypass "
                    f"and arbitrary claim forgery."
                ),
                'jwk': jwk
            })
        else:
            # jwk is present but malformed
            findings.append({
                'severity': 'HIGH',
                'title': "Malformed JWK parameter in header",
                'description': (
                    f"The JWT header contains a 'jwk' parameter but its value "
                    f"is not a valid JSON object. This may indicate a failed "
                    f"injection attempt or a misconfigured implementation."
                )
            })

    # jku header parameter - remote JWK set url
    if 'jku' in header:
        jku = header['jku']
        findings.append({
            'severity': 'HIGH',
            'title': "JKU header parameter present",
            'description': (
                f"The JWT header contains a 'jku' (JWK Set URL) parameter "
                f"pointing to: '{jku}'. Vulnerable servers fetch verification "
                f"keys from this URL at runtime. If an attacker can control "
                f"this URL, they can point it to their own JWK set and have "
                f"the server verify tokens with attacker-controlled keys. "
                f"Servers should only accept JKU values from a strict allowlist."
            ),
            'jku': jku
        })

    # x5u header parameter - similar vector using X.509 certificates
    if 'x5u' in header:
        x5u = header['x5u']
        findings.append({
            'severity': 'HIGH',
            'title': "X5U header parameter present",
            'description': (
                f"The JWT header contains an 'x5u' (X.509 URL) parameter "
                f"pointing to: '{x5u}'. Similar to the JKU attack, a vulnerable "
                f"server fetching certificates from this URL could be redirected "
                f"to attacker-controlled certificate material."
            ),
            'x5u': x5u
        })

    # x5c header parameter - embedded certificate chain
    if 'x5c' in header:
        findings.append({
            'severity': 'MEDIUM',
            'title': "X5C header parameter present",
            'description': (
                "The JWT header contains an 'x5c' (X.509 certificate chain) "
                "parameter. Servers that blindly trust the certificate chain "
                "embedded here without validating against a trusted root are "
                "vulnerable to certificate injection attacks."
            )
        })

    if not findings:
        findings.append({
            'severity': 'INFO',
            'title': "No JWK injection vectors detected",
            'description': (
                "The header contains no jwk, jku, x5u, or x5c parameters."
            )
        })

    return findings