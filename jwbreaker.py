"""
jwbreaker.py - JWBreaker CLI entry point

Main entry point for JWBreaker. Handles argument parsing,
orchestrates module execution, and produces the final report.

usage:
    python jwbreaker.py -t <token> [options]
    python jwbreaker.py -f <file> [options]
    python jwbreaker.py -f <file> --batch [options]

Author: Patrick Earley
Module: CMP320 Advanced Ethical Hacking
"""

import argparse
import sys
import time

from modules.decoder import decode, pretty_print, JWTDecodeError
from modules.claim_analyser import analyse as analyse_claims
from modules.sensitive_data import analyse as analyse_sensitive
from modules.alg_none import analyse as analyse_alg_none
from modules.brute_force import analyse as analyse_brute
from modules.entropy import analyse as analyse_entropy
from modules.jwk_injection import analyse as analyse_jwk
from modules.kid_injection import analyse as analyse_kid
from modules.alg_confusion import analyse as analyse_confusion
from modules.forgery import forge
from modules.reporter import build_report, render_text, render_json, write_report


# argument parser

def build_parser():
    parser = argparse.ArgumentParser(
        prog='jwbreaker',
        description='JWBreaker - JWT Security Auditing Tool',
        epilog='Example: python jwbreaker.py -t <token> -w wordlists/common_secrets.txt --forge role=admin',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # token input - mutually exclusive
    token_group = parser.add_mutually_exclusive_group(required=True)
    token_group.add_argument(
        '-t', '--token',
        metavar='TOKEN',
        help='JWT string to audit'
    )
    token_group.add_argument(
        '-f', '--file',
        metavar='FILE',
        help='path to file containing a token (or tokens with --batch)'
    )

    # attack options
    parser.add_argument(
        '-w', '--wordlist',
        metavar='WORDLIST',
        help='path to wordlist for brute-force attack'
    )
    parser.add_argument(
        '-k', '--pubkey',
        metavar='PUBKEY',
        help='path to RSA public key PEM file (for algorithm confusion attack)'
    )

    # forgery
    parser.add_argument(
        '--forge',
        metavar='CLAIM=VALUE',
        action='append',
        dest='forge_mods',
        help='forge a new token with a modified claim (repeatable, e.g. --forge role=admin --forge sub=attacker)'
    )

    # output options
    parser.add_argument(
        '-o', '--output',
        metavar='OUTPUT',
        help='output file path for report (default: stdout)'
    )
    parser.add_argument(
        '--format',
        choices=['txt', 'json'],
        default='txt',
        help='report output format (default: txt)'
    )

    # behaviour flags
    parser.add_argument(
        '--threads',
        type=int,
        default=4,
        metavar='N',
        help='number of brute-force threads (default: 4)'
    )
    parser.add_argument(
        '--batch',
        action='store_true',
        help='treat --file as a newline-separated list of tokens and audit all'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='show step-by-step module output and forged tokens inline'
    )

    return parser


# token loading

def load_token(args):
    """
    load a single token string from --token or --file.
    returns the raw token string.
    """
    if args.token:
        return args.token.strip()

    try:
        with open(args.file, 'r', encoding='utf-8') as f:
            content = f.read().strip()
        # if batch mode, this will be handled separately
        # here just return the first non-comment line
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith('#') and not line.startswith('['):
                return line
        print("[!] No token found in file.", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print(f"[!] File not found: '{args.file}'", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[!] Failed to read file: {e}", file=sys.stderr)
        sys.exit(1)


def load_batch_tokens(file_path):
    """
    load multiple tokens from a file for batch mode.

    accepts both plain token files (one per line) and the
    labelled format used in tests/sample_tokens.txt.
    skips blank lines, comments (#), and label lines ([label]).
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"[!] File not found: '{file_path}'", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[!] Failed to read file: {e}", file=sys.stderr)
        sys.exit(1)

    tokens = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('['):
            continue
        tokens.append(line)

    if not tokens:
        print("[!] No tokens found in file.", file=sys.stderr)
        sys.exit(1)

    return tokens


# single token audit

def audit_token(token_str, args):
    """
    run the full audit pipeline on a single token string.

    decodes the token, runs all relevant modules, handles forgery
    if requested, and returns a completed report dict.
    """
    start = time.time()

    # decode
    try:
        decoded = decode(token_str)
    except JWTDecodeError as e:
        print(f"[!] Failed to decode token: {e}", file=sys.stderr)
        return None

    if args.verbose:
        pretty_print(decoded)

    # run all analysis modules
    module_findings = {}

    module_findings['claim_analyser'] = analyse_claims(decoded)
    module_findings['sensitive_data'] = analyse_sensitive(decoded)
    module_findings['alg_none']       = analyse_alg_none(decoded)
    module_findings['jwk_injection']  = analyse_jwk(decoded)
    module_findings['kid_injection']  = analyse_kid(decoded)
    module_findings['alg_confusion']  = analyse_confusion(decoded, pubkey_path=args.pubkey)

    # brute force
    brute_findings = analyse_brute(
        decoded,
        wordlist_path=args.wordlist,
        threads=args.threads
    )
    module_findings['brute_force'] = brute_findings

    # entropy - only if a secret was cracked
    cracked_secret = next(
        (f.get('cracked_secret') for f in brute_findings if 'cracked_secret' in f),
        None
    )
    if cracked_secret is not None:
        module_findings['entropy'] = analyse_entropy(cracked_secret)

    # forgery - only if modifications were requested and we have a signing method
    if args.forge_mods:
        use_alg_none = decoded['is_alg_none']
        module_findings['forgery'] = forge(
            decoded,
            modifications=args.forge_mods,
            cracked_secret=cracked_secret,
            use_alg_none=use_alg_none
        )

    elapsed = time.time() - start
    return build_report(decoded, module_findings, elapsed=elapsed)


# entry point
# ABANDON HOPE ALL YE WHO ENTER HERE

def main():
    parser = build_parser()
    args = parser.parse_args()

    # batch mode
    if args.batch:
        if not args.file:
            print("[!] --batch requires --file", file=sys.stderr)
            sys.exit(1)

        tokens = load_batch_tokens(args.file)
        print(f"[*] Batch mode: {len(tokens)} token(s) loaded")

        reports = []
        for i, token_str in enumerate(tokens, 1):
            print(f"[*] Auditing token {i}/{len(tokens)}...")
            report = audit_token(token_str, args)
            if report:
                reports.append(report)

        if not reports:
            print("[!] No valid tokens were audited.", file=sys.stderr)
            sys.exit(1)

        # render batch output
        if args.format == 'json':
            import json
            output = json.dumps(reports, indent=2, default=str)
        else:
            output = '\n\n'.join(
                render_text(r, verbose=args.verbose) for r in reports
            )

        write_report(output, args.output)
        return

    # single token mode
    token_str = load_token(args)
    report = audit_token(token_str, args)

    if not report:
        sys.exit(1)

    if args.format == 'json':
        output = render_json(report)
    else:
        output = render_text(report, verbose=args.verbose)

    write_report(output, args.output)


if __name__ == '__main__':
    main()