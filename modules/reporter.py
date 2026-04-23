"""
reporter.py - findings aggregation and report rendering

collects findings from all analysis modules and renders them
as a structured report in plain-text or JSON format.

severity levels (highest to lowest):
    CRITICAL  - immediate exploitation possible
    HIGH      - significant vulnerability, likely exploitable
    MEDIUM    - notable weakness, may be exploitable in context
    LOW       - minor issue, defence in depth concern
    INFO      - informational, no direct vulnerability

the overall risk score is determined by the highest severity
finding across all modules.

Author: Patrick Earley
Module: CMP320 Advanced Ethical Hacking
"""

import json
import sys
from datetime import datetime, timezone


# severity ordering for sorting and scoring
SEVERITY_ORDER = {
    'CRITICAL': 0,
    'HIGH':     1,
    'MEDIUM':   2,
    'LOW':      3,
    'INFO':     4,
}

# fields from findings that shouldn't appear in plain-text output
# (they're too long/complex - shown in JSON only)
VERBOSE_FIELDS = {'forged_token', 'forged_tokens', 'jwk', 'kid', 'jku', 'x5u'}


def _overall_risk(all_findings):
    """
    determine the overall risk level from a flat list of findings.
    returns the highest severity present.
    """
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        if any(f['severity'] == severity for f in all_findings):
            return severity
    return 'INFO'


def _sort_findings(findings):
    # sort findings by severity, highest first.
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f['severity'], 99))


def _severity_badge(severity):
    # return a plain-text badge for a severity level.
    badges = {
        'CRITICAL': '[CRITICAL]',
        'HIGH':     '[HIGH]    ',
        'MEDIUM':   '[MEDIUM]  ',
        'LOW':      '[LOW]     ',
        'INFO':     '[INFO]    ',
    }
    return badges.get(severity, '[UNKNOWN] ')


def build_report(decoded, module_findings, elapsed=None):
    """
    build a structured report dictionary from all module findings.

    args:
        decoded:         output of decoder.decode()
        module_findings: dict mapping module name to its findings list
                         e.g. {'claim_analyser': [...], 'brute_force': [...]}
        elapsed:         optional float of seconds the scan took

    returns a report dict ready for render_text() or render_json().
    """
    # flatten all findings into one list for scoring
    all_findings = []
    for findings in module_findings.values():
        all_findings.extend(findings)

    return {
        'meta': {
            'tool':      'JWBreaker',
            'version':   '1.0.0',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'elapsed':   f"{elapsed:.2f}s" if elapsed else None,
        },
        'token': {
            'algorithm':  decoded['algorithm'],
            'token_type': decoded['token_type'],
            'header':     decoded['header'],
            'payload':    decoded['payload'],
        },
        'risk':     _overall_risk(all_findings),
        'summary':  _summarise(all_findings),
        'findings': {
            module: _sort_findings(findings)
            for module, findings in module_findings.items()
        }
    }


def _summarise(all_findings):
    # count findings by severity.
    summary = {s: 0 for s in SEVERITY_ORDER}
    for f in all_findings:
        if f['severity'] in summary:
            summary[f['severity']] += 1
    return summary


def render_text(report, verbose=False):
    """
    render a report as a human-readable plain-text string.

    if verbose is True, includes forged tokens and other long fields
    that are hidden by default.
    """
    lines = []
    sep  = '=' * 60
    thin = '-' * 60

    # header
    lines.append(sep)
    lines.append("  JWBreaker — JWT Security Audit Report")
    lines.append(sep)
    lines.append(f"  Timestamp : {report['meta']['timestamp']}")
    if report['meta']['elapsed']:
        lines.append(f"  Scan time : {report['meta']['elapsed']}")
    lines.append(f"  Algorithm : {report['token']['algorithm']}")
    lines.append(f"  Overall   : {report['risk']}")
    lines.append(thin)

    # summary counts
    lines.append("  Finding summary:")
    for severity, count in report['summary'].items():
        if count > 0:
            lines.append(f"    {_severity_badge(severity)}  {count} finding(s)")
    lines.append(sep)

    # token info
    lines.append("  Token Header:")
    for line in json.dumps(report['token']['header'], indent=4).splitlines():
        lines.append(f"    {line}")
    lines.append("  Token Payload:")
    for line in json.dumps(report['token']['payload'], indent=4).splitlines():
        lines.append(f"    {line}")
    lines.append(sep)

    # findings by module
    for module, findings in report['findings'].items():
        if not findings:
            continue
        lines.append(f"  Module: {module}")
        lines.append(thin)
        for f in findings:
            lines.append(f"  {_severity_badge(f['severity'])} {f['title']}")
            lines.append(f"    {f['description']}")

            # show extra fields in verbose mode
            if verbose:
                for field in VERBOSE_FIELDS:
                    if field in f:
                        val = f[field]
                        if isinstance(val, (dict, list)):
                            lines.append(f"    {field}:")
                            for l in json.dumps(val, indent=6).splitlines():
                                lines.append(f"      {l}")
                        else:
                            lines.append(f"    {field}: {val}")
            else:
                # always show forged tokens even without verbose
                # (they're the main output the user wants to see)
                for field in ['forged_token', 'cracked_secret']:
                    if field in f:
                        lines.append(f"    {field}: {f[field]}")

            lines.append("")
        lines.append(sep)

    return '\n'.join(lines)


def render_json(report):
    # render a report as a pretty-printed JSON string.
    return json.dumps(report, indent=2, default=str)


def write_report(content, output_path=None):
    """
    write report content to a file or stdout.

    if output_path is None or '-', writes to stdout.
    otherwise writes to the specified file path.
    """
    if not output_path or output_path == '-':
        print(content)
        return

    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"[+] Report written to {output_path}")
    except Exception as e:
        print(f"[!] Failed to write report to '{output_path}': {e}", file=sys.stderr)
        print(content)