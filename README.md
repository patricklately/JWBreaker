# JWBreaker
A command-line JWT security auditing tool written in Python. JWBreaker automates the kind of token security review a penetration tester would perform manually, such as decoding, attacking, and reporting on JSON Web Tokens for a wide range of known vulnerability classes.
## Features
* alg:none bypass - detects tokens accepted without a signature (CVE-2015-9235)
* algorithm confusion - RS256 -> HS256 attack using a supplied public key
* HMAC brute-force - dictionary attack with mutation rules and multi-threading
* JWK header injection - detects embedded attacker-controlled public keys (CVE-2018-0114)
* kid injection - flags path traversal, SQLi, and command injection in the kid parameter
* claim analysis - validates exp, iss, aud, nbf, iat against RFC 7519
* sensitive data detection - regex scanning for PII, API keys, and bearer tokens in payloads
* entropy scoring - Shannon entropy rating of any recovered HMAC secret
* token forgery - forge a new signed token with modified claims post-exploitation
* batch mode - audit multiple tokens from a file in a single run
* structured reporting - output the findings as plain-text or JSON with severity ratings
## Installation
### Prerequisites
* Python 3.8 or more recent
* Docker (optional, but recommended)
## Local Installation
```
git clone https://github.com/patricklately/JWBreaker.git
cd JWBreaker
python -m venv venv

# Windows
venv\Scripts\activate

# macOS/Linux
source venv/bin/activate

pip install -r requirements.txt
```
### Docker
```
docker build -t jwbreaker .
docker run --rm jwbreaker --help

# Docker Compose
docker-compose run jwbreaker --help
```
## Usage
```
usage: jwbreaker.py [-h] (-t TOKEN | -f FILE) [-w WORDLIST] [-k PUBKEY]
                    [-o OUTPUT] [--format {txt,json}] [--forge CLAIM=VALUE]
                    [--threads N] [--verbose] [--batch]

options:
  -h, --help            Show this help message and exit
  -t, --token           JWT string to audit
  -f, --file            Path to file containing a token (or tokens with --batch)
  -w, --wordlist        Path to wordlist for brute-force attack
  -k, --pubkey          Path to RSA public key file (for algorithm confusion attack)
  -o, --output          Output file path for report (default: stdout)
  --format {txt,json}   Report output format (default: txt)
  --forge CLAIM=VALUE   Forge a new token with a modified claim after successful attack
  --threads N           Number of brute-force threads (default: 4)
  --verbose             Show step-by-step module output
  --batch               Treat --file input as newline-separated list of token
  ```
## Examples
### Decode and audit a token:
```
python jwbreaker.py -t eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```
### Brute-force with a wordlist:
```
python jwbreaker.py -t <token> -w wordlists/common_secrets.txt
```
### Algorithm confusion attack:
```
python jwbreaker.py -t <token> -k public.pem
```
### Forge a token after cracking:
```
python jwbreaker.py -t <token> -w wordlists/common_secrets.txt --forge role=admin
```
### Audit multiple tokens and save a JSON report:
```
python jwbreaker.py -f tokens.txt --batch --format json -o report.json
```
### Run with Docker:
```
docker run --rm -v "${PWD}:/data" jwbreaker -f /data/tokens.txt --batch --format json -o /data/report.json
```
## Modules
* decoder.py - Base64URL decodes and validates JWT structure
* alg_none.py - Tests the alg:none signature bypass
* alg_confusion.py - RS256 -> HS256 algorithm confusion attack
* brute_force.py - Multithreaded dictionary attack with mutation rules
* entropy.py - Shannon entropy scoring of recovered secrets
* claim_analyser - RFC 7519 claim validation and anomaly detection
* sensitive_data.py - Regex-based PII and secret detection in payload
* jwk_injection - JWK header injection detection (CVE-2018-0114)
* kid_injection.py - kid parameter injection pattern analysis
* forgery.py - Post-exploitation token forging
* reporter.py - Severity-rating findings aggregation and output
## Ethical Usage
JWBreaker operates entirely on tokens supplied by the user. It performs no network scanning, credential harvesting, or interaction with live systems without explicit user instruction. This tool is intended for:

* Penetration testing of systems you have explicit permission to test
* Defensive security assessment
* Educational and research purposes

**Do not use this tool against systems you do not own or have written permission to test.**
## Dependencies
* cryptography - RSA keyhandling for algorithm confusion attack
* PyJWT - Token generation for forgery module
* requests - HTTP calls for optional API integrations
Everything else is uses Python stdlib dependencies.
## References
* Jones, M., Bradley, J. and Sakimura, N. (2015) JSON Web Token (JWT). RFC 7519. IETF
* Sheffer, Y., Hardt, D. and Jones, M. (2020) JSON Web Token Best Current Practices. RFC 8725. IETF.
* McLean, T. (2015) 'Critical vulnerabilities in JSON Web Token libraries'. Auth0 Blog.
* Yang, J. et al. (2026) 'Token Time Bomb: Evaluating JWT Implementations for Vulnerability Discovery'. NDSS 2026.
* PortSwigger (no date) 'JWT attacks'. Web Security Academy.
* OWASP (no date) 'Testing JSON Web Tokens (WSTG-SESS-10)'. OWASP WSTG.