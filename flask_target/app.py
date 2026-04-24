"""
flask_target/app.py - intentionally vulnerable JWT target

a deliberately insecure Flask application for testing JWBreaker.
do NOT deploy this anywhere. it is intentionally vulnerable.

vulnerabilities implemented:
    - weak HMAC secret ('secret')
    - accepts alg:none tokens
    - no audience validation
    - accepts expired tokens
    - sensitive data in JWT payload (email)

endpoints:
    POST /login         - issues a JWT for a given username
    GET  /protected     - requires any valid JWT
    GET  /admin         - requires role=admin in the token

usage:
    pip install flask pyjwt
    python flask_target/app.py

Author: Patrick Earley
Module: CMP320 Advanced Ethical Hacking
"""

from flask import Flask, request, jsonify
import jwt
import datetime

app = Flask(__name__)

# deliberately weak secret - should be a long random string in production
JWT_SECRET = 'secret'
JWT_ALGORITHM = 'HS256'

# fake user database
USERS = {
    'alice': {'password': 'password123', 'role': 'user',  'email': 'alice@example.com'},
    'bob':   {'password': 'letmein',     'role': 'user',  'email': 'bob@example.com'},
    'admin': {'password': 'admin123',    'role': 'admin', 'email': 'admin@example.com'},
}


def decode_token(token):
    """
    decode and verify a JWT token.

    intentionally vulnerable:
        - accepts alg:none (no algorithm enforcement)
        - does not verify expiry
        - does not validate audience
    """
    try:
        # vulnerability 1: trusts the algorithm declared in the header
        # rather than enforcing a specific expected algorithm
        header = jwt.get_unverified_header(token)
        algorithm = header.get('alg', JWT_ALGORITHM)

        # vulnerability 2: alg:none accepted - no signature verification
        if algorithm.lower() == 'none':
            decoded = jwt.decode(
                token,
                options={
                    'verify_signature': False,
                    'verify_exp': False,        # vulnerability 3: expiry not checked
                    'verify_aud': False,        # vulnerability 4: audience not checked
                }
            )
            return decoded, None

        # vulnerability 5: expiry not enforced even for signed tokens
        decoded = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[algorithm],
            options={
                'verify_exp': False,            # expired tokens accepted
                'verify_aud': False,            # audience not checked
            }
        )
        return decoded, None

    except jwt.InvalidTokenError as e:
        return None, str(e)
    except Exception as e:
        return None, str(e)


# routes

@app.route('/login', methods=['POST'])
def login():
    """
    issue a JWT for a valid username/password combination.

    vulnerability: email address included in the token payload
    (sensitive data that shouldn't be in an unencrypted JWT).
    """
    data = request.get_json(silent=True) or {}
    username = data.get('username', '')
    password = data.get('password', '')

    user = USERS.get(username)
    if not user or user['password'] != password:
        return jsonify({'error': 'Invalid credentials'}), 401

    payload = {
        'sub':   username,
        'role':  user['role'],
        'email': user['email'],        # vulnerability: PII in token
        'iat':   datetime.datetime.utcnow(),
        'exp':   datetime.datetime.utcnow() + datetime.timedelta(hours=1),
    }

    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return jsonify({'token': token}), 200


@app.route('/protected', methods=['GET'])
def protected():
    """
    returns a welcome message for any valid JWT holder.
    """
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Missing or invalid Authorization header'}), 401

    token = auth_header[len('Bearer '):]
    decoded, error = decode_token(token)

    if error:
        return jsonify({'error': f'Token rejected: {error}'}), 401

    return jsonify({
        'message': f"Welcome, {decoded.get('sub', 'unknown')}!",
        'role':    decoded.get('role', 'unknown'),
        'email':   decoded.get('email', 'not provided'),
    }), 200


@app.route('/admin', methods=['GET'])
def admin():
    """
    returns admin panel access for tokens with role=admin.
    """
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Missing or invalid Authorization header'}), 401

    token = auth_header[len('Bearer '):]
    decoded, error = decode_token(token)

    if error:
        return jsonify({'error': f'Token rejected: {error}'}), 401

    if decoded.get('role') != 'admin': 
        return jsonify({'error': 'Access denied - admin role required'}), 403

    return jsonify({
        'message': 'Admin panel access granted',
        'user':    decoded.get('sub', 'unknown'),
        'role':    decoded.get('role'),
    }), 200


@app.route('/', methods=['GET'])
def index():
    return jsonify({
        'app':       'JWBreaker Vulnerable Target',
        'warning':   'intentionally vulnerable - do not deploy',
        'endpoints': {
            'POST /login':     'get a JWT (body: {"username": "alice", "password": "password123"})',
            'GET /protected':  'access with any valid JWT (Authorization: Bearer <token>)',
            'GET /admin':      'access with role=admin JWT (Authorization: Bearer <token>)',
        }
    }), 200


if __name__ == '__main__':
    print("=" * 55)
    print("  JWBreaker Vulnerable Target")
    print("  WARNING: intentionally insecure - do not deploy")
    print("  Running on http://127.0.0.1:5000")
    print("=" * 55)
    app.run(debug=False, port=5000)