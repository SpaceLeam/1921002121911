"""
Comprehensive Flask test server for TfaBuster validation.
Simulates various 2FA vulnerabilities and security scenarios.
"""
from flask import Flask, request, jsonify, make_response
import time
import hashlib
from datetime import datetime
from threading import Lock

app = Flask(__name__)

# Global state for rate limiting and session tracking
request_tracker = {}
session_store = {}
rate_limit_lock = Lock()

# Valid OTP for testing (in production this would be dynamic)
VALID_OTP = "1337"
ADMIN_BACKDOOR = "0000"


def track_request(endpoint: str):
    """Track requests for rate limiting simulation."""
    with rate_limit_lock:
        now = time.time()
        key = f"{request.remote_addr}:{endpoint}"
        
        if key not in request_tracker:
            request_tracker[key] = []
        
        # Clean old entries (> 60 seconds)
        request_tracker[key] = [t for t in request_tracker[key] if now - t < 60]
        request_tracker[key].append(now)
        
        return len(request_tracker[key])


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({"status": "healthy", "server": "TfaBuster Test Lab"}), 200


# ===== VULNERABLE ENDPOINTS =====

@app.route('/api/verify-basic', methods=['POST'])
def verify_basic():
    """Basic 2FA endpoint - multiple vulnerabilities."""
    data = request.get_json(force=True, silent=True) or {}
    otp = data.get('otp')
    
    # 1. Missing parameter bypass
    if 'otp' not in data:
        return jsonify({
            "status": "success",
            "message": "Bypassed: Missing parameter",
            "vulnerability": "CWE-306"
        }), 200
    
    # 2. Null bypass
    if otp is None:
        return jsonify({
            "status": "success",
            "message": "Bypassed: Null value",
            "vulnerability": "CWE-20"
        }), 200
    
    # 3. Array injection
    if isinstance(otp, list):
        return jsonify({
            "status": "success",
            "message": "Bypassed: Array type juggling",
            "vulnerability": "CWE-843"
        }), 200
    
    # 4. Boolean bypass
    if otp is True or otp is False:
        return jsonify({
            "status": "success",
            "message": "Bypassed: Boolean type",
            "vulnerability": "CWE-843"
        }), 200
    
    # 5. Admin backdoor
    if str(otp) == ADMIN_BACKDOOR:
        return jsonify({
            "status": "success",
            "message": "Backdoor OTP accepted",
            "access_token": "admin_token_12345"
        }), 200
    
    # Valid OTP
    if str(otp) == VALID_OTP:
        return jsonify({
            "status": "success",
            "message": "Valid OTP",
            "access_token": "token_" + hashlib.md5(str(time.time()).encode()).hexdigest()
        }), 200
    
    return jsonify({"status": "fail", "message": "Invalid OTP"}), 403


@app.route('/api/verify-csrf', methods=['POST'])
def verify_csrf():
    """CSRF vulnerable endpoint - no session validation."""
    data = request.get_json(force=True, silent=True) or {}
    
    # Vulnerable: No cookie/session check
    # Should require valid session cookie but doesn't
    return jsonify({
        "status": "success", 
        "message": "No CSRF protection",
        "vulnerability": "CWE-352"
    }), 200


@app.route('/api/verify-rate-limited', methods=['POST'])
def verify_rate_limited():
    """Rate limited endpoint - test adaptive retry."""
    count = track_request('rate-limited')
    
    # Simulate rate limit after 5 requests per minute
    if count > 5:
        response = make_response(jsonify({
            "error": "Rate limit exceeded"
        }), 429)
        response.headers['Retry-After'] = '10'  # Wait 10 seconds
        return response
    
    data = request.get_json(force=True, silent=True) or {}
    otp = data.get('otp')
    
    if str(otp) == VALID_OTP:
        return jsonify({"status": "success"}), 200
    
    return jsonify({"status": "fail"}), 403


@app.route('/api/verify-waf-protected', methods=['POST'])
def verify_waf_protected():
    """Simulates WAF protection - blocks automated tools."""
    user_agent = request.headers.get('User-Agent', '')
    
    # Block obvious bot user agents
    bot_indicators = ['python', 'curl', 'wget', 'bot', 'scanner']
    if any(indicator in user_agent.lower() for indicator in bot_indicators):
        return jsonify({
            "error": "Access denied",
            "waf": "Cloudflare",
            "ray_id": "fake-ray-id-12345"
        }), 403
    
    data = request.get_json(force=True, silent=True) or {}
    otp = data.get('otp')
    
    if str(otp) == VALID_OTP:
        return jsonify({"status": "success"}), 200
    
    return jsonify({"status": "fail"}), 403


@app.route('/api/verify-timing', methods=['POST'])
def verify_timing():
    """Timing-based detection - fast response = bypass."""
    data = request.get_json(force=True, silent=True) or {}
    otp = data.get('otp')
    
    # Fast path (bypass) - no DB check
    if otp is None or 'otp' not in data:
        return jsonify({"status": "success", "timing": "fast"}), 200
    
    # Slow path (normal) - simulate DB check
    time.sleep(0.2)
    
    if str(otp) == VALID_OTP:
        return jsonify({"status": "success", "timing": "normal"}), 200
    
    return jsonify({"status": "fail"}), 403


@app.route('/api/verify-json-response', methods=['POST'])
def verify_json_response():
    """Test JSON structure changes detection."""
    data = request.get_json(force=True, silent=True) or {}
    otp = data.get('otp')
    
    # Bypass returns different JSON structure
    if otp is None:
        return jsonify({
            "authenticated": True,  # Different from baseline
            "user_role": "admin",
            "session_id": "bypass_session_123"
        }), 200
    
    if str(otp) == VALID_OTP:
        return jsonify({
            "authenticated": True,
            "user_role": "user",
            "session_id": "valid_session_456"
        }), 200
    
    return jsonify({
        "authenticated": False,
        "error": "Invalid credentials"
    }), 403


@app.route('/api/verify-cookie-leak', methods=['POST'])
def verify_cookie_leak():
    """Test new cookie detection."""
    data = request.get_json(force=True, silent=True) or {}
    otp = data.get('otp')
    
    response = make_response()
    
    # Bypass leaks session cookie
    if otp is None:
        response = make_response(jsonify({
            "status": "success"
        }), 200)
        response.set_cookie('session_token', 'leaked_token_12345', httponly=True)
        response.set_cookie('auth', 'bypass_auth_token', secure=False)
        return response
    
    if str(otp) == VALID_OTP:
        response = make_response(jsonify({"status": "success"}), 200)
        response.set_cookie('session_token', 'valid_token_67890', httponly=True)
        return response
    
    return jsonify({"status": "fail"}), 403


@app.route('/api/verify-oauth-bypass', methods=['POST'])
def verify_oauth_bypass():
    """Simulates OAuth bypass vulnerability."""
    data = request.get_json(force=True, silent=True) or {}
    
    # Check if OAuth token provided (bypass 2FA)
    if 'oauth_token' in data or 'oauth_provider' in data:
        return jsonify({
            "status": "success",
            "message": "OAuth bypass successful",
            "access_token": "oauth_token_xyz"
        }), 200
    
    # Normal 2FA flow
    otp = data.get('otp')
    if str(otp) == VALID_OTP:
        return jsonify({"status": "success"}), 200
    
    return jsonify({"status": "fail"}), 403


@app.route('/api/verify-race-condition', methods=['POST'])
def verify_race_condition():
    """Vulnerable to race condition - OTP reuse."""
    data = request.get_json(force=True, silent=True) or {}
    otp = data.get('otp')
    user_id = data.get('user_id', 'default')
    
    # Simulate OTP validation without proper locking
    # In real scenario, first request should invalidate OTP
    # But this vulnerable version allows reuse
    
    if str(otp) == VALID_OTP:
        # Simulate slow DB operation (race window)
        time.sleep(0.05)
        return jsonify({
            "status": "success",
            "message": "OTP accepted (vulnerable to race)",
            "user_id": user_id
        }), 200
    
    return jsonify({"status": "fail"}), 403


# ===== UTILITY ENDPOINTS =====

@app.route('/api/reset-rate-limit', methods=['POST'])
def reset_rate_limit():
    """Reset rate limiting counters (for testing)."""
    global request_tracker
    request_tracker = {}
    return jsonify({"message": "Rate limits reset"}), 200


@app.route('/api/endpoints', methods=['GET'])
def list_endpoints():
    """List all test endpoints with descriptions."""
    endpoints = {
        "/api/verify-basic": "Basic 2FA with multiple bypasses (null, array, boolean, backdoor)",
        "/api/verify-csrf": "No CSRF protection - accepts requests without session",
        "/api/verify-rate-limited": "Rate limited endpoint (5 req/min, 429 after)",
        "/api/verify-waf-protected": "WAF simulation - blocks bot user agents",
        "/api/verify-timing": "Timing-based bypass detection",
        "/api/verify-json-response": "JSON structure changes on bypass",
        "/api/verify-cookie-leak": "Leaks session cookies on bypass",
        "/api/verify-oauth-bypass": "OAuth bypass vulnerability",
        "/api/verify-race-condition": "Race condition - OTP reuse",
        "/health": "Health check",
        "/api/reset-rate-limit": "Reset rate limit counters"
    }
    
    return jsonify(endpoints), 200


if __name__ == '__main__':
    print("="*70)
    print("TfaBuster Comprehensive Test Lab")
    print("="*70)
    print(f"\nServer starting on http://127.0.0.1:5555")
    print(f"\nValid OTP: {VALID_OTP}")
    print(f"Admin Backdoor: {ADMIN_BACKDOOR}")
    print(f"\nEndpoints available:")
    print("  - /api/endpoints (GET) - List all test endpoints")
    print("  - /health (GET) - Health check")
    print("\nTest with:")
    print("  python main.py --target http://127.0.0.1:5555/api/verify-basic --payload '{\"otp\":\"0000\"}'")
    print("="*70 + "\n")
    
    app.run(host='127.0.0.1', port=5555, debug=True, threaded=True)
