"""
Mock vulnerable 2FA server for testing TfaBuster.
Implements various intentional 2FA vulnerabilities.
"""
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
import uvicorn
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Mock 2FA Vulnerable Server")

# Track OTP usage for race condition testing
used_otps = set()


@app.post("/verify")
async def verify_normal(request: Request):
    """
    Normal 2FA endpoint - returns 403 for invalid codes.
    Vulnerable to: Response status manipulation
    """
    data = await request.json()
    code = data.get("code")
    
    logger.info(f"[/verify] Received code: {code}")
    
    # Always reject (for baseline testing)
    return JSONResponse(
        status_code=403,
        content={"success": False, "message": "Invalid verification code"}
    )


@app.post("/verify-null")
async def verify_null_bypass(request: Request):
    """
    Vulnerable to: Null/Missing parameter bypass
    If 'code' is missing or null, it passes!
    """
    data = await request.json()
    code = data.get("code")
    
    logger.info(f"[/verify-null] Received code: {code}")
    
    # BUG: Passes if code is None or missing
    if code is None:
        logger.warning("[!] NULL BYPASS TRIGGERED")
        return JSONResponse(
            status_code=200,
            content={"success": True, "message": "Welcome! Token: fake_jwt_here"}
        )
    
    return JSONResponse(
        status_code=403,
        content={"success": False, "message": "Invalid code"}
    )


@app.post("/verify-array")
async def verify_array_bypass(request: Request):
    """
    Vulnerable to: Array injection (code[])
    PHP/Node.js-style type confusion
    """
    data = await request.json()
    
    logger.info(f"[/verify-array] Received payload: {data}")
    
    # BUG: If 'code[]' is present instead of 'code', it passes
    if "code[]" in data:
        logger.warning("[!] ARRAY INJECTION BYPASS TRIGGERED")
        return JSONResponse(
            status_code=200,
            content={"success": True, "message": "Authenticated via array bypass"}
        )
    
    return JSONResponse(
        status_code=403,
        content={"success": False, "message": "Invalid code"}
    )


@app.post("/verify-race")
async def verify_race_vulnerable(request: Request):
    """
    Vulnerable to: Race condition (OTP reuse)
    Doesn't properly invalidate OTP after first use
    """
    global used_otps
    
    data = await request.json()
    code = data.get("code")
    
    logger.info(f"[/verify-race] Received code: {code}, Used OTPs: {len(used_otps)}")
    
    # Correct code for testing
    VALID_CODE = "123456"
    
    if code == VALID_CODE:
        # BUG: Doesn't check if already used
        used_otps.add(code)
        logger.warning(f"[!] RACE: Code accepted (total uses: {len(used_otps)})")
        return JSONResponse(
            status_code=200,
            content={"success": True, "message": f"Authenticated (reuse #{len(used_otps)})"}
        )
    
    return JSONResponse(
        status_code=403,
        content={"success": False, "message": "Invalid code"}
    )


@app.post("/verify-boolean")
async def verify_boolean_bypass(request: Request):
    """
    Vulnerable to: Boolean type juggling
    """
    data = await request.json()
    code = data.get("code")
    
    logger.info(f"[/verify-boolean] Received code: {code} (type: {type(code).__name__})")
    
    # BUG: Boolean True passes validation
    if code is True:
        logger.warning("[!] BOOLEAN BYPASS TRIGGERED")
        return JSONResponse(
            status_code=200,
            content={"success": True, "message": "Boolean bypass successful"}
        )
    
    return JSONResponse(
        status_code=403,
        content={"success": False, "message": "Invalid code"}
    )


@app.post("/verify-csrf")
async def verify_csrf_vulnerable(request: Request):
    """
    Vulnerable to: CSRF (no session binding check)
    Accepts requests even without valid session
    """
    data = await request.json()
    cookies = request.cookies
    
    logger.info(f"[/verify-csrf] Cookies: {cookies}")
    
    # BUG: Doesn't validate session cookie
    # Should check if session exists and is valid
    code = data.get("code")
    
    if not cookies.get("session"):
        logger.warning("[!] CSRF BYPASS: No session cookie, but accepting anyway")
        return JSONResponse(
            status_code=200,
            content={"success": True, "message": "No session validation bypass"}
        )
    
    return JSONResponse(
        status_code=403,
        content={"success": False, "message": "Invalid code"}
    )


@app.get("/")
async def root():
    """Root endpoint with vulnerability info."""
    return {
        "name": "Mock 2FA Vulnerable Server",
        "purpose": "Testing TfaBuster",
        "endpoints": {
            "/verify": "Normal (baseline) - always returns 403",
            "/verify-null": "Null/Missing parameter bypass",
            "/verify-array": "Array injection bypass (code[])",
            "/verify-race": "Race condition (valid code: 123456)",
            "/verify-boolean": "Boolean bypass (code=true)",
            "/verify-csrf": "CSRF/No session validation"
        },
        "usage": "python main.py --target http://localhost:8000/verify-null --payload '{\"code\":\"000000\"}'"
    }


@app.post("/reset")
async def reset_state():
    """Reset server state (clear used OTPs)."""
    global used_otps
    used_otps.clear()
    logger.info("[*] Server state reset")
    return {"message": "State reset successful"}


if __name__ == "__main__":
    print("\n" + "="*70)
    print("Mock 2FA Vulnerable Server")
    print("="*70)
    print("\nStarting server on http://localhost:8000")
    print("\nAvailable endpoints:")
    print("  [GET]  /                - Server info")
    print("  [POST] /verify          - Normal (baseline)")
    print("  [POST] /verify-null     - Null bypass")
    print("  [POST] /verify-array    - Array injection bypass")
    print("  [POST] /verify-race     - Race condition")
    print("  [POST] /verify-boolean  - Boolean bypass")
    print("  [POST] /verify-csrf     - CSRF bypass")
    print("  [POST] /reset           - Reset state")
    print("\n" + "="*70 + "\n")
    
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
